# Kerberoasting: Attack, Detection & Incident Response

**Home SOC + Active Directory Purple Team Lab**

> **TL;DR** — In a self-built 4-VM Active Directory lab, I executed a Kerberoasting attack, discovered the SIEM missed it by default, engineered a custom Wazuh detection rule, and ran a full (simulated) NIST incident-response cycle — then re-ran the attack to prove the fix held. **My role: both attacker (red) and defender/detection engineer (blue).** This demonstrates offensive technique, detection engineering, and structured incident response end to end.

**MITRE ATT&CK:** [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | **Tactic:** Credential Access

---

## 1. Summary

| | |
|---|---|
| **Objective** | Reproduce a Kerberoasting attack against a vulnerable service account, detect it with a custom SIEM rule, and respond using the NIST IR framework. |
| **Attacker** | Kali Linux (`192.168.56.40`), using a valid low-privilege domain account (`user1` / `user2`) — simulating an attacker who has already gained an initial foothold ("assume breach"). |
| **Target** | `svc-sql` — a service account with an SPN and a weak password, on domain `lab.local`. |
| **Detection** | Custom Wazuh rule (ID `100100`, level 12) matching Windows Event `4769` + RC4 encryption (`0x17`) + service name `svc-sql`. |
| **Outcome** | Attack succeeded (ticket cracked offline), was detected in the SIEM, contained and eradicated, and a repeat attack failed — confirming the fix. |

**Why it matters:** service accounts often hold elevated privileges and broad data access, so a single Kerberoasted credential can become a pivot into much of the domain. Detecting the request *as it happens* is the only reliable window, because the password cracking itself occurs offline and invisibly.

---

## 2. Lab Environment

Isolated VirtualBox Host-Only network `192.168.56.0/24` (no DHCP, static IPs). Each VM also has a NAT adapter for internet; all attack/detection traffic stays on the isolated segment.

| VM | IP | Role |
|---|---|---|
| **DC01** | `192.168.56.10` | Windows Server 2022 — Domain Controller (AD DS + DNS), domain `lab.local` |
| **WIN11** | `192.168.56.20` | Windows 11 — domain-joined endpoint, Sysmon installed |
| **WAZUH** | `192.168.56.30` | Ubuntu Server — Wazuh 4.9 SIEM (manager + indexer + dashboard) |
| **KALI** | `192.168.56.40` | Kali Linux — attacker |

**Log pipeline:** Windows Security + Sysmon logs → Wazuh agents on DC01 & WIN11 → Wazuh manager (rule evaluation) → dashboard.

### Vulnerable target setup (the "bait")

`svc-sql` was created as a deliberately vulnerable service account — representative of a real-world misconfiguration:

```cmd
:: On DC01 — register an SPN so the account becomes Kerberoast-able
setspn -s MSSQLSvc/dc01.lab.local:1433 svc-sql

:: Verify
setspn -l svc-sql
::   MSSQLSvc/dc01.lab.local:1433
```

Password set to a weak value to mirror the common real-world problem of service accounts with stale, weak passwords.

---

## 3. Attack — Kerberoasting (MITRE T1558.003)

> **Why it works:** Any authenticated domain user can request a Kerberos service ticket (TGS) for any account that has an SPN. The ticket is encrypted with the service account's password hash. The attacker requests the ticket, takes it offline, and brute-forces the password — with no further interaction with the DC, making the cracking phase invisible to the network.

### Step 1 — Enumerate SPNs

From Kali, using a valid domain account's credentials:

```bash
impacket-GetUserSPNs -dc-ip 192.168.56.10 lab.local/user1:'Password123!'
```

`svc-sql` is exposed as a Kerberoastable target:

![SPN enumeration](screenshots/01-spn-enumeration.png)

### Step 2 — Request & extract the ticket ("roasting")

```bash
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user1:'Password123!'
```

The tool returns the RC4-encrypted TGS hash (`$krb5tgs$23$...` — `$23$` marks RC4/etype 0x17, deliberately requested because it is far easier to crack than AES):

![Ticket extraction](screenshots/02-ticket-extraction.png)

### Step 3 — Crack offline

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
```

The service account password is recovered. In a real environment, the attacker now holds the credentials of a service account — often with elevated privileges and broad data access.

![John crack](screenshots/03-john-crack.png)

> **Wordlist note:** the account's exact password was a variant (`Password123!`) not present verbatim in stock `rockyou.txt`, so for this demonstration the variant was added to the wordlist to show a successful crack end-to-end. This is itself the real lesson: a "weak" password is only crackable if it — or a close mutation of it — is in the attacker's wordlist. Real attackers don't rely on stock lists; they generate target-specific candidates (company name, year, season) and apply rule-based mutations. The takeaway for defenders is that password *length and unpredictability* matter more than surface complexity.

---

## 4. Detection Engineering

### 4.1 The attack artifact

Each ticket request writes **Windows Security Event 4769** on the Domain Controller. The Kerberoasting signature:

| Field | Normal traffic | Kerberoasting |
|---|---|---|
| `eventID` | 4769 | 4769 |
| `ticketEncryptionType` | `0x12` (AES) | **`0x17` (RC4)** ← red flag |
| `serviceName` | computer/krbtgt | **a user service account (`svc-sql`)** |

> **Prerequisite:** "Kerberos Service Ticket Operations" auditing had to be enabled on DC01, or no 4769 events are generated:
> ```cmd
> auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
> ```

### 4.2 Detection gap

The 4769 events existed on DC01 but **did not surface as alerts in Wazuh** — Wazuh treats 4769 as high-volume noise and classifies it at level 0 by default. This is the real-world reason Kerberoasting slips past default configurations, and the gap a Detection Engineer must close.

### 4.3 Custom Wazuh rule

Added to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="kerberoasting,attack,">
  <rule id="100100" level="12">
    <if_group>windows_security</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <field name="win.eventdata.serviceName">svc-sql</field>
    <description>Kerberoasting detected: RC4 service ticket requested for svc-sql ($(win.eventdata.serviceName)) by $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

> **Rule ID `100100`:** Wazuh reserves IDs `100000+` for user-defined rules, so custom rules don't collide with built-in rules (`0–99999`) or get overwritten on update.

> **False-positive consideration:** the three conditions are combined deliberately. A 4769 event alone is pure noise; but *RC4 encryption* **and** a *user service account* together are uncommon in a modern AES-first environment. That combination is what separates an attack from normal Kerberos traffic and keeps the rule's false-positive rate low. (A known RC4-dependent legacy app would be whitelisted by service name.)

Validate and apply:

```bash
sudo /var/ossec/bin/wazuh-logtest          # confirm no XML errors
sudo systemctl restart wazuh-manager
```

### 4.4 Detection confirmed

Re-running the attack fires the rule. The alert in the Wazuh dashboard shows `rule.id: 100100`, `rule.level: 12`, the MITRE mapping (`T1558.003`, Credential Access), and the full context — who (`user1`), from where (`192.168.56.40`), against what (`svc-sql`, RC4 `0x17`):

![Wazuh alert 100100 — search](screenshots/04-wazuh-alert-100100-1.png)

![Wazuh alert 100100 — expanded](screenshots/04-wazuh-alert-100100-2.png)

The rule was verified against **both `user1` and `user2`**, confirming it keys on the **behavior** (`4769 + RC4 + svc-sql`) rather than a specific account.

### 4.5 Threat Hunting dashboard

The attack surfaces on the SIEM's Threat Hunting dashboard — level-12 alerts, a spike on the alert-level timeline, and automatic classification under MITRE ATT&CK (Kerberoasting / Credential Access):

![Threat Hunting dashboard](screenshots/05-threat-hunting-dashboard.png)

> **Lesson — IP is not reliable:** early runs logged the source as the gateway (`192.168.56.1`) instead of the real attacker (`192.168.56.40`), because traffic was routed through NAT. Network paths (NAT, proxies, gateways) can mask the true source IP, so **detection should rely on behavior, not IP.**

---

## 5. Incident Response — Simulated (NIST SP 800-61)

Acting as the SOC / defender after the alert fired, following the NIST IR lifecycle as a lab exercise (not a response to a real-world breach).

### 5.1 Preparation ✅
- Sysmon (SwiftOnSecurity config) on endpoints; Wazuh SIEM collecting Security + Sysmon logs.
- Custom detection rule `100100` deployed with MITRE mapping.

### 5.2 Identification ✅
- Rule `100100` fired a level-12 alert.
- Triage: an RC4 TGS request for a *user* service account (`svc-sql`) from a workstation IP is not normal business activity → **confirmed genuine incident**, not a false positive.

### 5.3 Containment ✅

```cmd
:: Invalidate the stolen credential — attacker's cracked password is now useless
net user svc-sql Str0ng!P@ssw0rd#2026$Complex /domain

:: Disable the compromised foothold account
net user user2 /active:no /domain
```

### 5.4 Eradication ✅

Remove the **root cause** — the SPN that made the account Kerberoastable in the first place:

```cmd
setspn -d MSSQLSvc/dc01.lab.local:1433 svc-sql
setspn -l svc-sql
::   (no SPNs registered)
```

> Changing the password alone (containment) still leaves the account attackable. Removing the SPN makes Kerberoasting **structurally impossible** for this account.

### 5.5 Recovery ✅
- Re-enabled `user2` with a new password after confirming the scope was limited.
- Monitored Wazuh for further `rule.id:100100` alerts — none observed.

### 5.6 Verification — re-attack fails ✅

The decisive proof that the response worked. After removing the SPN, the same attack returns **"No entries found!"** — the account is no longer Kerberoastable:

![Re-attack fails](screenshots/06-reattack-fails.png)

```bash
# user1 — still valid, but target is gone
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user1:'Password123!'
#   No entries found!                        ← no SPN = not Kerberoastable (eradication works)

# user2 — disabled account
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user2:'Password123!'
#   [-] invalidCredentials ... data 533      ← account disabled (containment works)
```

### 5.7 Lessons Learned
- **Strong service-account passwords** — long/complex passwords make offline cracking infeasible.
- **Remove unused SPNs** — no SPN, no Kerberoasting.
- **Disable RC4, force AES** — removes the weak cipher the attack depends on.
- **Consider gMSA** (group Managed Service Accounts) — the system rotates a strong password automatically, eliminating human-set weak passwords.
- **Keep detection rule `100100`** for ongoing coverage.
- **Enforce password policy** — during recovery, a weak replacement password was rejected by domain policy, demonstrating policy as a first-line defense.
- **Detect on behavior, not IP** — source IPs can be masked by network infrastructure.

---

## 6. Skills Demonstrated

- **Red team:** AD enumeration, Kerberoasting (Impacket), offline hash cracking (John the Ripper), custom wordlists.
- **Blue team / Detection Engineering:** Windows event analysis (4769), audit policy configuration, SIEM rule authoring (Wazuh), MITRE ATT&CK mapping, closing a detection gap.
- **Incident Response:** full NIST 800-61 lifecycle, containment/eradication decisions, verification by re-attack.
- **Infrastructure & troubleshooting:** building a 4-VM AD lab, log-pipeline troubleshooting, NTP time synchronization, disk management, network routing.

---

## 7. Roadmap

This lab is built to grow — each attack is added as its own module with the same attack → detection → response structure.

- ✅ **01 — Kerberoasting** (T1558.003) — this report
- 🔜 **AES-ticket evasion** — bypassing the RC4-only rule and hardening detection to be behavior-based
- 🔜 **02 — Pass-the-Hash** (T1550.002)

---

*Lab built on VirtualBox. All activity performed in an isolated environment against systems I own, for educational and portfolio purposes.*
