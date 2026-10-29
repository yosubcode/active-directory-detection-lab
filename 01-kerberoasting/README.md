# Kerberoasting: Attack, Detection & Incident Response

**Home SOC + Active Directory Purple Team Lab**

In a self-built 4-VM Active Directory lab, I ran a Kerberoasting attack, found that the SIEM missed it under its default configuration, wrote a custom Wazuh rule to close the gap, and worked through the NIST incident-response lifecycle as a lab exercise. I then re-ran the attack to confirm the fix held. After that I showed how an attacker evades the rule by switching to AES encryption, and I rebuilt the detection on a behavioral signal so it survives the bypass. I played both the attacker and the defender.

**MITRE ATT&CK:** [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) · Tactic: Credential Access

---

## 1. Summary

| | |
|---|---|
| Objective | Reproduce a Kerberoasting attack against a vulnerable service account, detect it with a custom SIEM rule, and respond using the NIST IR framework. |
| Attacker | Kali Linux (`192.168.56.40`), using a valid low-privilege domain account (`user1` / `user2`), simulating an attacker who already has an initial foothold ("assume breach"). |
| Target | `svc-sql`, a service account with an SPN and a weak password, on domain `lab.local`. |
| Detection | Custom Wazuh rules: `100100` (level 12) for classic RC4 Kerberoasting, and `100101` (level 12) for the evasion-resistant behavioral variant. |
| Outcome | The attack succeeded, was detected, contained, and eradicated, and a repeat attack failed. An AES-based evasion that bypassed the first rule was then caught by a hardened behavioral rule. |

Service accounts often hold elevated privileges and broad data access, so one Kerberoasted credential can become a pivot into much of the domain. The only reliable window to detect it is the moment of the request, because the password cracking happens offline and leaves no trace on the network.

---

## 2. Lab Environment

Isolated VirtualBox Host-Only network `192.168.56.0/24` (no DHCP, static IPs). Each VM also has a NAT adapter for internet; all attack and detection traffic stays on the isolated segment.

| VM | IP | Role |
|---|---|---|
| DC01 | `192.168.56.10` | Windows Server 2022, Domain Controller (AD DS + DNS), domain `lab.local` |
| WIN11 | `192.168.56.20` | Windows 11, domain-joined endpoint, Sysmon installed |
| WAZUH | `192.168.56.30` | Ubuntu Server, Wazuh 4.9 SIEM (manager + indexer + dashboard) |
| KALI | `192.168.56.40` | Kali Linux, attacker |

Log pipeline: Windows Security and Sysmon logs go to Wazuh agents on DC01 and WIN11, then to the Wazuh manager for rule evaluation, then to the dashboard.

### Vulnerable target setup

`svc-sql` was created as a deliberately vulnerable service account, representative of a common real-world misconfiguration:

```cmd
:: On DC01 — register an SPN so the account becomes Kerberoast-able
setspn -s MSSQLSvc/dc01.lab.local:1433 svc-sql

:: Verify
setspn -l svc-sql
::   MSSQLSvc/dc01.lab.local:1433
```

Its password was set to a weak value, mirroring the common problem of service accounts with stale, weak passwords.

---

## 3. Attack — Kerberoasting (MITRE T1558.003)

Any authenticated domain user can request a Kerberos service ticket (TGS) for any account that has an SPN. The ticket is encrypted with the service account's password hash. The attacker requests the ticket, takes it offline, and brute-forces the password with no further contact with the DC, which keeps the cracking phase invisible to the network.

### Step 1 — Enumerate SPNs

From Kali, using a valid domain account's credentials:

```bash
impacket-GetUserSPNs -dc-ip 192.168.56.10 lab.local/user1:'Password123!'
```

`svc-sql` is exposed as a Kerberoastable target:

![SPN enumeration](screenshots/01-spn-enumeration.png)

### Step 2 — Request and extract the ticket

```bash
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user1:'Password123!'
```

The tool returns the RC4-encrypted TGS hash (`$krb5tgs$23$...`). The `$23$` marks RC4, etype 0x17, which the tool requests on purpose because it is far easier to crack than AES:

![Ticket extraction](screenshots/02-ticket-extraction.png)

### Step 3 — Crack offline

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
```

The service account password is recovered. In a real environment, the attacker now holds the credentials of a service account, often with elevated privileges and broad data access.

![John crack](screenshots/03-john-crack.png)

The account's exact password (`Password123!`) was not in stock `rockyou.txt`, so for this demonstration the variant was added to the wordlist to show the crack end to end. That is the lesson: a weak password is only crackable if it, or a close mutation of it, is in the attacker's wordlist. Real attackers generate target-specific candidates (company name, year, season) and apply rule-based mutations rather than relying on stock lists, so password length and unpredictability matter more than surface complexity.

---

## 4. Detection Engineering

### 4.1 The attack artifact

Each ticket request writes Windows Security Event 4769 on the Domain Controller. The Kerberoasting signature:

| Field | Normal traffic | Kerberoasting |
|---|---|---|
| `eventID` | 4769 | 4769 |
| `ticketEncryptionType` | `0x12` (AES) | `0x17` (RC4), a red flag |
| `serviceName` | computer / krbtgt | a user service account (`svc-sql`) |

Auditing for "Kerberos Service Ticket Operations" had to be enabled on DC01, or no 4769 events are generated:

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

### 4.2 Detection gap

The 4769 events existed on DC01 but did not surface as alerts in Wazuh. Wazuh treats 4769 as high-volume noise and classifies it at level 0 by default. This is the real-world reason Kerberoasting slips past default configurations, and the gap a detection engineer has to close.

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

Wazuh reserves rule IDs `100000+` for user-defined rules, so custom rules do not collide with the built-in set (`0–99999`) or get overwritten on update.

On false positives: the three conditions are combined on purpose. A 4769 event on its own is pure noise, but RC4 encryption together with a user service account is uncommon in a modern AES-first environment, and that combination is what separates an attack from normal Kerberos traffic. A known RC4-dependent legacy application would be whitelisted by service name.

Validate and apply:

```bash
sudo /var/ossec/bin/wazuh-logtest          # confirm no XML errors
sudo systemctl restart wazuh-manager
```

### 4.4 Detection confirmed

Re-running the attack fires the rule. The alert in the Wazuh dashboard shows `rule.id: 100100`, `rule.level: 12`, the MITRE mapping (`T1558.003`, Credential Access), and the full context: who (`user1`), from where (`192.168.56.40`), and against what (`svc-sql`, RC4 `0x17`).

![Wazuh alert 100100 — search](screenshots/04-wazuh-alert-100100-1.png)

![Wazuh alert 100100 — expanded](screenshots/04-wazuh-alert-100100-2.png)

The rule was verified against both `user1` and `user2`, confirming it keys on the behavior (`4769 + RC4 + svc-sql`) rather than a specific account.

### 4.5 Threat hunting dashboard

The attack surfaces on the SIEM's Threat Hunting dashboard: level-12 alerts, a spike on the alert-level timeline, and automatic classification under MITRE ATT&CK (Kerberoasting, Credential Access).

![Threat hunting dashboard](screenshots/05-threat-hunting-dashboard.png)

A note on source IP: early runs logged the source as the gateway (`192.168.56.1`) instead of the real attacker (`192.168.56.40`), because traffic was routed through NAT. Network paths such as NAT, proxies, and gateways can mask the true source IP, so detection should rely on behavior rather than IP.

---

## 5. Incident Response — Simulated (NIST SP 800-61)

Acting as the SOC analyst after the alert fired, following the NIST IR lifecycle as a lab exercise rather than a response to a real breach.

### 5.1 Preparation
Sysmon (SwiftOnSecurity config) on endpoints; Wazuh SIEM collecting Security and Sysmon logs; custom detection rule `100100` deployed with MITRE mapping.

### 5.2 Identification
Rule `100100` fired a level-12 alert. On triage, an RC4 TGS request for a user service account (`svc-sql`) from a workstation IP is not normal business activity, so it was confirmed as a genuine incident rather than a false positive.

### 5.3 Containment

```cmd
:: Invalidate the stolen credential — the attacker's cracked password is now useless
net user svc-sql Str0ng!P@ssw0rd#2026$Complex /domain

:: Disable the compromised foothold account
net user user2 /active:no /domain
```

### 5.4 Eradication

Remove the root cause, the SPN that made the account Kerberoastable in the first place:

```cmd
setspn -d MSSQLSvc/dc01.lab.local:1433 svc-sql
setspn -l svc-sql
::   (no SPNs registered)
```

Changing the password alone (containment) still leaves the account attackable. Removing the SPN makes Kerberoasting structurally impossible for this account.

### 5.5 Recovery
Re-enabled `user2` with a new password after confirming the scope was limited, and monitored Wazuh for further `rule.id:100100` alerts. None were observed.

### 5.6 Verification — re-attack

The decisive proof that the response worked. After removing the SPN, the same attack returns "No entries found!", so the account is no longer Kerberoastable:

![Re-attack fails](screenshots/06-reattack-fails.png)

```bash
# user1 — still valid, but target is gone
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user1:'Password123!'
#   No entries found!                        <- no SPN = not Kerberoastable (eradication works)

# user2 — disabled account
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user2:'Password123!'
#   [-] invalidCredentials ... data 533      <- account disabled (containment works)
```

### 5.7 Lessons Learned
- Strong service-account passwords make offline cracking infeasible.
- Remove unused SPNs. No SPN, no Kerberoasting.
- Disable RC4 and force AES to remove the weak cipher the attack depends on.
- Consider gMSA (group Managed Service Accounts), which rotate a strong password automatically and remove human-set weak passwords.
- Keep detection rule `100100` for ongoing coverage.
- Enforce password policy. During recovery, a weak replacement password was rejected by domain policy, which shows policy acting as a first line of defense.
- Detect on behavior, not IP, since source IPs can be masked by network infrastructure.

---

## 6. Detection Evasion and Hardening — AES bypass

The rule in Section 4 keys on RC4 encryption (`0x17`), a signature-based detection, and signatures can be evaded. This section shows the evasion and the fix.

![Attack flow: RC4 caught by rule 100100, AES evades it and is caught by rule 100101](screenshots/12-detection-flow.png)

### 6.1 The evasion

By default, `impacket-GetUserSPNs` downgrades its request to RC4. If the service account is restricted to AES only, which is a realistic hardening posture in a modern environment, that downgrade is no longer possible and the KDC issues an AES ticket instead:

```powershell
# On DC01 — restrict svc-sql to AES only
Set-ADUser svc-sql -KerberosEncryptionType AES128,AES256
```

The same attack command now returns an AES-256 hash (`$krb5tgs$18$`, etype `0x12`) instead of RC4 (`$23$`):

```bash
impacket-GetUserSPNs -dc-ip 192.168.56.10 -request lab.local/user1:'Password123!'
#   $krb5tgs$18$svc-sql$LAB.LOCAL$...        <- $18$ = AES256, not $23$ (RC4)
```

![AES ticket extracted](screenshots/07-aes-ticket.png)

The attack still succeeds. The attacker obtains a crackable hash; AES is slower to crack than RC4, but the credential is still exposed. The attacker traded cracking speed for stealth.

### 6.2 The gap

Rule `100100` requires `ticketEncryptionType: 0x17`, so the AES request does not match it. The event never even reaches the alerts index, because Wazuh only indexes events that trigger an alert and a plain 4769 sits at level 0.

Searching `rule.id:100100` for the AES attack returns nothing:

![No alert for AES attack](screenshots/08-aes-no-alert.png)

The request still happened. Event 4769 is present on DC01, showing the AES encryption type:

```
Service Name:            svc-sql
Client Address:          ::ffff:192.168.56.40
Ticket Encryption Type:  0x12            <- AES256
```

![Event 4769 on DC01 with AES](screenshots/09-dc-4769-aes.png)

The log exists at the source; the detection missed it.

### 6.3 The fix — behavior-based detection

The fix is to detect on what the attacker cannot easily change. To perform Kerberoasting, the attacker has to request a ticket for the target service account, whatever cipher it uses. So the hardened rule drops the encryption condition and alerts on any service-ticket request for `svc-sql`, a decoy account that no legitimate service uses, which makes it a honey-SPN (honeytoken).

```xml
<rule id="100101" level="12">
  <if_group>windows_security</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.serviceName">svc-sql</field>
  <description>Kerberoasting (evasion-resistant): TGS for decoy account svc-sql by $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress), enc $(win.eventdata.ticketEncryptionType)</description>
  <mitre>
    <id>T1558.003</id>
  </mitre>
</rule>
```

Rule `100100` is kept alongside it. `100100` is a high-fidelity signature for classic RC4 Kerberoasting, and `100101` is the broader behavioral net that survives a cipher change. The two together are a small example of layered detection.

![Both rules in local_rules.xml](screenshots/10-new-rule.png)

### 6.4 Verification

With `100101` in place, the same AES attack now fires an alert (`rule.id:100101`), showing the AES encryption type it was previously blind to:

![AES attack now detected](screenshots/11-aes-detected.png)

| Attack | Rule 100100 (RC4 signature) | Rule 100101 (behavioral) |
|---|---|---|
| RC4 ticket | fires | fires |
| AES ticket | misses | fires |

### 6.5 Limitation

Keying on `svc-sql` works because it is a decoy account with no legitimate ticket traffic, so any request for it is suspicious. For a service account that is actually in use, this rule would produce false positives, and detection would have to move to a frequency-based signal, for example one account requesting tickets for many distinct SPNs in a short window. This is the general trade-off in detection engineering: the harder a signal is to evade, the more tuning it takes to stay quiet.

---

## 7. Skills Demonstrated

- Red team: AD enumeration, Kerberoasting (Impacket), offline hash cracking (John the Ripper), custom wordlists, and detection evasion by avoiding the RC4 downgrade.
- Blue team / detection engineering: Windows event analysis (4769), audit policy configuration, SIEM rule authoring (Wazuh), MITRE ATT&CK mapping, closing a detection gap, and hardening a signature rule into a behavioral one.
- Incident response: the NIST 800-61 lifecycle, containment and eradication decisions, and verification by re-attack.
- Infrastructure and troubleshooting: building a 4-VM AD lab, log-pipeline troubleshooting, NTP time synchronization, disk management, and network routing.

---

## 8. Roadmap

Each attack is added as its own module with the same attack, detection, response structure.

- 01 — Kerberoasting (T1558.003), complete, this report
- Kerberoasting AES evasion and behavioral hardening, complete, Section 6
- 02 — Pass-the-Hash (T1550.002), planned

---

*Lab built on VirtualBox. All activity performed in an isolated environment against systems I own, for educational and portfolio purposes.*
