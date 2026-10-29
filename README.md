# Active Directory Detection Lab

A home **Purple Team** lab for reproducing real Active Directory attacks, engineering custom SIEM detections, and running full incident-response cycles — with screenshot evidence for each.

Built to demonstrate hands-on **SOC / Detection Engineering** skills: attack → log → detection rule → MITRE ATT&CK mapping → NIST incident response → verification.

---

## Lab Environment

Isolated VirtualBox network (`192.168.56.0/24`, Host-Only, static IPs):

| VM | IP | Role |
|---|---|---|
| **DC01** | `192.168.56.10` | Windows Server 2022 — Domain Controller (`lab.local`) |
| **WIN11** | `192.168.56.20` | Windows 11 — domain-joined endpoint, Sysmon |
| **WAZUH** | `192.168.56.30` | Ubuntu — Wazuh 4.9 SIEM (manager + indexer + dashboard) |
| **KALI** | `192.168.56.40` | Kali Linux — attacker |

**Pipeline:** Windows Security + Sysmon logs -> Wazuh agents -> Wazuh manager (rule evaluation) -> dashboard.

---

## Attacks & Detections

| # | Attack | MITRE | Status |
|---|---|---|---|
| 01 | [Kerberoasting](01-kerberoasting/) | T1558.003 | Complete |

*More attacks in progress.*

---

## Skills Demonstrated

- **Red team:** AD enumeration, credential attacks (Impacket), offline hash cracking.
- **Blue team / Detection Engineering:** Windows event analysis, custom Wazuh rule authoring, MITRE ATT&CK mapping, closing detection gaps.
- **Incident Response:** full NIST SP 800-61 lifecycle, verified by re-attack.
- **Infrastructure:** multi-VM AD lab, log-pipeline troubleshooting, time sync, network routing.

---

*All activity is performed in an isolated lab against systems I own, for educational and portfolio purposes.*
