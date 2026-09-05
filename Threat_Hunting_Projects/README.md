# 🎯 Threat Hunting Projects - CTF Collection

A comprehensive collection of Capture The Flag (CTF) threat hunting exercises documenting real-world attack scenarios, investigation methodologies, and forensic analysis techniques.

## 📚 Threat Hunt Reports

### 1. 🌉 [Threat Hunt SAGA#3: Bridge Takeover](./%28CTF%29%20Threat%20Hunt%20SAGA%233%3A%20Bridge%20Takeover.md)
**Date Completed:** 2026-09-05  
**Environment:** Cyber Range AZURE LAW  
**Focus:** RDP pivot to the admin PC, disguised payload staging, Meterpreter C2 over a named pipe, Base64-encoded backdoor account, discovery, KeePass and browser credential theft, cloud exfiltration  
**Flags:** 25

Five days after the file server breach the attacker returned, pivoting over RDP from a compromised workstation to the CEO's admin PC with a reused account. A 7-Zip payload disguised as a Windows update was pulled from a public file host and extracted into a Temp cache, a Meterpreter implant opened command and control over a named pipe, and a lookalike backdoor account was created and promoted with Base64-encoded PowerShell. Session, trust and network enumeration led to KeePass and browser credential theft with a renamed Mimikatz, banking and contract documents were staged in a hidden ProgramData folder, and eight archives were uploaded to gofile.io.

---

### 2. 🚢 [Threat Hunt SAGA#2: Cargo Hold](./%28CTF%29%20Threat%20Hunt%20SAGA%232%3A%20Cargo%20Hold.md)
**Date Completed:** 2026-02-14  
**Environment:** Cyber Range AZURE LAW  
**Focus:** Return access, share discovery, staging, credential dumping, cloud exfiltration  
**Flags:** 20

A focused intrusion on an Azuki file server featuring RDP pivoting, share enumeration, hidden staging, certutil-based tool transfer, LSASS dumping, and exfiltration to a public file-sharing service.

---

### 3. 🚪 [Threat Hunt SAGA#1: Port of Entry](./%28CTF%29%20Threat%20Hunt%20SAGA%231%3A%20Port%20of%20Entry.md)
**Date Completed:** 2025-11-20  
**Environment:** Cyber Range AZURE LAW  
**Threat Actor:** JADE SPIDER (APT-SL44, SilentLynx)  
**Focus:** RDP compromise, credential theft, lateral movement, data exfiltration  
**Flags:** 20

A sophisticated attack chain targeting Azuki Import/Export Trading Co. involving RDP credential compromise, Windows Defender evasion, Mimikatz credential dumping, Discord exfiltration, and lateral movement attempts.

---

### 4. 💬 [Assistance](./%28CTF%29%20Assistance.md)
**Date Completed:** 2025-10-09  
**Environment:** LOG(N) Pacific - Cyber Range 1  
**Focus:** Remote assistance masquerading, PowerShell abuse, persistence mechanisms  
**Flags:** 15

An investigation into suspicious remote assistance activity that revealed a complete attack chain disguised as IT support, including defense tampering, reconnaissance, exfiltration attempts, and planted narrative artifacts.

---

### 5. 🥷🏿 [Lurker Re-emerges](./%28CTF%29%20Lurker.md)
**Date Completed:** 2025-07-13  
**Environment:** LOG(N) Pacific - Cyber Range 1  
**Focus:** PowerShell abuse, LOLBins, lateral movement, cloud exfiltration  
**Flags:** 17

A multi-phase attack starting with PowerShell abuse and LOLBins, escalating to targeted data exfiltration across multiple systems using cloud services and anti-forensic techniques.

---

### 6. 🖳 [Hide Your RDP: Password Spray Leads to Full Compromise](./%28CTF%29%20RDP%20Password%20Spray.md)
**Date Completed:** 2025-09-08  
**Environment:** LOG(N) Pacific - Cyber Range 1  
**Focus:** Password spraying, RDP compromise, persistence, data exfiltration  
**Flags:** 10

A password spray attack against an internet-exposed RDP endpoint leading to full system compromise, persistence establishment, and data exfiltration over HTTP.

---

### 7. 🧾 [Papertrail — Insider HR Tamper](./%28CTF%29%20Papertrail.md)
**Date Completed:** 2025-09-08  
**Environment:** LOG(N) Pacific - Cyber Range 1  
**Focus:** Insider threat, HR data manipulation, credential dumping, anti-forensics  
**Flags:** Multiple

An insider threat investigation involving HR automation masquerading, credential theft via LSASS memory dumping, Defender tampering, and audit log manipulation.

---

## 🎓 Learning Objectives

These threat hunting exercises cover:

- **Initial Access Techniques:** RDP compromise, password spraying, credential theft
- **Execution Methods:** PowerShell abuse, LOLBins, script execution
- **Persistence Mechanisms:** Scheduled tasks, registry Run keys, hidden accounts
- **Defense Evasion:** Windows Defender exclusions, log clearing, AMSI bypass
- **Credential Access:** Mimikatz usage, LSASS memory dumping, credential storage
- **Discovery:** Network reconnaissance, system enumeration, account discovery
- **Lateral Movement:** RDP, scheduled tasks, credential reuse
- **Command & Control:** Meterpreter implants, named-pipe C2, disguised payload downloads
- **Collection & Exfiltration:** Data staging, cloud service abuse, Discord webhooks
- **Impact:** Data manipulation, backdoor account creation

## 🛠️ Tools & Frameworks

- **Microsoft Defender for Endpoint** (MDE)
- **KQL (Kusto Query Language)** for log analysis
- **MITRE ATT&CK Framework** for technique mapping
- **NIST 800-61** for incident response
- **Diamond Model** for threat intelligence

## 📊 Statistics

- **Total Reports:** 6
- **Total Flags Captured:** 80+
- **Attack Scenarios:** External threats, insider threats, APT groups
- **Techniques Covered:** 50+ MITRE ATT&CK techniques

## 🤝 Contributors

- **Adetola Kolawole** - Agentic SOC Analyst
- **Mohammed A** - Hunt Design Master
- **Josh Madakor's Team** - Cyber Range AZURE LAW
- **Joshua Balondo** - Hunt Design Master
- **Peter Pan (Panbear)** - Primary Analyst

## 📝 Notes

All reports follow a consistent structure:
- Incident overview and context
- Diamond Model analysis
- MITRE ATT&CK technique mapping
- Detailed flag-by-flag investigation with KQL queries
- Remediation recommendations
- Lessons learned
- Timeline reconstruction

---

**Last Updated:** 2026-02-14
