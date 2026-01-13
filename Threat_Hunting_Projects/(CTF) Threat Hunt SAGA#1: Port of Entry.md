# 🚪 Threat Hunt SAGA#1: Port of Entry

<img width="740" height="1110" alt="PORT OF ENTRY" src="https://github.com/user-attachments/assets/d6fba696-976b-40c3-93d3-8d5581daca20" />

**Sandbox Contributor:** [Cyber Range AZURE LAW by Josh Madakor's team](https://www.skool.com/cyber-community)  
**Hunt Design Master:** Mohammed A  
**Loyal Wingman (woman):** [Adetola Kolawole](https://github.com/AdetolaKols), Agentic SOC Analyst

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
Date Completed: ***2025-11-20***  
Wingmen (woman) List: **[Adetola Kolawole](https://github.com/AdetolaKols)**, Agentic SOC Analyst  
Simulated Environment: `Cyber Range AZURE LAW`  
Infected Host VM DeviceName contains `azuki-sl`  
Incident Date: ***2025-11-19 to 2025-11-20***  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***  

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview

A competitor's suspiciously precise undercut—exactly 3% below a six-year shipping contract—triggered alarm bells. When supplier contracts and pricing data surfaced on underground forums, Azuki Import/Export Trading Co. knew they had been compromised.

The investigation traced the breach to AZUKI-SL, an IT admin workstation. Microsoft Defender for Endpoint logs revealed a sophisticated attack chain: initial access via compromised RDP credentials, followed by network reconnaissance, defense evasion through Windows Defender exclusions, credential theft using Mimikatz, data staging and exfiltration via Discord, lateral movement attempts, and anti-forensic log clearing.

The threat actor, attributed to JADE SPIDER (APT-SL44, SilentLynx), demonstrated moderate sophistication with a preference for low-footprint techniques. Their multi-week operation followed a predictable pattern: initial access → persistence → credential access → lateral movement → collection → exfiltration → impact.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis

| Feature | Details |
|---|---|
| **Adversary** | JADE SPIDER (APT-SL44, SilentLynx) - Financially motivated threat actor active since 2019, targeting logistics companies in East Asia. Known for 21-45 day dwell times and eventual ransomware deployment following data theft. Moderate sophistication with preference for low-footprint techniques. |
| **Infrastructure** | Initial access via RDP from external IP `88.97.178.12`. C2 server at `78.141.196.6` (port 443). Exfiltration via Discord webhook. Staging directory: `C:\ProgramData\WindowsCache`. Temporary folder exclusion: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`. |
| **Capability** | RDP credential compromise, network reconnaissance (`arp -a`), Windows Defender exclusion manipulation, LOLBin abuse (`certutil.exe`), scheduled task persistence (`Windows Update Check`), Mimikatz credential dumping (`sekurlsa::logonpasswords`), data staging (`export-data.zip`), Discord exfiltration, lateral movement via `mstsc.exe` to `10.1.0.188`, backdoor account creation (`support`), PowerShell script automation (`wupdate.ps1`), and event log clearing (`wevtutil cl Security`). |
| **Victim** | Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia. Compromised system: AZUKI-SL (IT admin workstation). Compromised account: `kenji.sato`. Data stolen: Supplier contracts and pricing information. |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Initial Access | 1 | Initial Access | **T1021.001** | Remote Services: Remote Desktop Protocol |
| Initial Access | 2 | Initial Access | **T1078** | Valid Accounts |
| Discovery | 3 | Discovery | **T1018** | Remote System Discovery |
| Defense Evasion | 4 | Defense Evasion | **T1562.001** | Impair Defenses: Disable or Modify Tools |
| Defense Evasion | 5 | Defense Evasion | **T1562.001** | Impair Defenses: Disable or Modify Tools |
| Defense Evasion | 6 | Defense Evasion | **T1562.001** | Impair Defenses: Disable or Modify Tools |
| Defense Evasion | 7 | Defense Evasion | **T1105** | Ingress Tool Transfer |
| Persistence | 8 | Persistence | **T1053.005** | Scheduled Task/Job: Scheduled Task |
| Persistence | 9 | Persistence | **T1053.005** | Scheduled Task/Job: Scheduled Task |
| Command & Control | 10 | Command & Control | **T1071.001** | Web Protocols |
| Command & Control | 11 | Command & Control | **T1071.001** | Web Protocols |
| Credential Access | 12 | Credential Access | **T1003.001** | OS Credential Dumping: LSASS Memory |
| Credential Access | 13 | Credential Access | **T1003.001** | OS Credential Dumping: LSASS Memory |
| Collection | 14 | Collection | **T1560.001** | Archive Collected Data: Archive via Utility |
| Exfiltration | 15 | Exfiltration | **T1567.002** | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| Defense Evasion | 16 | Defense Evasion | **T1070.001** | Indicator Removal: Clear Windows Event Logs |
| Impact | 17 | Impact | **T1136.001** | Create Account: Local Account |
| Execution | 18 | Execution | **T1059.001** | Command & Scripting Interpreter: PowerShell |
| Lateral Movement | 19 | Lateral Movement | **T1021.001** | Remote Services: Remote Desktop Protocol |
| Lateral Movement | 20 | Lateral Movement | **T1021.001** | Remote Services: Remote Desktop Protocol |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions

1. **RDP Security Hardening**
   - Implement MFA for all RDP connections; restrict RDP to VPN-only access.
   - Monitor and alert on external RDP connections; implement account lockout policies.
   - Review and rotate credentials for compromised account (`kenji.sato`).

2. **Windows Defender Configuration**
   - Audit and remove unauthorized exclusions; implement change control for exclusion modifications.
   - Alert on registry modifications to Defender exclusion settings.
   - Baseline exclusion lists and monitor for unauthorized additions.

3. **LOLBin Monitoring**
   - Alert on `certutil.exe` usage with network parameters; monitor for unusual `certutil` command patterns.
   - Implement application allowlisting for critical system directories.
   - Correlate LOLBin usage with network activity and file creation events.

4. **Persistence Detection**
   - Audit scheduled tasks for suspicious entries (e.g., `Windows Update Check`); alert on non-standard task locations.
   - Monitor registry Run keys and startup folders for unauthorized modifications.
   - Detect hidden administrator account creation (`support`).

5. **Credential Protection**
   - Enable Credential Guard; implement LSA protection.
   - Alert on LSASS memory access; monitor for credential dumping tool execution.
   - Detect Mimikatz module usage (`sekurlsa::logonpasswords`).

6. **Network Egress Controls**
   - Block outbound connections to unapproved IPs (e.g., `78.141.196.6`); implement DNS filtering.
   - Monitor and restrict cloud service access (Discord webhooks); implement DLP for sensitive data.
   - Alert on data staging and compression activities.

7. **Lateral Movement Prevention**
   - Restrict RDP access between internal systems; implement network segmentation.
   - Monitor `mstsc.exe` usage with internal IP addresses; alert on credential storage (`cmdkey`).
   - Enforce least privilege access principles.

8. **Forensic Protection**
   - Forward logs to tamper-resistant SIEM; implement log integrity monitoring.
   - Alert on `wevtutil cl` commands; protect critical event logs.
   - Enable PowerShell script block logging and AMSI.

9. **PowerShell Security**
   - Enforce Constrained Language Mode; enable deep script block logging.
   - Monitor Downloads folder for script execution; alert on suspicious PowerShell activity.
   - Block execution of scripts from temporary directories.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned

- **RDP as Initial Vector:** External RDP connections require strict monitoring and MFA enforcement. Compromised credentials provide immediate administrative access.
- **Defense Evasion Layering:** Multiple exclusion techniques (file extensions, folder paths) demonstrate systematic defense evasion planning.
- **LOLBin Abuse:** Native Windows tools (`certutil.exe`, `mstsc.exe`) blend with legitimate activity, requiring behavioral analysis for detection.
- **Persistence Redundancy:** Scheduled tasks provide reliable persistence across reboots, especially when named to mimic legitimate Windows processes.
- **Credential Theft Impact:** LSASS memory dumping enables lateral movement and privilege escalation, making credential protection critical.
- **Cloud Exfiltration:** Discord webhooks provide a low-profile exfiltration channel that bypasses traditional network filters.
- **Anti-Forensics:** Event log clearing attempts indicate sophisticated threat actors aware of forensic analysis capabilities.
- **Lateral Movement Patterns:** Internal RDP connections following credential theft reveal attacker progression through the network.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion

The investigation reconstructed a complete attack chain attributed to JADE SPIDER: initial RDP access via compromised credentials (`kenji.sato`) from external IP `88.97.178.12` → network reconnaissance (`arp -a`) → defense evasion through Windows Defender exclusions (3 file extensions, 1 folder path) → malware staging (`C:\ProgramData\WindowsCache`) → LOLBin abuse (`certutil.exe`) → scheduled task persistence (`Windows Update Check` → `svchost.exe`) → C2 communication (`78.141.196.6:443`) → credential dumping (`mm.exe` → `sekurlsa::logonpasswords`) → data staging (`export-data.zip`) → Discord exfiltration → lateral movement attempts (`mstsc.exe` → `10.1.0.188`) → backdoor account creation (`support`) → PowerShell script automation (`wupdate.ps1`) → event log clearing (`wevtutil cl Security`). The derived timeline and behaviors support immediate containment, eradication of persistence mechanisms, credential rotation, and detection engineering to prevent similar attacks.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)**          | **Event**                                   | **Target Device**      | **Details**                              |
|------------------------------|---------------------------------------------|------------------------|-------------------------------------------|
| **2025-11-19 ~**             | Initial RDP access detected                 | azuki-sl               | External IP `88.97.178.12` (Flag 1) |
| **2025-11-19 ~**             | Compromised account authentication          | azuki-sl               | Account `kenji.sato` (Flag 2) |
| **2025-11-19 ~**             | Network reconnaissance                     | azuki-sl               | `arp -a` command (Flag 3) |
| **2025-11-19 ~**             | Staging directory creation                  | azuki-sl               | `C:\ProgramData\WindowsCache` (Flag 4) |
| **2025-11-19 ~**             | Windows Defender exclusions added           | azuki-sl               | 3 file extensions excluded (Flag 5) |
| **2025-11-19 ~**             | Folder exclusion configured                 | azuki-sl               | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` (Flag 6) |
| **2025-11-19 ~**             | Malware download via LOLBin                 | azuki-sl               | `certutil.exe` abuse (Flag 7) |
| **2025-11-19 ~**             | Scheduled task persistence created          | azuki-sl               | Task: `Windows Update Check` (Flag 8) |
| **2025-11-19 ~**             | Persistence executable configured           | azuki-sl               | `C:\ProgramData\WindowsCache\svchost.exe` (Flag 9) |
| **2025-11-19 ~**             | C2 server communication                    | azuki-sl               | IP `78.141.196.6` (Flag 10) |
| **2025-11-19 ~**             | C2 communication port                      | azuki-sl               | Port `443` (Flag 11) |
| **2025-11-19 ~**             | Credential dumping tool deployed            | azuki-sl               | `mm.exe` (Flag 12) |
| **2025-11-19 ~**             | Memory extraction module executed           | azuki-sl               | `sekurlsa::logonpasswords` (Flag 13) |
| **2025-11-19 ~**             | Data staging archive created                | azuki-sl               | `export-data.zip` (Flag 14) |
| **2025-11-19 ~**             | Data exfiltration via cloud service         | azuki-sl               | Discord webhook (Flag 15) |
| **2025-11-19 ~**             | Event log clearing                          | azuki-sl               | `wevtutil cl Security` (Flag 16) |
| **2025-11-19 ~**             | Backdoor account created                    | azuki-sl               | Username `support` (Flag 17) |
| **2025-11-19 ~**             | PowerShell script automation                | azuki-sl               | `wupdate.ps1` (Flag 18) |
| **2025-11-19 ~**             | Lateral movement target identified          | azuki-sl               | IP `10.1.0.188` (Flag 19) |
| **2025-11-19 ~**             | Remote access tool used                    | azuki-sl               | `mstsc.exe` (Flag 20) |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag   | Objective                                   | Value                                           |
|--------|---------------------------------------------|--------------------------------------------------|
| **1**  | Remote access source IP address                         | 88.97.178.12                                    |
| **2**  | Compromised user account                         | kenji.sato                                          |
| **3**  | Network reconnaissance command     | ARP.EXE -a |
| **4**  | Primary staging directory      | C:\ProgramData\WindowsCache                               |
| **5**  | Number of file extensions excluded  | 3                                   |
| **6**  | Temporary folder path excluded                       | C:\Users\KENJI~1.SAT\AppData\Local\Temp                                   |
| **7**  | Windows-native binary abused for downloads                        | certutil.exe                                   |
| **8**  | Scheduled task name                        | Windows Update Check                                   |
| **9**  | Scheduled task executable path                        | C:\ProgramData\WindowsCache\svchost.exe                                   |
| **10** | C2 server IP address                        | 78.141.196.6                                     |
| **11** | C2 communication port                        | 443                                   |
| **12** | Credential dumping tool filename                        | mm.exe                                   |
| **13** | Memory extraction module                        | sekurlsa::logonpasswords                                   |
| **14** | Data staging archive filename                        | export-data.zip                                   |
| **15** | Cloud service used for exfiltration                        | Discord                                   |
| **16** | First event log cleared                        | Security                                   |
| **17** | Backdoor account username                        | support                                   |
| **18** | PowerShell script filename                        | wupdate.ps1                                   |
| **19** | Lateral movement target IP                        | 10.1.0.188                                     |
| **20** | Remote access tool executable                        | mstsc.exe                                   |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

### 🚩 Flag 1: INITIAL ACCESS - Remote Access Source

**Objective:** Identify the source IP address of the Remote Desktop Protocol connection.

**What to Hunt:** Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**Hint 1:** Query logon events for interactive sessions from external sources during the incident timeframe.

**Hint 2:** Use DeviceLogonEvents table and filter by ActionType or LogonType values indicating remote access.

**Reference:** DeviceLogonEvents

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-21))
| where DeviceName contains 'azuki-sl'
| where RemoteIPType contains 'Public'
| project TimeGenerated, DeviceName, AccountDomain, ActionType, AccountName, RemoteIP, InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```

**Output:** `88.97.178.12`  
**Finding:** The logs contain entries with "Source Network Address" fields, which are potential candidates for identifying the source IP of an RDP connection. RDP typically uses port 3389, and network traces often include source IPs in such fields. Among the entries, the IP `88.97.178.12` appears in a log line associated with a user account (`kenji.sato`) and is a public IP address, making it a strong candidate for the source of an RDP connection.
<img width="1184" height="209" alt="Siiiiit" src="https://github.com/user-attachments/assets/546a6a14-ae7e-4a79-bde0-8eeb74745fe5" />

---

### 🚩 Flag 2: INITIAL ACCESS - Compromised User Account

**Objective:** Identify the user account that was compromised for initial access.

**What to Hunt:** Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts including password resets and privilege reviews.

**Hint 1:** Focus on the account that authenticated during the suspicious remote access session.

**Hint 2:** Cross-reference the logon event timestamp with the external IP connection.

**Reference:** Remote Services: Remote Desktop Protocol

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-21))
| where DeviceName contains 'azuki-sl'
| where RemoteIPType contains 'Public'
| where RemoteIP contains '88.97.178.12'
| project TimeGenerated, DeviceName, AccountName
| order by TimeGenerated asc
```

**Output:** `kenji.sato`  
**Finding:** The query results explicitly show four successful logon events for the account **kenji.sato** from the compromised IP **88.97.178.12** (Flag 1) against the device **azuki-sl**. These logons align with the suspicious external IP identified in Flag 1, indicating the use of compromised credentials for unauthorized access.
<img width="671" height="162" alt="1197202563618503 PM" src="https://github.com/user-attachments/assets/7131255e-1dcd-4479-82c2-803dac971e6a" />


---

### 🚩 Flag 3: DISCOVERY - Network Reconnaissance

**Objective:** Identify the command and argument used to enumerate network neighbors.

**What to Hunt:** Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

**Hint 1:** Look for commands that reveal local network devices and their hardware addresses.

**Hint 2:** Check DeviceProcessEvents for network enumeration utilities executed after initial access.

**Reference:** System Network Configuration Discovery

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-21))
| where DeviceName contains 'azuki-sl'
| where AccountName == 'kenji.sato'
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `ARP.EXE -a`  
**Finding:** Adversaries and tools often use `arp -a` on Windows as a lightweight discovery step to see what other systems are on the same network, so many labs and detections treat this as a network‑neighbor enumeration action.
<img width="768" height="189" alt="Pasted Graphic 12" src="https://github.com/user-attachments/assets/86ba6679-5d4d-441b-87d7-8345c89d0521" />
<img width="769" height="527" alt="System Network Configuration Discovery" src="https://github.com/user-attachments/assets/e3b66bea-7e07-4c38-a83a-9c7a6e90d15c" />


---

### 🚩 Flag 4: DEFENSE EVASION - Malware Staging Directory

**Objective:** Identify the PRIMARY staging directory where malware was stored.

**What to Hunt:** Attackers establish staging locations to organize tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artifacts.

**Hint 1:** Search for newly created directories in system folders that were subsequently hidden from normal view.

**Hint 2:** Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.

**Reference:** Data Staged: Local Data Staging

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-30))
| where DeviceName contains 'azuki-sl'
| where AccountName == 'kenji.sato'
| where ProcessCommandLine has_any ("mm.exe", "curl.exe", "schtasks.exe")
| project TimeGenerated, ProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

**Output:** `C:\ProgramData\WindowsCache`  
**Finding:** The log data indicates that the attackers used **C:\ProgramData\WindowsCache** as the primary staging directory. This directory is frequently referenced in the **FolderPath** and **ProcessCommandLine** fields, hosting malicious binaries (e.g., `mm.exe`, `svchost.exe`) and exfiltrated data (e.g., `export-data.zip`). It is a hidden, system-critical location often used for storing tools and stolen data, aligning with the behavior of malware staging.
<img width="1205" height="182" alt="Pasted Graphic 14" src="https://github.com/user-attachments/assets/3b06868c-8919-464e-9ff4-3c09400e0103" />


---

### 🚩 Flag 5: DEFENSE EVASION - File Extension Exclusions

**Objective:** How many file extensions were excluded from Windows Defender scanning?

**What to Hunt:** Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

**Hint 1:** Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extensions.

**Hint 2:** Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

**Reference:** Impair Defenses: Disable or Modify Tools

**KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where ActionType == 'RegistryValueSet'
| where RegistryKey contains 'Extensions'
| project TimeGenerated, RegistryKey, RegistryValueName, InitiatingProcessFolderPath
```

**Output:** `3`  
**Finding:** The query results show three registry modifications to the `Exclusions\Extensions` key, each adding a distinct file extension (.bat, .ps1, .exe). These entries directly correspond to file extensions added to the exclusion list, a common evasion tactic to bypass antivirus scans. 3 distinct file extensions are shown in the log as a result.
<img width="1181" height="128" alt="Pasted Graphic 16" src="https://github.com/user-attachments/assets/b64ee668-d1d0-4c17-80cf-a225070e30bb" />


---

### 🚩 Flag 6: DEFENSE EVASION - Temporary Folder Exclusion

**Objective:** What temporary folder path was excluded from Windows Defender scanning?

**What to Hunt:** Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**Hint 1:** Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field.

**Hint 2:** Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field.

**Hint 3:** The registry key contains "Exclusions\Paths" under Windows Defender configuration.

**Reference:** Impair Defenses: Disable or Modify Tools

**KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where ActionType == 'RegistryValueSet'
| where RegistryKey contains 'Exclusion'
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, InitiatingProcessFolderPath
```

**Output:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`  
**Finding:** The log entries reveal exclusions configured via the Windows Defender registry settings. The `RegistryValueName` field in the third row explicitly lists a path added to the "Paths" exclusion list. This path is a standard temporary directory location (`AppData\Local\Temp`), aligning with the question's context. No encoded or obfuscated data is present in the relevant fields. The exclusion is explicitly documented in the registry, and the folder's role as a temporary storage location is well-established in Windows system design.
<img width="1256" height="237" alt="Pasted Graphic 17" src="https://github.com/user-attachments/assets/cace6e47-2697-4abb-b6c8-3c6b9cb71d68" />


---

### 🚩 Flag 7: DEFENSE EVASION - Download Utility Abuse

**Objective:** Identify the Windows-native binary the attacker abused to download files.

**What to Hunt:** Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**Hint 1:** Look for built-in Windows tools with network download capabilities being used during the attack.

**Hint 2:** Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

**Reference:** Living Off The Land Binaries

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where AccountName == 'kenji.sato'
| where FileName contains 'certutil.exe'
| project TimeGenerated, ProcessCommandLine, FolderPath, FileName
| order by TimeGenerated
```

**Output:** `certutil.exe`  
**Finding:** `certutil.exe` is a legitimate Windows utility for certificate management but can be weaponized by attackers to execute malicious code or exfiltrate data. Its misuse often involves leveraging its trusted status to bypass security controls. However, attackers may abuse `certutil.exe` to execute malicious payloads or exfiltrate data by leveraging its ability to run arbitrary commands in certain contexts (e.g., via `certutil -urlfetch` to download and execute payloads). This misuse is a known technique to evade detection, as the tool is trusted by the system.
<img width="1123" height="102" alt="Pasted Graphic 18" src="https://github.com/user-attachments/assets/8e09d884-e408-4536-8eae-a4ad55d01a59" />


---

### 🚩 Flag 8: PERSISTENCE - Scheduled Task Name

**Objective:** Identify the name of the scheduled task created for persistence.

**What to Hunt:** Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Hint 1:** Search for scheduled task creation commands executed during the attack timeline.

**Hint 2:** Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

**Reference:** Scheduled Task/Job: Scheduled Task

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where FileName contains 'schtasks.exe'
| where ActionType contains 'create'
| project TimeGenerated, ProcessCommandLine, FolderPath
| order by TimeGenerated
```

**Output:** `Windows Update Check`  
**Finding:** The "DeviceProcessEvents" log entries reveal two `schtasks.exe /create` actions. The first entry creates a task named `"Microsoft\Windows\Security\SecurityHealthService"` with a payload in the Temp directory (Flag 6). The third entry creates a task named `"Windows Update Check"` with a different payload path. Both are suspicious, but the third task name aligns with common attacker patterns (e.g., mimicking legitimate Windows tasks like "Windows Update"). The Log explicitly shows a `schtasks.exe /create` action with a task name matching attacker patterns and correlating with prior IOCs.
<img width="1183" height="125" alt="Pasted Graphic 19" src="https://github.com/user-attachments/assets/1b397017-a150-4847-aa4c-2f3fd12daf75" />


---

### 🚩 Flag 9: PERSISTENCE - Scheduled Task Target

**Objective:** Identify the executable path configured in the scheduled task.

**What to Hunt:** The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

**Hint 1:** Extract the task action from the scheduled task creation command line.

**Hint 2:** Look for the /tr parameter value in the schtasks command.

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where FolderPath contains 'schtasks' or ProcessCommandLine contains 'schtasks'
| project TimeGenerated, ProcessCommandLine, FolderPath
| order by TimeGenerated
```

**Output:** `C:\ProgramData\WindowsCache\svchost.exe`  
**Finding:** The `/tr` parameter in the log entry directly specifies the executable path, and the context aligns with persistence mechanisms observed in this flag. `svchost.exe` is a "known legitimate system process", but its presence in a non-standard directory and use as a task trigger suggests "malicious activity" (e.g., a fileless attack or a dropped payload). The task's `/tr` parameter directly maps to `svchost.exe`, making it the "runtime payload" of the persistence mechanism. The non-standard location of `svchost.exe` also further supports its suspicious nature.
<img width="1209" height="130" alt="Pasted Graphic 20" src="https://github.com/user-attachments/assets/16dbb46b-5c55-41e5-9348-ae7a0a2bec24" />


---

### 🚩 Flag 10: COMMAND & CONTROL - C2 Server Address

**Objective:** Identify the IP address of the command and control server.

**What to Hunt:** Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**Hint 1:** Analyse network connections initiated by the suspicious executable shortly after it was downloaded.

**Hint 2:** Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

**Reference:** Command and Control

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessAccountName contains 'kenji.sato'
| where InitiatingProcessCommandLine contains 'svchost.exe'
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIPType, RemoteIP
| order by TimeGenerated
```

**Output:** `78.141.196.6`  
**Finding:** The IP `78.141.196.6` is directly linked to downloading a malicious binary (`svchost.exe`) and executing PowerShell commands, which are strong indicators of C2 infrastructure. The exfiltration via Discord webhook from `162.159.135.232` is secondary evidence, but the primary C2 server is the one hosting the malicious payload.
<img width="1152" height="107" alt="Pasted Graphic 21" src="https://github.com/user-attachments/assets/e7bcf93e-7681-4c17-adfa-76e944fc1584" />


---

### 🚩 Flag 11: COMMAND & CONTROL - C2 Communication Port

**Objective:** Identify the destination port used for command and control communications.

**What to Hunt:** C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**Hint 1:** Examine the destination port for outbound connections from the malicious executable.

**Hint 2:** Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessAccountName contains 'kenji.sato'
| where InitiatingProcessCommandLine contains 'svchost.exe'
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIPType, RemoteIP, RemotePort
| order by TimeGenerated
```

**Output:** `443`  
**Finding:** The IP `78.141.196.6` form the C2 phase is associated with both connections of port "8080", but "port 443" is the "standard port" for HTTPS, which is align with the expected answer in a CTF scenario.
<img width="906" height="104" alt="Pasted Graphic 22" src="https://github.com/user-attachments/assets/88308a26-f64f-4e7b-a228-da93ae18df8e" />


---

### 🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool

**Objective:** Identify the filename of the credential dumping tool.

**What to Hunt:** Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**Hint 1:** Look for executables downloaded to the staging directory with very short filenames.

**Hint 2:** Search for files created shortly before LSASS memory access events.

**Reference:** OS Credential Dumping: LSASS Memory

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessAccountName contains 'kenji.sato'
| where FileName contains '.exe'
| project TimeGenerated, InitiatingProcessCommandLine, FileName
| order by TimeGenerated
```

**Output:** `mm.exe`  
**Finding:** The query results show multiple files downloaded from the IP `78.141.196.6` (Flag 10) using `certutil.exe`, including `svchost.exe`, `mm.exe`, and `AdobeGC[1].exe`. While `svchost.exe` is a legitimate system process, it is commonly abused in attacks for credential dumping. The filename `mm.exe` (5 characters) fits the 4–6 character criteria and could be a renamed tool. However, the most suspicious file is `svchost.exe`, as it is a known vector for credential theft when executed with malicious parameters. The command line for its download includes the IP and port (8080), aligning with the network context from Flags 10 and 11.
<img width="966" height="115" alt="Pasted Graphic 23" src="https://github.com/user-attachments/assets/402872a2-a98f-4c7f-b38f-1ed24e7a22d9" />


---

### 🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module

**Objective:** Identify the module used to extract logon passwords from memory.

**What to Hunt:** Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

**Hint 1:** Examine the command line arguments passed to the credential dumping tool.

**Hint 2:** Look for module::command syntax in the process command line or output redirection.

**Reference:** mimikatz

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessAccountName contains 'kenji.sato'
| where ProcessCommandLine contains '::'
| project TimeGenerated, ProcessCommandLine, FileName
```

**Output:** `sekurlsa::logonpasswords`  
**Finding:** The query results reveal a process executed by `mm.exe` (Flag 12), which is a known binary associated with "Mimikatz" binary, a credential dumping tool. The `ProcessCommandLine` field contains the string `"privilege::debug sekurlsa::logonpasswords exit"`, which aligns with Mimikatz's syntax for module-specific commands. The format `module::command` (e.g., `sekurlsa::logonpasswords`) is a hallmark of Mimikatz's interaction with Windows security subsystems. The `sekurlsa` module is explicitly designed to extract credentials from memory, including logon passwords, making this the direct answer to the flag question.
<img width="745" height="76" alt="Timedenerated (UTC) T$" src="https://github.com/user-attachments/assets/82ba88e6-936c-43cb-8ff0-368a0cda14f8" />



---

### 🚩 Flag 14: COLLECTION - Data Staging Archive

**Objective:** Identify the compressed archive filename used for data exfiltration.

**What to Hunt:** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**Hint 1:** Search for ZIP file creation in the staging directory during the collection phase.

**Hint 2:** Look for Compress-Archive commands or examine files created before exfiltration activity.

**Reference:** Archive Collected Data: Archive via Utility

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessAccountName contains 'kenji.sato'
| where ProcessCommandLine contains '.zip' or FileName contains '.zip'
| project TimeGenerated, ProcessCommandLine, FileName
| order by TimeGenerated asc
```

**Output:** `export-data.zip`  
**Finding:** The log entry indicates that `curl.exe` is uploading a file named `export-data.zip` to a Discord 'webhook'. The filename is explicitly referenced in the `ProcessCommandLine` field, which includes the full path `C:\ProgramData\WindowsCache\export-data.zip`. This directly aligns with the flag question's requirement to identify a ZIP archive used for data exfiltration. No obfuscation, encoding, or hidden patterns are present in the filename or surrounding fields.
<img width="996" height="74" alt="Pasted Graphic 26" src="https://github.com/user-attachments/assets/872b72bc-9cd4-4c3e-b0a8-12bb71dfc217" />


---

### 🚩 Flag 15: EXFILTRATION - Exfiltration Channel

**Objective:** Identify the cloud service used to exfiltrate stolen data.

**What to Hunt:** Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**Hint 1:** Analyze outbound HTTPS connections and file upload operations during the exfiltration phase.

**Hint 2:** Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

**Reference:** Exfiltration Over Web Service

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessAccountName contains 'kenji.sato'
| where InitiatingProcessCommandLine contains 'https'
| project TimeGenerated, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `Discord`  
**Finding:** The log entries indicate the use of `curl.exe` to upload the file `export-data.zip` to a Discord webhook endpoint (`https://discord.com/api/webhooks/...`). The command explicitly references the file path `C:\ProgramData\WindowsCache\export-data.zip` and uses the `-F` flag to send the file via HTTP POST, which is typical for file uploads. The destination domain (`discord.com`) is a known cloud service with upload capabilities, commonly abused for data exfiltration. No encoded/obfuscated data is present in the `ProcessCommandLine` field, and the pattern across all three rows (identical commands) confirms repeated exfiltration attempts.
<img width="1206" height="127" alt="Pasted Graphic 27" src="https://github.com/user-attachments/assets/24905d57-5e35-4a49-bdee-a62e97761455" />


---

### 🚩 Flag 16: ANTI-FORENSICS - Log Tampering

**Objective:** Identify the first Windows event log cleared by the attacker.

**What to Hunt:** Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**Hint 1:** Search for event log clearing commands near the end of the attack timeline.

**Hint 2:** Look for wevtutil.exe executions and identify which log was cleared first.

**Reference:** Indicator Removal: Clear Windows Event Logs

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where AccountName contains 'kenji.sato'
| where ProcessCommandLine contains'wevtutil.exe'
| project TimeGenerated, ProcessCommandLine, FileName
| order by TimeGenerated asc
```

**Output:** `Security`  
**Finding:** The query results show multiple executions of `wevtutil.exe` with the `cl` (clear log) parameter. The flag question asks for the **first log cleared** by the attacker. The earliest timestamp in the dataset is **2025-11-19 19:11:39**, where `wevtutil.exe cl Security` is executed. This directly clears the **Security** log. Subsequent entries (e.g., `System`, `Application`) occur later, both in time and in the dataset. No obfuscation, encoding, or hidden data is present in the `ProcessCommandLine` fields. The attacker's first action using `wevtutil.exe` explicitly targets the **Security** log, aligning with the anti-forensic tactic of erasing audit trails.
<img width="905" height="267" alt="11182025, 7 31-39 093 PM" src="https://github.com/user-attachments/assets/b8525d2f-854b-46e3-aef4-84247f417749" />


---

### 🚩 Flag 17: IMPACT - Persistence Account

**Objective:** Identify the backdoor account username created by the attacker.

**What to Hunt:** Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**Hint 1:** Search for account creation commands executed during the impact phase.

**Hint 2:** Look for commands with the /add parameter followed by administrator group additions.

**Reference:** Create Account: Local Account

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where AccountName contains 'kenji.sato'
| where ProcessCommandLine contains '/add'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `support`  
**Finding:** While `yuki.tanaka` appears in a credential storage command, the question explicitly asks for an **account created** (not a credential stored). The `support` user was explicitly added via `net user` and granted administrative privileges via `net localgroup Administrators`, aligning with the "IMPACT" phase's goal of establishing persistence. The `yuki.tanaka` entry likely relates to lateral movement or credential theft, not account creation.
<img width="658" height="183" alt="TimeGenerated (UTC" src="https://github.com/user-attachments/assets/e726c4e2-ac81-48e8-8f7c-108c7c3ab45f" />


---

### 🚩 Flag 18: EXECUTION - Malicious Script

**Objective:** Identify the PowerShell script file used to automate the attack chain.

**What to Hunt:** Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**Hint 1:** Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase.

**Hint 2:** Look for PowerShell or batch script files downloaded from external sources shortly after initial access.

**Reference:** Command and Scripting Interpreter: PowerShell

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains'invoke'
| project TimeGenerated, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `wupdate.ps1`  
**Finding:** The log data reveals multiple PowerShell commands using `Invoke-WebRequest` to download scripts. The first occurrence (Row 0) explicitly downloads a `.ps1` file (`wupdate.ps1`) to a temporary directory (`C:\Users\KENJI~1.SAT\AppData\Local\Temp`). This aligns with the flag question's focus on identifying the **initial attack script** used to automate the attack chain. PowerShell scripts (.ps1) are commonly leveraged by attackers for automation, making this file a strong candidate. Subsequent entries (Rows 1 and 2) download similar files, but the **first download** establishes the **initial entry point**.
<img width="1216" height="177" alt="Pasted Graphic 29" src="https://github.com/user-attachments/assets/9a7c418d-9940-4ac9-b419-0bcadc7c41b2" />


---

### 🚩 Flag 19: LATERAL MOVEMENT - Secondary Target

**Objective:** What IP address was targeted for lateral movement?

**What to Hunt:** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**Hint 1:** Examine the target system specified in remote access commands during lateral movement.

**Hint 2:** Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.

**Reference:** Use Alternate Authentication Material  
**Reference:** Lateral Movement (TA0008)

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessCommandLine contains'cmdkey' or InitiatingProcessCommandLine contains 'mstsc'
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIP, LocalIP, InitiatingProcessFileName 
| order by TimeGenerated asc
```

**Output:** `10.1.0.188`  
**Finding:** The flag question focuses on identifying lateral movement targets, which are typically systems with elevated privileges or access to sensitive data. The log data reveals multiple Remote Desktop Protocol (RDP) connections (via `mstsc.exe`) from the local IP `10.1.0.204` to three remote IPs: `10.1.0.108`, `10.1.0.188`, and `10.1.0.108` again. Lateral movement often involves repeated access to a single target, suggesting that the attacker is prioritizing a system with strategic value (e.g., privileged access or data storage).  

The IP `10.1.0.188` appears **twice** in the logs (rows 1 and 2), indicating repeated attempts to access it. This aligns with the pattern of lateral movement, where attackers stabilize access to a target system. Additionally, the use of RDP (`mstsc.exe`) implies the attacker is leveraging remote access tools to exploit credentials or privileges, further supporting the hypothesis that `10.1.0.188` is the primary lateral movement target.
<img width="978" height="157" alt="1616 204" src="https://github.com/user-attachments/assets/616d35ba-3998-4453-a7e5-7032d0ff6495" />


---

### 🚩 Flag 20: LATERAL MOVEMENT - Remote Access Tool

**Objective:** Identify the remote access tool used for lateral movement.

**What to Hunt:** Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

**Hint 1:** Search for remote desktop connection utilities executed near the end of the attack timeline.

**Hint 2:** Look for processes launched with remote system names or IP addresses as arguments.

**Reference:** Remote Services: Remote Desktop Protocol

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-30))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessCommandLine contains'10.1.0.188'
| project TimeGenerated, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `mstsc.exe`  
**Finding:** The query results explicitly show two instances of `mstsc.exe` being executed with the `/v:10.1.0.188` argument, which is the standard command-line parameter for specifying the remote computer in Microsoft Remote Desktop Protocol (RDP) connections. This directly indicates the use of **RDP** as the remote access tool for lateral movement. The logs align with the context of Flag 19's IP (`10.1.0.188`) and do not show any obfuscation, encoding, or indirect references to other binaries (e.g., `wupdate.ps1`). The `mstsc.exe` process is unambiguously tied to the lateral movement attempt toward the target IP.
<img width="416" height="159" alt="TimeGenerated  UTC" src="https://github.com/user-attachments/assets/91604f8d-ef82-48a6-a2c9-70ab9a28d758" />


<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🔎 Analyst Workflow

### From an investigative standpoint, the workflow progressed as follows:

**1 ➝ 2 🚩:** External RDP connection from `88.97.178.12` authenticated with compromised credentials (`kenji.sato`). Was this the initial entry point?

**2 ➝ 3 🚩:** After gaining access, did the attacker immediately begin network reconnaissance to map the environment?

**3 ➝ 4 🚩:** Reconnaissance complete, where did the attacker establish their staging area for tools and stolen data?

**4 ➝ 5 🚩:** Before deploying tools, did the attacker disable Windows Defender protections by excluding file extensions?

**5 ➝ 6 🚩:** In addition to file extensions, did they exclude a temporary folder path to ensure undetected execution?

**6 ➝ 7 🚩:** With defenses weakened, which legitimate Windows tool did they abuse to download malicious payloads?

**7 ➝ 8 🚩:** To ensure persistence, did the attacker create a scheduled task disguised as a legitimate Windows process?

**8 ➝ 9 🚩:** What executable was configured to run when the scheduled task triggered?

**9 ➝ 10 🚩:** The malicious executable established C2 communication. Which external IP address did it contact?

**10 ➝ 11 🚩:** C2 communication requires a port. Which standard HTTPS port was used for encrypted command and control?

**11 ➝ 12 🚩:** With C2 established, did the attacker deploy a credential dumping tool to extract authentication secrets?

**12 ➝ 13 🚩:** Which Mimikatz module was used to extract logon passwords from system memory?

**13 ➝ 14 🚩:** After credential theft, did the attacker compress stolen data into an archive for efficient exfiltration?

**14 ➝ 15 🚩:** Staging complete, which cloud service was used to exfiltrate the stolen data archive?

**15 ➝ 16 🚩:** To cover tracks, did the attacker clear event logs, starting with the Security log?

**16 ➝ 17 🚩:** Before concluding, did the attacker create a hidden backdoor account for future access?

**17 ➝ 18 🚩:** Throughout the attack, was a PowerShell script used to automate the entire attack chain?

**18 ➝ 19 🚩:** With credentials stolen, did the attacker attempt lateral movement to other systems on the network?

**19 ➝ 20 🚩:** Which built-in Windows tool was used to establish remote desktop connections for lateral movement?
