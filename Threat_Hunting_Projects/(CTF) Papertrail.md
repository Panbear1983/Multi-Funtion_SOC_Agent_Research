# 🧾 Papertrail — Insider HR Tamper (CTF)
<img width="1536" height="1024" alt="AN7BsVD9Q9eVWIKBEH5ItR8O35fyrBLgMyFe8hXdMphBUspIIT-PPe6tvV64ZAC_I0CUdN1lOp50FAOApYIFyoQ3-ZmKwoHDOlw91bbLtRSnxk3IsHv32_FVf_Tm" src="https://github.com/user-attachments/assets/495af84a-c49c-43b1-ba97-fbcd24a7c7f7" />



## 📏 Perimeters
Date Completed: ***2025-09-08***  
Participant: Peter Pan ***Panbear*** (w/ fellow team member: [**Jorge Juarez**](https://github.com/jorjuarez), [**Andrey Massalskiy**](https://github.com/massandr))  
Simulated Environment: `LOG(N) Pacific - Cyber Range 1`  
Infected Host VMs: `n4thani3l-vm` (primary), `nathan-i3l-vm` (legit/decoy naming variant used during recon)  
Suspected Time Frame: ***August 17 – 20, 2025***  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview

An insider masqueraded HR automation to tamper with performance records and bury audit evidence. The actor used **PowerShell** with execution-policy bypass, blended actions under an **HRTools** directory, queried local/privileged accounts, and reviewed credential-rich artifacts created via **rundll32 + comsvcs.dll**. They **disabled Defender runtime**, **modified Defender policy** via registry, beaconed outbound to **Azure Blob**/Pipedream (`*.core.windows.net`, `*.pipedream.net`), established persistence with a **legacy-themed script**, and attempted **audit-log and history cleanup**. Despite anti-forensics, the reconstructed timeline exposes motive around **promotion data** manipulation and personnel file targeting.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis

| Feature        | Details                                                                 |
|----------------|-------------------------------------------------------------------------|
| **Adversary**  | Insider / red-team emulating insider. Hands-on-keyboard, comfortable with PS tradecraft, LOLBins, and anti-forensics. |
| **Infrastructure** | Outbound to **Azure Blob** (`*.core.windows.net`) and **Pipedream** (`*.pipedream.net`). LOLBins used locally (`wevtutil.exe`, `qwinsta.exe`). |
| **Capability** | PowerShell (bypass), account & group discovery, **rundll32 + comsvcs.dll** memory access, Defender runtime disable + registry policy change, persistence via autorun script. |
| **Victim**     | Primary: **`n4thani3l-vm`**; naming variant overlap with **`nathan-i3l-vm`** leveraged for camouflage during discovery. Target data tied to HR personnel and promotion artifacts. |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Flag/Event                               | Tactic               | Technique ID      | Technique Name                                                                 |
|------------------------------------------|----------------------|-------------------|--------------------------------------------------------------------------------|
| Initial PS Execution                      | Execution            | **T1059.001**     | Command & Scripting Interpreter: **PowerShell**                                |
| Local Account Enumeration                 | Discovery            | **T1087.001**     | Account Discovery: **Local Account**                                           |
| Privileged Group Check                    | Discovery            | **T1069.001**     | Permission Groups Discovery: **Local Groups**                                  |
| Active Session Discovery (`qwinsta`)      | Discovery            | **T1033**         | System Owner/User Discovery (logged-on sessions)                               |
| Defender Runtime Disable                  | Defense Evasion      | **T1562.001**     | Impair Defenses: **Disable or Modify Tools**                                   |
| Defender Policy (Registry) Change         | Defense Evasion      | **T1112**         | **Modify Registry**                                                            |
| LSASS/Memory Access via `comsvcs.dll`     | Credential Access    | **T1003.001**     | OS Credential Dumping: **LSASS Memory**                                        |
| File Review of Dump (`HRConfig.json`)     | Collection           | **T1005**         | Data from Local System                                                         |
| Exfil Test to non-`.com` endpoints        | Exfiltration         | **T1567.002**     | Exfiltration Over Web Services: **Cloud Storage**                              |
| Persistence via Run Key Script            | Persistence          | **T1547.001**     | Boot/Logon Autostart: **Registry Run Keys / Startup Folder**                   |
| Data/Record Manipulation (promotion list) | Impact/Evasion       | **T1565.001**     | **Stored Data Manipulation**                                                   |
| Event Log Clearing (`wevtutil cl`)        | Defense Evasion      | **T1070.001**     | Indicator Removal: **Clear Windows Event Logs**                                |
| Clear Shell History (PS console)          | Defense Evasion      | **T1070.003**     | Indicator Removal: **Clear Command History**                                   |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
1. **PowerShell Guardrails**
   - Enforce **Constrained Language Mode**; block PowerShell v2; enable **Script Block** + **Module** logging to central SIEM.
2. **Defender Hardening**
   - Alert on `Set-MpPreference`/`MpCmdRun` tampering; lock registry keys for Defender policy; baseline **Disable**-prefixed values.
3. **HRTools Path Controls**
   - Monitor `C:\HRTools\**` for unusual writes/exec (non-signed, user-context); require signing for automation scripts.
4. **Credential Dumping Detections**
   - Create rules for `rundll32.exe` loading `comsvcs.dll`; alert on `lsass.exe` handles from non-system processes.
5. **Persistence Audits**
   - Watch `HKCU/HKLM\...\Run` for new/modified values executing PS/HTA; verify `OnboardTracker.ps1`-style names.
6. **Egress Controls**
   - Review allowlists for `*.core.windows.net`; restrict paste/test services (e.g., `*.pipedream.net`); deploy **CASB/DLP**.
7. **Anti-Forensics Alerts**
   - Alert on `wevtutil cl *`, `Clear-EventLog`, `ConsoleHost_history` touches; ship critical logs to write-once storage.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
- **Camouflage Matters:** HR-themed folders and legacy names hide malicious PS activity in plain sight.  
- **Name Games:** Look-alike **device/account** names impede simple equals-filters—normalize and correlate behaviorally.  
- **Defense First:** Detect **Defender runtime + registry** tampering early; both commonly precede collection/exfil.  
- **Persistence is Boring on Purpose:** Plain `.ps1` under Run keys blends as “business tooling”.  
- **Anti-Forensics is Noisy:** `wevtutil cl` and history wipes still leave process/file/network breadcrumbs.  
- **Chain the Timeline:** Reconstructing **who → what → where → when** beats chasing isolated IOCs.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion
“Papertrail” illustrates a quiet insider blending with HR automation to alter records and prep a fraudulent promotion. By correlating **process**, **file**, **registry**, and **network** telemetry—despite anti-forensics—we surfaced the attack chain: **PS recon → privilege scoping → Defender weakening → credential access → outbound testing → persistence → data targeting → audit disruption**. The outcome: a forensically sound timeline and concrete controls to prevent recurrence.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)**          | **Event**                                         | **Target Device** | **Details** |
|------------------------------|---------------------------------------------------|-------------------|-------------|
| **2025-08-19 03:42:32.938Z** | Earliest suspicious PS activity                   | n4thani3l-vm      | Initial “who” context enumeration (Flag 1) |
| **2025-08-19 ~**             | Local account discovery begins                    | n4thani3l-vm      | SHA256 tied to recon instance (Flag 2) |
| **2025-08-19 ~**             | Privileged group query                            | nathan-i3l-vm     | `net localgroup Administrators` (Flag 3) |
| **2025-08-19 ~**             | Active sessions enumerated                        | nathan-i3l-vm     | `qwinsta.exe` (Flag 4) |
| **2025-08-19 ~**             | Defender runtime disabled                         | n4thani3l-vm      | `Set-MpPreference -DisableRealtimeMonitoring $true` (Flag 5) |
| **2025-08-19 ~**             | Defender policy registry modified                 | n4thani3l-vm      | `DisableAntiSpyware` (Flag 6) |
| **2025-08-19 ~**             | HR-labeled dump artifact referenced               | n4thani3l-vm      | `HRConfig.json` tied to `comsvcs.dll` (Flag 7) |
| **2025-08-19 ~**             | Dump reviewed locally                             | n4thani3l-vm      | `notepad.exe C:\HRTools\HRConfig.json` (Flag 8) |
| **2025-08-19 ~**             | Beacon / connectivity test to non-`.com`          | n4thani3l-vm      | `.net` endpoints (Flag 9) |
| **2025-08-19 ~**             | Last unusual outbound ping (recon)                | n4thani3l-vm      | `3.234.58.20` (Pipedream) (Flag 10) |
| **2025-08-19 ~**             | Persistence registered via legacy script          | n4thani3l-vm      | `OnboardTracker.ps1` (Flag 11) |
| **2025-08-19 ~**             | Repeatedly accessed personnel record              | n4thani3l-vm      | `Carlos Tanaka` (Flag 12) |
| **2025-08-19 ~**             | Promotion list modified (first instance)          | n4thani3l-vm      | SHA1 `df5e35a8...fa05` (Flag 13) |
| **2025-08-19 04:55:48.966Z** | First audit-trail clearing attempt                | n4thani3l-vm      | `wevtutil cl …` (Flag 14) |
| **2025-08-19 05:08:11.852Z** | Last associated cleanup attempt (final)           | n4thani3l-vm      | Latest `FileDeleted` (PS history focus) (Flag 15) |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flags   | Objective                                           | Value |
|---------|------------------------------------------------------|-------|
| **Start** | First suspicious machine                           | `n4thani3l-vm` |
| **1**   | First suspicious PS creation time                    | `2025-08-19T03:42:32.9389416Z` |
| **2**   | Associated SHA256 (local account assessment)         | `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3` |
| **3**   | Privileged group assessment command                  | `"powershell.exe" net localgroup Administrators` |
| **4**   | Active session discovery program                     | `qwinsta.exe` |
| **5**   | Defender config recon command                        | `"powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep -Seconds 1; Set-Content -Path "C:\Users\Public\PromotionPayload.ps1" -Value "Write-Host 'Payload Executed'"` |
| **6**   | Defender policy modification value (registry)        | `DisableAntiSpyware` |
| **7**   | HR-related file name tied to memory access tactic    | `HRConfig.json` |
| **8**   | Command that inspected dumped artifact               | `"notepad.exe" C:\HRTools\HRConfig.json` |
| **9**   | TLD of unusual outbound communication                | `.net` |
| **10**  | Ping (RemoteIP) of last unusual outbound attempt     | `3.234.58.20` |
| **11**  | File name tied to persistence registry value         | `OnboardTracker.ps1` |
| **12**  | Personnel file name repeatedly accessed              | `Carlos Tanaka` |
| **13**  | First modified promotion file SHA1                   | `df5e35a8dcecdf1430af7001c58f3e9e9faafa05` |
| **14**  | First audit-trail clearing attempt timestamp         | `2025-08-19T04:55:48.9660467Z` |
| **15**  | Last associated cleanup attempt timestamp            | `2025-08-19T05:08:11.8528871Z` |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏁 Hunting Flags

**Starting Point:** Initial Machine Identification
**Objective:** Determine the first machine touched via HR configs/scripts.
**What to Hunt:** .xml artifacts created by PowerShell between Aug 17–20, 2025.
**TTP:** Script-generated config drops in HR/operations paths via powershell.exe.
**Why It Matters:** Establishes the initial foothold and narrows the time/device scope for subsequent flags.

**KQL Query:**

***//Identify the initial compromised vm***
```
let StartTime = datetime(2025-08-17);
let EndTime = datetime(2025-08-20);
DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where InitiatingProcessCommandLine contains "powershell.exe"
| where FileName has_any (".xml")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCreationTime, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Output:** n4thani3l-vm
**Finding:** The spoofed the legitmate VM `nathan-i3l-vm` with fake VM `n4thani3l-vm`. Filtering file events for PowerShell-driven .xml creation during the specified window surfaced entries consistent with script-generated configs rather than standard HR executables. The earliest such activity points to n4thani3l-vm, identified as the initial foothold host.
<img width="1153" height="266" alt="Pasted Graphic 4" src="https://github.com/user-attachments/assets/d4af313b-43f4-4478-87a3-2fa859deed06" />


---

### Flag 1: Initial PowerShell Execution Detection

**Objective:** Pinpoint the earliest suspicious PowerShell activity marking the intruder’s entry.  
**What to Hunt:** PowerShell usage deviating from baseline, including lightweight reconnaissance like who.  
**TTP:** Command-and-scripting interpreter abuse (PowerShell) for environment awareness.  
**Why It Matters:** Establishes the first malicious process creation to anchor subsequent actions.  

**KQL Query:**  

***// Identify the initial suspicious process***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where AccountName contains "n4th4n13l"
| where ProcessCommandLine contains "who"
| project Timestamp, InitiatingProcessParentCreationTime, InitiatingProcessCreationTime,
          DeviceName, FileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Output:** `2025-08-19T03:42:32.9389416Z`  
**Finding:** The earliest anomalous PowerShell activity appears at 03:42:32Z on Aug 19. Note the concurrent device-name spoofing (n4than-i3l-vm vs. n4thani3l-vm), which complicates host attribution and underscores the need to correlate across multiple telemetry types.  
<img width="1263" height="451" alt="Pasted Graphic 1" src="https://github.com/user-attachments/assets/4536e01f-9208-4a2d-9293-837805b7cd83" />


---

### Flag 2: Local Account Assessment

**Objective:** Confirm local identity enumeration following initial foothold.  
**What to Hunt:** Account discovery queries and associated process hashes.  
**TTP:** Local account reconnaissance to stage impersonation and privilege escalation.  
**Why It Matters:** Early identity mapping signals intent to pivot privileges or blend with legitimate users.  

**KQL Query:**

***// Identify the associated SHA256 value***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceEvents
| where Timestamp between (StartTime .. EndTime)
| where AccountName has_any ("n4th4n13l", "n4th4n-13l")
| project Timestamp, DeviceName, AccountName, SHA256, InitiatingProcessSHA256
| order by Timestamp asc
```
**Output:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
**Finding:** Multiple account-name variants (n4th4n13l, n4th4n-13l, N4th4n13L) appear, indicating alias spoofing during enumeration. The associated SHA256 above ties the activity to a specific process lineage.  
<img width="1275" height="559" alt="Pasted Graphic 2" src="https://github.com/user-attachments/assets/e5cfe945-0218-43c8-a1c5-21b5c88125a1" />


---

### Flag 3: Privileged Group Assessment

**Objective:** Identify checks for elevated local administrators.  
**What to Hunt:** Group membership queries executed from PowerShell.  
**TTP:** Discovery of privileged groups to target admin accounts.  
**Why It Matters:** Reveals preparation for escalation and potential lateral movement.  

**KQL Query:**

***// Looking for the InitiatingCommandLine for privileged group***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "nathan-i3l-vm"
| where InitiatingProcessCommandLine has_any ("net","Get","who","local","admin","privilege","account","member","group")
| project Timestamp, FileName, ProcessCreationTime, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
```
**Output:** `"powershell.exe" net localgroup Administrators`  
**Finding:** The actor leverages PowerShell to invoke net localgroup Administrators, enumerating local admins and surfacing accounts of interest such as n4th4n13l.  
<img width="1373" height="573" alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/7cb2e4b1-5023-4ba7-bfc8-db84c5d2e6f3" />


---

### Flag 4: Active Session Discovery

**Objective:** Identify enumeration of active sessions for potential piggybacking.  
**What to Hunt:** qwinsta or query session execution.  
**TTP:** Session discovery to blend operations with existing user contexts.  
**Why It Matters:** Riding live sessions reduces new-logon noise and helps evade detections.  

**KQL Query:**

***// Reveal active sessions for potential masking***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "nathan-i3l-vm"
| where InitiatingProcessCommandLine has_any ("qwinsta","query session")
| project FileName, InitiatingProcessFileName
```
**Output:** `qwinsta.exe`  
**Finding:** Use of qwinsta.exe confirms active session enumeration consistent with masquerading tactics.  
<img width="793" height="137" alt="Pasted Graphic 5" src="https://github.com/user-attachments/assets/8daed584-ad69-4d32-ae42-d02cad8f9237" />


---

### Flag 5: Defender Configuration Recon

**Objective:** Detect tampering with Defender runtime protections masked as HR activity.  
**What to Hunt:** PowerShell commands modifying Defender preferences.  
**TTP:** Defense evasion via Set-MpPreference and payload staging.  
**Why It Matters:** Disabling real-time monitoring enables subsequent credential access and exfiltration with reduced telemetry.  

**KQL Query:**

***// Investigate AV disablement disguised as HR activity***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "n4thani3l-vm"
| where InitiatingProcessCommandLine has_any ("powershell","union","defender","get","preference")
| project Timestamp, InitiatingProcessCommandLine
```
**Output:** `"powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep -Seconds 1; Set-Content -Path "C:\Users\Public\PromotionPayload.ps1" -Value "Write-Host 'Payload Executed'"`  
**Finding:** The actor bypasses execution policy, disables real-time monitoring, inserts a brief delay, and drops a staged payload to C:\Users\Public\PromotionPayload.ps1.  
<img width="1713" height="60" alt="Pasted Graphic 6" src="https://github.com/user-attachments/assets/c046528e-688e-4e9c-9991-2fb0df4fb38b" />


---

### Flag 6: Defender Policy Modification

**Objective:** Validate registry-level weakening of baseline protections.  
**What to Hunt:** Defender-related registry values set to disable protections.  
**TTP:** Persistent defense evasion by policy modification.  
**Why It Matters:** Policy changes survive reboots and degrade long-term detection.  

**KQL Query:**

***// Registry change indicating Defender disablement***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "n4thani3l-vm"
| where RegistryValueName contains "disable"
| project Timestamp, RegistryValueName
```
**Output:** `DisableAntiSpyware`  
**Finding:** Setting DisableAntiSpyware indicates intentional reduction of Defender coverage beyond runtime toggles.  
<img width="667" height="141" alt="Timestamp" src="https://github.com/user-attachments/assets/4edd0c70-fba3-431a-92ad-a8ac89fe4c21" />


---

### Flag 7: Access to Credential-Rich Memory Space

**Objective:** Confirm use of native tools to target credential-bearing memory.  
**What to Hunt:** rundll32 with comsvcs.dll and HR-themed file operations.  
**TTP:** LOLBin memory dump techniques masked as HR tooling.  
**Why It Matters:** Memory dumps often precede credential theft and lateral movement.  

**KQL Query:**

***// HR-themed LOLBin interaction with protected memory***
```
let StartTime = datetime(2025-08-05);
let EndTime   = datetime(2025-08-20);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "n4thani3l-vm"
| where ProcessCommandLine has_any ("comsvcs.dll","HRTool")
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, ActionType
```
**Output:** `HRConfig.json`  
**Finding:** Activity referencing comsvcs.dll (via rundll32) and HR tooling correlates with artifacts written/read as HRConfig.json, aligning with credential-access tradecraft under business pretext.  
<img width="1667" height="176" alt="Pasted Graphic 9" src="https://github.com/user-attachments/assets/a4d1cafa-a9d9-4124-ad33-ba55cad88286" />


---

### Flag 8: File Inspection of Dumped Artifacts

**Objective:** Validate post-collection review of sensitive dump content.  
**What to Hunt:** Local tools opening HR-themed dump files.  
**TTP:** On-host verification of collected data prior to exfiltration.  
**Why It Matters:** Confirms successful collection and triage before staging.  

**KQL Query:**

***// Command-line access to the dump post-collection***
```
let StartTime = datetime(2025-08-19T03:59:55.835968Z);
let EndTime   = datetime(2025-08-20);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("notepad","Get","Content","type")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
```
**Output:** `"notepad.exe" C:\HRTools\HRConfig.json`  
**Finding:** notepad.exe opens C:\HRTools\HRConfig.json, indicating on-host review of a sensitive HR-config artifact likely tied to a prior dump.  
<img width="1684" height="205" alt="Pasted Graphic 10" src="https://github.com/user-attachments/assets/18b8dc87-3f49-4117-aeff-79103c9b6668" />


---

### Flag 9: Outbound Communication Test

**Objective:** Identify non-standard outbound beacons used to verify egress.  
**What to Hunt:** Lightweight connectivity checks to atypical TLDs.  
**TTP:** External reachability testing prior to exfiltration.  
**Why It Matters:** Early beacons reveal planned exfiltration channels.  

**KQL Query:**

***// Identify unusual outbound destinations by TLD***
```
let StartTime = datetime(2025-08-19T03:59:55.835968Z);
let EndTime   = datetime(2025-08-20);
DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where isnotempty(RemoteUrl) and RemoteUrl !has ".com"
| project Timestamp, RemoteUrl, Protocol, RemoteIP, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Output:** `.net`  
**Finding:** Egress tests target .net destinations (e.g., Azure blob endpoints), aligning with staging to cloud infrastructure.  
<img width="1524" height="98" alt="Pasted Graphic 11" src="https://github.com/user-attachments/assets/7e371dad-1391-4bf2-ab9f-4739b471c7f2" />


---

### Flag 10: Covert Data Transfer

**Objective:** Capture the final reconnaissance ping before active exfiltration.  
**What to Hunt:** Last suspicious .net connection and its IP.  
**TTP:** Beacon confirmation to external service prior to data transfer.  
**Why It Matters:** The last pre-exfil contact helps bracket the exfiltration window.  

**KQL Query:**

***// Last suspicious outbound ping (.net) prior to exfiltrate***
```
let StartTime = datetime(2025-08-19T03:59:55.835968Z);
let EndTime   = datetime(2025-08-20T23:59:59);
DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where RemoteUrl has ".net"
| project Timestamp, RemoteIP, RemotePort, Protocol, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Output:** `3.234.58.20`  
**Finding:** The final reconnaissance connection resolves to 3.234.58.20 (e.g., pipedream endpoint), marking the transition toward exfiltration. 
<img width="1179" height="419" alt="Pasted Graphic 12" src="https://github.com/user-attachments/assets/050bb553-7f67-458a-a8ca-b7bf933fe12c" />


---

### Flag 11: Persistence via Local Scripting

**Objective:** Verify persistence established through legacy/autorun mechanisms.  
**What to Hunt:** Startup configurations invoking non-standard scripts.  
**TTP:** Registry Run/autorun persistence using HR-themed script names.  
**Why It Matters:** Ensures continuity of access under the guise of business tooling.  

**KQL Query:**

***// Identify executable/script tied to autorun-style registry value***
```
let StartTime = datetime(2025-08-19T04:37:45.2395387Z);
let EndTime   = datetime(2025-08-20T23:59:59);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("run","legacy")
| project Timestamp, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc
```
**Output:** `OnboardTracker.ps1`  
**Finding:** A legacy-themed autorun path references OnboardTracker.ps1, signaling script-based persistence masquerading as HR onboarding automation.  
<img width="1341" height="81" alt="Pasted Graphic 14" src="https://github.com/user-attachments/assets/2d05c71c-dc5a-4276-b826-294be7e94af8" />
<img width="1595" height="104" alt="Pasted Graphic 13" src="https://github.com/user-attachments/assets/938038b8-776a-4cfc-a683-bcce026bca89" />


---

### Flag 12: Targeted File Reuse / Access

**Objective:** Surface the personnel file that drew repeated attention.  
**What to Hunt:** Multiple accesses to PII-bearing .txt files.  
**TTP:** Target validation and staging of personnel data for influence or extortion.  
**Why It Matters:** The repeatedly accessed file often reveals motive and target.  

**KQL Query:**

***// Identify repeatedly accessed personnel text files***
```
let StartTime = datetime(2025-08-19T04:46:06.5654042Z);
let EndTime   = datetime(2025-08-20T23:59:59);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine contains ".txt"
| project Timestamp, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc
```
**Output:** `Carlos Tanaka`  
**Finding:** Personnel entries show disproportionate access to Carlos Tanaka (six instances), distinguishing it from other one-off lookups.  
<img width="1230" height="345" alt="Pasted Graphic 15" src="https://github.com/user-attachments/assets/e18120be-7a14-41c9-97da-150498d1ae14" />


---

### Flag 13: Candidate List Manipulation

**Objective:** Detect tampering with promotion-related records.  
**What to Hunt:** Early modifications to promotion files and their hashes.  
**TTP:** Structured data manipulation prior to exfiltration.  
**Why It Matters:** Confirms staging and tampering tied directly to the promotion narrative.  

**KQL Query:**

***// First modification and SHA1 for promotion-related data***
```
let StartTime = datetime(2025-08-18T04:37:10.5471617Z);
let EndTime   = datetime(2025-08-20T23:59:59);
DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where FileName contains "promotion"
| project Timestamp, ActionType, InitiatingProcessCommandLine, SHA1
| order by Timestamp asc
```
**Output:** df5e35a8dcecdf1430af7001c58f3e9e9faafa05  
**Finding:** The earliest promotion-file modification (e.g., PromotionCandidates.csv) yields the SHA1 above, linking manipulation to the broader HR tampering timeline.  
<img width="1342" height="285" alt="Pasted Graphic 17" src="https://github.com/user-attachments/assets/1a36372b-bf4d-4fb9-b9e3-f4a85be7b6b5" />


---

### Flag 14: Audit Trail Disruption

**Objective:** Find the first attempt to impair forensic visibility.  
**What to Hunt:** wevtutil usage and disabling/clearing event logs.  
**TTP:** Indicator removal via Windows Event Log operations.  
**Why It Matters:** Early log manipulation is a strong signal of anti-forensics intent.  

**KQL Query:**

***// First attempt to clear/disable logging***
```
let StartTime = datetime(2025-08-01T23:59:59);
let EndTime   = datetime(2025-08-20T23:59:59);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where AccountName == "n4th4n13l"
| where ProcessCommandLine has_any ("eventlog","clean","disab","wevtutil")
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Output:** `2025-08-19T04:55:48.9660467Z`  
**Finding:** The first recorded anti-forensics action appears just before 05:00Z on Aug 19, with wevtutil-based log manipulation surfacing in command-line artifacts.  
<img width="979" height="374" alt="Pasted Graphic 18" src="https://github.com/user-attachments/assets/9c246e1c-376e-475e-95a8-02a6baf34b9e" />


---

### Flag 15: Final Cleanup and Exit Prep

**Objective:** Capture the last anti-forensics attempt before the actor exits.  
**What to Hunt:** Deletions of artifacts (e.g., PowerShell history) and other cleanup.  
**TTP:** Trace removal and script history deletion to impede investigation.  
**Why It Matters:** The final cleanup timestamp helps cap the incident timeline.  

KQL Query:

***// Last timestamp for actor's file deletion activity***
```
let StartTime = datetime(2025-08-01T23:59:59);
let EndTime   = datetime(2025-08-31T23:59:59);
DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName == "n4thani3l-vm"
| where ActionType contains "delete"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessCommandLine
| order by Timestamp desc
```
**Output:** `2025-08-19T05:08:11.8528871Z`  
**Finding:** The last associated cleanup targets ConsoleHost_history.txt via PowerShell, aligning with a typical sequence of history and trace deletion immediately prior to exit.  
<img width="1241" height="451" alt="Pasted Graphic 19" src="https://github.com/user-attachments/assets/357b2d49-e24a-4dc3-abc5-cdc49b93fd61" />


---

# FINISHED!!
<img width="495" height="496" alt="Pasted Graphic 20" src="https://github.com/user-attachments/assets/7c8e42cf-0145-46e2-8fb4-1fdd567b4bbf" />


---

# Flag Logic Flow:

Initial → 1 🚩: "New system activity surfaced involving HRTools. Was initial enumeration conducted using PowerShell to assess privilege context?"  
1 → 2 🚩: "Basic privilege data was revealed. Did the attacker move next to enumerate local user accounts to scope potential HR targets?"  
2 → 3 🚩: "User listings are often followed by privilege pivoting. Was the local admin group queried to identify elevated accounts?"  
3 → 4 🚩: "Recon suggests the attacker may be masking actions as legitimate HR activity. Did they check active sessions to piggyback on valid users?"  
4 → 5 🚩: "To safely proceed, attackers often tamper with security tools. Is there evidence of Defender tampering or script drops that blend with HR automation?"  
5 → 6 🚩: "Defender runtime protections aren't enough — policy-level changes may suggest long-term access planning. Were registry-based settings altered?"  
6 → 7 🚩: "With AV defenses lowered, was credential theft attempted? Is there LSASS access masked as HR config inspection via rundll32?"  
7 → 8 🚩: "A dump was likely created. Did the attacker verify access to this disguised file? Were internal reviews simulated?"  
8 → 9 🚩: "Once internal data is prepared, the next logical step is staging exfil. Is there a beacon or test GET request to verify outbound connectivity?"  
9 → 10 🚩: "With outbound confirmed, sensitive data like PromotionCandidates.csv is Base64 encoded and sent — was this file explicitly targeted for exfiltration?"  
10 → 11 🚩: "Exfil indicates long-term plans. Did they register persistence using legacy HR scripts through autorun registry keys?"  
11 → 12 🚩: "Persistence now enabled. Are there signs the attacker is repeatedly accessing specific HR performance artifacts (e.g., Carlos.Tanaka-Evaluation)?"  
12 → 13 🚩: "The focus shifts to staging broader impact. Is PromotionCandidates.csv manipulated or tied to suspicious filtering?"  
13 → 14 🚩: "With key content handled, anti-forensics takes priority. Is there bulk clearing of event logs to disrupt system audits?"  
14 → 15 🚩: "Indicators show advanced cleanup — PS history deletion, dummy Sysmon config drops, and HR registry trace removal all suggest attacker prepping to vanish."  


