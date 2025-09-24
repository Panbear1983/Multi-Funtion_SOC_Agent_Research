# 🛡️ Threat Hunt Scenario #3 — *Hide Your RDP: Password Spray Leads to Full Compromise*
<img width="1536" height="1024" alt="adninistrator -P pass tat rop20A1123" src="https://github.com/user-attachments/assets/759ad1f8-eb9e-45aa-b0fd-e4d8434d7675" />

**Wingmen:** Gregory Sewalt, Mohammed A

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
- **Incident Date:** **2025-09-14**
- **In-Scope Hosts:** Windows cloud VM(s) where `DeviceName` contains **"flare"**
- **Tooling Used:** Microsoft Sentinel • Microsoft Defender for Endpoint (MDE) • Advanced Hunting (KQL)

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview
A password spray against an internet-exposed RDP endpoint led to a successful logon from a public IP. Post-authentication, the intruder executed a masqueraded binary, established persistence via a **Scheduled Task**, weakened **Microsoft Defender** by adding a folder exclusion, ran host discovery, locally archived data, and communicated with external infrastructure before attempting exfiltration over HTTP to a nonstandard port.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis

| Feature | Details |
|---|---|
| **Adversary** | External actor leveraging password spraying and hands-on-keyboard Windows tradecraft. Comfortable with PowerShell and Windows tasking. |
| **Infrastructure** | Initial access from **159.26.106.84** (RDP). C2 / delivery over HTTP to **185.92.220.87:8081**. Uses web protocols and common public directories. |
| **Capability** | Masqueraded binary (**msupdate.exe**), PowerShell with `-ExecutionPolicy Bypass`, persistence via **Scheduled Task** (**MicrosoftUpdateSync**), Defender exclusion of **`C:\Windows\Temp`**, discovery with `systeminfo`, local staging to **backup_sync.zip**, exfil over HTTP. |
| **Victim** | Windows server(s) labeled with **"flare"** (e.g., `slflarewinsysmo`). Compromised account: **slflare**. RDP exposed to the internet. |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Initial Access | 1 | Credential Access → Initial Access | **T1110.001** | Brute Force: Password Guessing |
| Initial Access | 2 | Initial Access | **T1078** | Valid Accounts |
| Execution | 3 | Execution | **T1059.003** | Command & Scripting Interpreter: Windows Command Shell |
| Execution | 4 | Execution | **T1059** | Command & Scripting Interpreter |
| Persistence | 5 | Persistence | **T1053.005** | Scheduled Task/Job: Scheduled Task |
| Defense Evasion | 6 | Defense Evasion | **T1562.001** | Impair Defenses: Disable/Modify Security Tools |
| Discovery | 7 | Discovery | **T1082** | System Information Discovery |
| Collection | 8 | Collection | **T1560.001** | Archive Collected Data: Local Archiving |
| Command & Control | 9 | C2 | **T1071.001**, **T1105** | Web Protocols; Ingress Tool Transfer |
| Exfiltration | 10 | Exfiltration | **T1048.003** | Exfiltration Over Unencrypted Protocol |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
1. **RDP Exposure & Auth**
   - Restrict RDP to VPN/Privileged Access Workstation; apply just-in-time access.
   - Enforce MFA; tighten lockout thresholds; audit failed logons for spray patterns.
2. **Defender Hardening**
   - Remove unauthorized exclusions; enable Tamper Protection; baseline and alert on Defender policy changes.
3. **Persistence Cleanup**
   - Audit **Task Scheduler** (`TaskCache\Tree`) for rogue tasks (e.g., *MicrosoftUpdateSync*); remove and block re-creation.
4. **PowerShell Controls**
   - Enforce Constrained Language Mode; enable Script Block/Module logging; collect centrally.
5. **Egress & C2 Controls**
   - Block outbound HTTP to unapproved IPs/ports (e.g., **185.92.220.87:8081**); implement DNS/HTTP egress filtering with DLP/CASB.
6. **Credential Hygiene**
   - Reset credentials for **slflare** and related admins; rotate secrets; review lateral movement artifacts.
7. **Detection Engineering**
   - Detections for `ExecutionPolicy Bypass`, creation of archives in **Temp/Public**, and Scheduled Task creation by non-admin contexts.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
- Internet-exposed RDP without MFA remains a high-risk vector for password spraying.
- Masqueraded binaries and public directories effectively blend with legitimate activity—naming controls and AMSI/EDR telemetry are essential.
- Defender exclusions create durable blind spots; monitor and gate all changes to AV policies.
- Task Scheduler remains a reliable persistence vector; registry-backed telemetry (`TaskCache\Tree`) is invaluable for detection.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion
The investigation reconstructs a complete intrusion chain: password spray → valid RDP logon → execution and policy bypass → scheduled task persistence → Defender evasion → discovery → staging to archive → C2 contact → exfiltration attempt. The derived IOCs and behaviors support immediate containment, eradication of persistence, and follow-on detection engineering to reduce time-to-detect for similar tradecraft.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)**          | **Event**                                   | **Target Device**      | **Details**                              |
|------------------------------|---------------------------------------------|------------------------|-------------------------------------------|
| **2025-09-17 ~**             | Earliest RDP password spray attempt         | flare host             | External IP 159.26.106.84 (Flag 1)        |
| **2025-09-17 ~**             | First successful RDP login                  | flare host             | Compromised account: slflare (Flag 2)     |
| **2025-09-17 ~**             | Suspicious binary executed post-login       | flare host             | msupdate.exe (Flag 3)                     |
| **2025-09-17 ~**             | Payload executed with bypass policy         | flare host             | "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1 (Flag 4) |
| **2025-09-17 ~**             | Scheduled Task persistence created          | flare host             | Task: MicrosoftUpdateSync (Flag 5)        |
| **2025-09-17 ~**             | Defender exclusion added                    | flare host             | C:\Windows\Temp (Flag 6)                  |
| **2025-09-17 ~**             | Discovery command run                       | flare host             | "cmd.exe" /c systeminfo (Flag 7)          |
| **2025-09-17 ~**             | Archive file created for staging            | flare host             | backup_sync.zip (Flag 8)                  |
| **2025-09-17 ~**             | C2 connection made                          | flare host             | 185.92.220.87 (Flag 9)                    |
| **2025-09-17 ~**             | Exfiltration attempt to IP:Port             | flare host             | 185.92.220.87:8081 (Flag 10)              |


<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag   | Objective                                   | Value                                           |
|--------|---------------------------------------------|--------------------------------------------------|
| **1**  | Attacker IP Address                         | 159.26.106.84                                    |
| **2**  | Compromised Account                         | slflare                                          |
| **3**  | Executed Binary Name                        | msupdate.exe                                     |
| **4**  | Command Line Used to Execute the Binary     | "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1 |
| **5**  | Persistence Mechanism (Scheduled Task)      | MicrosoftUpdateSync                               |
| **6**  | Defender Setting Modified (Exclusion Path)  | C:\Windows\Temp                                   |
| **7**  | Discovery Command Run                       | "cmd.exe" /c systeminfo                           |
| **8**  | Archive File Created                        | backup_sync.zip                                   |
| **9**  | C2 Connection Destination                   | 185.92.220.87                                     |
| **10** | Exfiltration Attempt Destination (IP:Port)  | 185.92.220.87:8081                                |



### 🏁 Stage 1: Initial Access — *The Threat Actor is trying to get into your network.*

### Flag 1: Attacker IP Address
**Objective:** Identify the earliest external IP that successfully logged in via RDP after multiple failures.  
**What to Hunt:** First `ActionType == "LogonSuccess"` from a Public `RemoteIP` on “flare” hosts.  
**TTP:** T1110.001 (Password Guessing) → T1078 (Valid Accounts).  
**Why It Matters:** Anchors initial access and the source of compromise.

**KQL Query:**

***// Earliest public IP with RDP LogonSuccess on flare hosts***
```kql
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceLogonEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonType
| sort by Timestamp asc
```
**Output:** `159.26.106.84`  
**Finding:** The earliest `LogonSuccess` from a public source was **159.26.106.84**, consistent with password‑spray attempts preceding a successful login.
<img width="1237" height="405" alt="Pasted Graphic 5" src="https://github.com/user-attachments/assets/65d71a9d-27d3-414d-9104-c0027b54ce82" />

---

### Flag 2: Compromised Account
**Objective:** Determine the username used during the successful RDP login.  
**What to Hunt:** Account tied to Flag 1’s `LogonSuccess` event.  
**TTP:** T1078 (Valid Accounts).  
**Why It Matters:** Establishes attacker’s operating identity and permission scope.

**KQL Query:**
***// First successful RDP login’s account on flare hosts***
```kql
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceLogonEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonType
| sort by Timestamp asc
```
**Output:** `slflare`  
**Finding:** The first successful RDP authentication from an external IP used the account **slflare**.
<img width="1178" height="284" alt="Pasted Graphic 4" src="https://github.com/user-attachments/assets/37e01d26-6c6b-48ce-8228-21df181ce367" />

---

### Flag 3: Executed Binary Name
**Objective:** Identify the binary executed post‑RDP access.  
**What to Hunt:** Suspicious executions by **slflare** from `Public/Temp/Downloads` locations or with download/bypass flags.  
**TTP:** T1059.003 (Cmd) / T1204.002 (Malicious File).  
**Why It Matters:** Reveals the initial payload/tooling executed by the adversary.

**KQL Query:**
***// Suspicious binary launches under slflare***
```kql
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where AccountName contains "slflare"
| where ProcessCommandLine has_any ("Bypass","Invoke-WebRequest","DownloadString","certutil","bitsadmin","powershell","public","Temp","Download")
| sort by Timestamp asc
| project Timestamp, ProcessCommandLine, FileName
```
**Output:** `msupdate.exe`  
**Finding:** Under **slflare**, the process list shows execution of **msupdate.exe**, a legit‑sounding name commonly used to masquerade malicious payloads.
<img width="1208" height="361" alt="Pasted Graphic 7" src="https://github.com/user-attachments/assets/9615dadd-eeca-4627-93ec-701983234144" />

---

### Flag 4: Command Line Used to Execute the Binary
**Objective:** Provide the full command line used to launch the binary from Flag 3.  
**What to Hunt:** `ProcessCommandLine` containing **msupdate.exe**.  
**TTP:** T1059 (Command and Scripting Interpreter).  
**Why It Matters:** Parameters expose execution policy bypass and payload pathing.

**KQL Query:**
***// Full command line for msupdate.exe***
```kql
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where AccountName contains "slflare"
| where ProcessCommandLine contains "msupdate.exe"
| project ProcessCommandLine
```
**Output:** `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`  
**Finding:** The binary was invoked with **ExecutionPolicy Bypass**, executing `C:\Users\Public\update_check.ps1`, indicating script‑based follow‑on activity.  
<img width="608" height="90" alt="› msupdate exe -ExecutionPolicy Bypass -File C UsersPublicupdate_check ps1" src="https://github.com/user-attachments/assets/c97fced0-d8f1-4388-a3d1-5edf31edce13" />

---

### Flag 5: Persistence Mechanism Created
**Objective:** Identify the scheduled task created by the attacker.  
**What to Hunt:** Task creation breadcrumbs (e.g., `TaskCache\Tree\*`) and recent entries tied to attacker activity window.  
**TTP:** T1053.005 (Scheduled Task).  
**Why It Matters:** Confirms persistence method that survives reboots/logoff.

**KQL Query:**
***// Suspicious TaskCache registry entries***
```kql
let StartTime = datetime(2025-09-16T18:40:57.3785102Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "slflarewinsysmo"
| where isnotempty(RegistryKey) and RegistryKey contains "TaskCache\\Tree"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
| order by Timestamp asc
```
**Output:** `MicrosoftUpdateSync`  
**Finding:** New entry under **TaskCache\Tree** reveals a scheduled task named **MicrosoftUpdateSync**, consistent with persistence created minutes after initial access.
<img width="1272" height="317" alt="•  Sep 17,2605 24644 AM" src="https://github.com/user-attachments/assets/61f240a3-0988-4045-87ab-54befe1a6a42" />

---

### Flag 6: What Defender Setting Was Modified?
**Objective:** Identify the folder path added to Defender exclusions.  
**What to Hunt:** Defender exclusion registry updates (Exclusions\Paths).  
**TTP:** T1562.001 (Impair Defenses: Disable/Modify Defender).  
**Why It Matters:** Exclusions enable on‑disk payloads to evade scanning.

**KQL Query:**
***// Defender exclusion registry modifications***
```kql
let StartTime = datetime(2025-09-16T19:39:45.4135161Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceRegistryEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "slflarewinsysmo"
| where RegistryKey contains "Windows Defender" and (isnotempty(RegistryValueName) or isnotempty(RegistryValueData))
| project Timestamp, RegistryValueName, RegistryValueData, RegistryKey
| order by Timestamp asc
```
**Output:** `C:\Windows\Temp`  
**Finding:** A Defender exclusion was added for **C:\Windows\Temp**, a common staging folder for transient payloads and archives.
<img width="1103" height="349" alt="Sep 1R 2075 8 16" src="https://github.com/user-attachments/assets/0f804391-7ce2-4a01-a351-b2843db7aeb5" />

---

### Flag 7: What Discovery Command Did the Attacker Run?
**Objective:** Identify earliest system discovery command.  
**What to Hunt:** `whoami` / `systeminfo` invocations following persistence.  
**TTP:** T1082 (System Information Discovery).  
**Why It Matters:** Validates reconnaissance phase and attacker context awareness.

**KQL Query:**
***// Earliest discovery commands***
```kql
let StartTime = datetime(2025-09-16T18:40:57.3785102Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "slflarewinsysmo"
| where ProcessCommandLine contains "systeminfo" or ProcessCommandLine contains "whoami"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```
**Output:** `"cmd.exe" /c systeminfo`  
**Finding:** The attacker initiated host enumeration via **systeminfo** (via `cmd /c`), shortly after establishing persistence.
<img width="658" height="213" alt="Timestamp" src="https://github.com/user-attachments/assets/269da14d-fea0-4599-9be9-7d4885aab5e2" />

---

### Flag 8: Archive File Created by Attacker
**Objective:** Identify the archive created to stage data for exfiltration.  
**What to Hunt:** `.zip` / `.7z` / `.rar` creation or usage from suspicious locations.  
**TTP:** T1560.001 (Local Archiving).  
**Why It Matters:** Confirms data staging prior to outbound transfer.

**KQL Query:**
***// Archive operations observed in process command lines***
```kql
let StartTime = datetime(2025-09-16T18:40:57.3785102Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "slflarewinsysmo"
| where ProcessCommandLine contains ".zip" or ProcessCommandLine contains ".rar" or ProcessCommandLine contains ".7z"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```
**Output:** `backup_sync.zip`  
**Finding:** The actor staged collected data into **backup_sync.zip**, a benign‑sounding archive name typical of masquerading techniques.
<img width="1263" height="197" alt="Pasted Graphic 15" src="https://github.com/user-attachments/assets/fd488f21-6b97-43f6-a646-a46d12c6f36b" />

---

### Flag 9: C2 Connection Destination
**Objective:** Identify the C2 destination contacted for remote access/tooling.  
**What to Hunt:** Outbound HTTP/S calls immediately following staging/persistence.  
**TTP:** T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer).  
**Why It Matters:** Pinpoints external infrastructure used to control the host.

**KQL Query:**
***// Outbound URLs/IPs tied to archive or tooling retrieval***
```kql
let StartTime = datetime(2025-09-16T18:40:57.3785102Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "slflarewinsysmo"
| where ProcessCommandLine contains "http" and ProcessCommandLine contains ".zip"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```
**Output:** `185.92.220.87`  
**Finding:** Process telemetry shows repeated callbacks to **185.92.220.87**, indicating external C2/tooling retrieval.
<img width="1183" height="197" alt="Pasted Graphic 16" src="https://github.com/user-attachments/assets/1cc54796-7b8f-4fb8-8231-9bee5b0c9f8c" />

---

### Flag 10: Exfiltration Attempt Detected
**Objective:** Identify the exfiltration destination and port.  
**What to Hunt:** Outbound connections to external IP:port following archive creation.  
**TTP:** T1048.003 (Exfiltration Over Unencrypted Protocol).  
**Why It Matters:** Confirms data egress attempt and aids containment/IOCs.

**KQL Query:**
***// External exfil destination (IP:Port)***
```kql
let StartTime = datetime(2025-09-16T18:40:57.3785102Z);
let EndTime   = datetime(2025-09-22T23:59:59Z);
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "slflarewinsysmo"
| where ProcessCommandLine contains "http" and ProcessCommandLine contains ".zip"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```
**Output:** `185.92.220.87:8081`  
**Finding:** The staged archive was sent (or attempted) to **185.92.220.87:8081**, aligning with observed C2 infrastructure and unencrypted exfil paths.
<img width="1156" height="192" alt="Pasted Graphic 17" src="https://github.com/user-attachments/assets/626f6b0f-6ad6-4e47-be16-4fb3bf664fbd" />


<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🔎 Analyst Workflow
### From an investigative standpoint, the workflow progressed as follows: ###

**Authentication Review** – Investigated failed logons. Confirmed brute force attempts followed by a successful RDP login from an external IP.

**Process and Execution Check** – Reviewed process tree. Identified suspicious binary executed after login, which then spawned PowerShell scripts for payload execution.

**Persistence and Evasion Review** – Validated changes to Defender settings with folder exclusions. Found a scheduled task created by the attacker to maintain access across reboots.

**Recon and Network Analysis** – Traced attacker commands used for host discovery including system enumeration. Observed outbound network traffic to external command and control infrastructure.

**Exfiltration Review** – Detected creation of a staged data archive. Correlated with outbound traffic showing an exfiltration attempt to external IP and port.

**Great job completing this CTF! 🎉**  
You successfully followed the intrusion chain from brute-force entry to malicious PowerShell execution, persistence creation, and outbound connections leading to staged data prepared for exfiltration.
