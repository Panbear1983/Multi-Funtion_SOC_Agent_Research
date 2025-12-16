# 🖥️ Assistance 💬🧑‍💻
<img width="1536" height="1024" alt="Assistance" src="https://github.com/user-attachments/assets/a1c316b2-55a4-4928-8f39-aa8f83491d6b" />


<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
Date Completed: ***2025-10-09***  
Wingmen (woman) List: **Adetola Kolawole**, Agentic SOC Analyst  
Simulated Environment: `LOG(N) Pacific - Cyber Range 1`  
Infected Host VM DeviceName contains `gab-intern-vm`  
Incident Date: ***2025-10-01 to 2025-10-15***  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***  


<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview
A routine support request should have ended with a reset and reassurance. Instead, the so-called "help" left behind a trail of anomalies that don't add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn't remote assistance. It was a misdirection.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis

| Feature | Details |
|---|---|
| **Adversary** | External actor masquerading as IT support, leveraging PowerShell and Windows LOLBins for reconnaissance and persistence. Comfortable with staged narratives and misdirection. |
| **Infrastructure** | Initial access via suspicious script execution from Downloads folder. Outbound connectivity checks to `www.msftconnecttest.com` and exfiltration attempts to `100.29.147.161` (AWS EC2). |
| **Capability** | PowerShell execution with `-ExecutionPolicy Bypass`, clipboard probing, host context enumeration (`qwinsta.exe`), storage mapping (`wmic logicaldisk`), network validation (`nslookup`), process enumeration (`tasklist.exe`), privilege checks (`whoami`), artifact staging (`ReconArtifacts.zip`), scheduled task persistence (`SupportToolUpdater`), registry Run key persistence (`RemoteAssistUpdater`), and planted narrative artifacts (`SupportChat_log.lnk`). |
| **Victim** | Windows intern machine (`gab-intern-vm`) with compromised account `g4bri3lintern`. Multiple machines in department affected with similar file patterns containing keywords "desk," "help," "support," and "tool." |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Initial Access | Starting Point | Initial Access | **T1204.002** | User Execution: Malicious File |
| Execution | 1 | Execution | **T1059.001** | Command & Scripting Interpreter: PowerShell |
| Defense Evasion | 2 | Defense Evasion | **T1562.001** | Impair Defenses: Disable/Modify Security Tools |
| Collection | 3 | Collection | **T1115** | Clipboard Data |
| Discovery | 4 | Discovery | **T1033** | System Owner/User Discovery |
| Discovery | 5 | Discovery | **T1082** | System Information Discovery |
| Discovery | 6 | Discovery | **T1018** | Remote System Discovery |
| Discovery | 7 | Discovery | **T1033** | System Owner/User Discovery |
| Discovery | 8 | Discovery | **T1057** | Process Discovery |
| Discovery | 9 | Discovery | **T1069.001** | Permission Groups Discovery: Local Groups |
| Command & Control | 10 | Command & Control | **T1071.001** | Web Protocols |
| Collection | 11 | Collection | **T1560.001** | Archive Collected Data: Archive via Utility |
| Exfiltration | 12 | Exfiltration | **T1041** | Exfiltration Over C2 Channel |
| Persistence | 13 | Persistence | **T1053.005** | Scheduled Task/Job: Scheduled Task |
| Persistence | 14 | Persistence | **T1547.001** | Boot/Logon Autostart: Registry Run Keys / Startup Folder |
| Defense Evasion | 15 | Defense Evasion | **T1036.005** | Masquerading: Match Legitimate Name or Location |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
1. **PowerShell Execution Controls**
   - Enforce Constrained Language Mode; enable Script Block and Module logging; alert on `-ExecutionPolicy Bypass` usage.
   - Monitor Downloads folder for script execution; implement application allowlisting.
2. **Defense Evasion Detection**
   - Alert on Defender tamper artifacts (`DefenderTamperArtifact.lnk`); monitor for security tool modifications.
   - Baseline security configurations and alert on unauthorized changes.
3. **Reconnaissance Detection**
   - Create detections for clipboard access, host enumeration (`qwinsta`, `whoami`, `systeminfo`), storage mapping (`wmic logicaldisk`), and process enumeration (`tasklist`).
4. **Persistence Monitoring**
   - Audit Scheduled Tasks for suspicious entries (e.g., `SupportToolUpdater`); monitor registry Run keys for unauthorized modifications.
   - Alert on registry value creation/modification in startup locations.
5. **Network Egress Controls**
   - Block outbound connections to unapproved IPs (e.g., `100.29.147.161`); implement DNS filtering.
   - Monitor for connectivity tests and exfiltration attempts.
6. **Artifact Analysis**
   - Investigate suspicious archive files (`ReconArtifacts.zip`) and planted narrative artifacts (`SupportChat_log.lnk`).
   - Correlate file creation timestamps with process execution chains.
7. **User Awareness**
   - Educate users on identifying suspicious support requests; implement verification procedures for remote assistance.
   - Review and validate all support-related activities.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
- **Misdirection is a Weapon:** Planted narratives and legitimate-sounding artifacts can mask malicious activity in plain sight.
- **Reconnaissance Chain:** Attackers follow predictable patterns: initial access → defense evasion → quick data probes → broader recon → persistence → exfiltration.
- **Persistence Redundancy:** Multiple persistence mechanisms (scheduled tasks + registry Run keys) increase attacker resilience.
- **Timing Tells the Story:** Correlating file creation, process execution, and network activity timestamps reveals the true attack timeline.
- **Support Masquerading:** Legitimate-sounding support tools and chat logs can be used to justify suspicious behavior.
- **Process Chain Analysis:** Following parent/child process relationships reveals the true source of malicious activity.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion
The investigation reconstructs a complete attack chain disguised as remote assistance: suspicious script execution → defense tampering → clipboard probing → host context enumeration → storage mapping → connectivity validation → session discovery → process enumeration → privilege checks → egress validation → artifact staging → exfiltration attempts → scheduled task persistence → registry Run key persistence → planted narrative artifacts. The derived timeline and behaviors support immediate containment, eradication of persistence mechanisms, and detection engineering to prevent similar misdirection attacks.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)**          | **Event**                                   | **Target Device**      | **Details**                              |
|------------------------------|---------------------------------------------|------------------------|-------------------------------------------|
| **2025-10-01 to 2025-10-15** | Multiple machines spawning processes from Downloads | Department machines | Files with keywords "desk," "help," "support," "tool" (Starting Point) |
| **2025-10-01 ~**             | Initial suspicious execution detected       | gab-intern-vm          | PowerShell with `-ExecutionPolicy` parameter (Flag 1) |
| **2025-10-01 ~**             | Defense tamper artifact created             | gab-intern-vm          | `DefenderTamperArtifact.lnk` (Flag 2) |
| **2025-10-01 ~**             | Clipboard data probe                        | gab-intern-vm          | `Get-Clipboard` command (Flag 3) |
| **2025-10-09 12:51:44Z**     | Last host context recon attempt             | gab-intern-vm          | `qwinsta.exe` execution (Flag 4) |
| **2025-10-09 ~**             | Storage surface mapping                     | gab-intern-vm          | `wmic logicaldisk get name,freespace,size` (Flag 5) |
| **2025-10-09 12:51:44Z ~**   | Connectivity check                          | gab-intern-vm          | `nslookup` via RuntimeBroker.exe (Flag 6) |
| **2025-10-09 12:51:32Z ~**   | Interactive session discovery               | gab-intern-vm          | Process ID: 2533274790397065 (Flag 7) |
| **2025-10-09 ~**             | Runtime application inventory               | gab-intern-vm          | `tasklist.exe` (Flag 8) |
| **2025-10-09 12:52:14Z**     | First privilege surface check               | gab-intern-vm          | `whoami` command (Flag 9) |
| **2025-10-09 12:52:14Z ~**   | Proof-of-access & egress validation         | gab-intern-vm          | `www.msftconnecttest.com` (Flag 10) |
| **2025-10-09 12:55:05Z ~**   | Artifact bundling/staging                   | gab-intern-vm          | `C:\Users\Public\ReconArtifacts.zip` (Flag 11) |
| **2025-10-09 12:55:05Z ~**   | Outbound transfer attempt                   | gab-intern-vm          | `100.29.147.161` (Flag 12) |
| **2025-10-09 13:00:40Z ~**   | Scheduled re-execution persistence          | gab-intern-vm          | Task: `SupportToolUpdater` (Flag 13) |
| **2025-10-09 13:00:40Z ~**   | Autorun fallback persistence                | gab-intern-vm          | Registry value: `RemoteAssistUpdater` (Flag 14) |
| **2025-10-09 13:00:40Z ~**   | Planted narrative artifact                  | gab-intern-vm          | `SupportChat_log.lnk` (Flag 15) |


<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag   | Objective                                   | Value                                           |
|--------|---------------------------------------------|--------------------------------------------------|
| **Starting Point**  | Most suspicious machine identification                         | gab-intern-vm                                    |
| **1**  | First CLI parameter name used during execution                         | -ExecutionPolicy                                          |
| **2**  | File name related to defense disabling exploit                        | DefenderTamperArtifact.lnk                                     |
| **3**  | Command value tied to clipboard probe exploit     | "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard \| Out-Null } catch { }" |
| **4**  | Timestamp of last recon attempt      | 2025-10-09T12:51:44.3425653Z                               |
| **5**  | 2nd command tied to storage assessment activity  | "cmd.exe" /c wmic logicaldisk get name,freespace,size                                   |
| **6**  | File name of initiating parent process                       | RuntimeBroker.exe                                   |
| **7**  | Unique ID of initiating process                   | 2533274790397065                                     |
| **8**  | File name demonstrating runtime process enumeration                        | tasklist.exe                                   |
| **9**  | Timestamp of first privilege check attempt                        | 2025-10-09T12:52:14.3135459Z                                   |
| **10** | First outbound destination contacted                        | www.msftconnecttest.com                                     |
| **11** | Full folder path where artifact was first dropped                        | C:\Users\Public\ReconArtifacts.zip                                   |
| **12** | IP of last unusual outbound connection                        | 100.29.147.161                                     |
| **13** | Scheduled task name                        | SupportToolUpdater                                   |
| **14** | Registry value name                        | RemoteAssistUpdater                                   |
| **15** | File name of planted narrative artifact                        | SupportChat_log.lnk                                   |


### 🏁 Starting Point: Initial Machine Identification

**Objective:** Identify the most suspicious machine based on the given conditions:
1. Multiple machines in the department started spawning processes originating from the download folders during the first half of October.
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included "desk," "help," "support," and "tool."
4. Intern operated machines seem to be affected to certain degree.

**What to Hunt:** Machine name containing "inter" with file events matching the keywords in Downloads folder.

**KQL Query:**

***// Looking for suspicious DeviceName***
```kql
let StartTime = datetime(2025-10-01T00:00:00Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceFileEvents
| where TimeGenerated between (StartTime .. EndTime)
| where FileName contains 'help'
| where DeviceName contains 'inter'
| where FolderPath contains 'download'
| project TimeGenerated, DeviceName, FolderPath, FileName
| summarize FileEvents=count() by DeviceName
| order by FileEvents desc 
```
**Output:** `gab-intern-vm`  
**Finding:** The additional puzzle piece lied in the 'intern' for the machine 'DeviceName' field. We are able to see the first device name that popped up with the name containing the word 'intern'.

---

### 🚩 Flag 1 - Initial Execution Detection

**Objective:** Detect the earliest anomalous execution that could represent an entry point.

**What to Hunt:** Look for atypical script or interactive command activity that deviates from normal user behavior or baseline patterns.

**Thought:** Pinpointing the first unusual execution helps you anchor the timeline and follow the actor's parent/child process chain.

**Hint:** 
1. Downloads
2. Two

**KQL Query:**

***// The key word indicates the hacker's execution command in the CLI***
```kql
let StartTime = datetime(2025-10-01T00:00:00Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| project TimeGenerated, AccountName, FolderPath, FileName, ProcessCommandLine
| order by TimeGenerated asc
| take 10
```
**Output:** `-ExecutionPolicy`  
**Finding:** So the riddle of this flag lies in the understanding of the framing of the question asked. We are looking for the action of the 'parameter' used in the CLI that hacker takes to bypass the security measure using 'powershell.exe'.

---

### 🚩 Flag 2 – Defense Disabling

**Objective:** Identify indicators that suggest attempts to imply or simulate changing security posture.

**What to Hunt:** Search for artifact creation or short-lived process activity that contains tamper-related content or hints, without assuming an actual configuration change occurred.

**Thought:** A planted or staged tamper indicator is a signal of intent — treat it as intent, not proof of actual mitigation changes.

**Hint:**
1. File was manually accessed

**KQL Query:**

***// Looking for file name that is the keyword 'Tamper'***
```kql
let StartTime = datetime(2025-10-01T00:00:00Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceFileEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where FileName contains 'tamper'
| project TimeGenerated, FolderPath, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `DefenderTamperArtifact.lnk`  
**Finding:** After trying a couple keywords in the flag intel, "tamper" and "artifact" turns out the crucial telltale sign within the File Name field under the "DeviceFileEvents" log.

---

### 🚩 Flag 3 – Quick Data Probe

**Objective:** Spot brief, opportunistic checks for readily available sensitive content.

**What to Hunt:** Find short-lived actions that attempt to read transient data sources common on endpoints.

**Thought:** Attackers look for low-effort wins first; these quick probes often precede broader reconnaissance.

**Hint:** 
1. Clip

**Side Note:** 1/2

**KQL Query:**

```kql
let StartTime = datetime(2025-10-01T00:00:00Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where ProcessCommandLine contains "clip"
| where FileName in ("powershell.exe","cmd.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
**Output:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`  
**Finding:** At this stage of the infiltration, the hacker utilize LOL resource of the hint "clip" as keyword within the "InitiatingProcessCommandLine" to piggyback the sensitive resource to probe possible vulnerabilities for further lateral movement.

---

### 🚩 Flag 4 – Host Context Recon

**Objective:** Find activity that gathers basic host and user context to inform follow-up actions.

**What to Hunt:** Telemetry that shows the actor collecting environment or account details without modifying them.

**Thought:** Context-gathering shapes attacker decisions — who, what, and where to target next.

**Hint:**
1. qwi

**KQL Query:**

```kql
let StartTime = datetime(2025-10-01T00:00:00Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where FileName contains "qwi"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
**Output:** `2025-10-09T12:51:44.3425653Z`  
**Finding:** The goal of this flag is to identify the last time stamp of when hacker attempts to gather environment or user information on a host system, without making changes to the system. The intel gives out obvious hint "qwi" within the "FileName" or "ProcessCommandLine" fields. And the result addresses the earlier time stamp from one of the 2 entries.

---

### 🚩 Flag 5 – Storage Surface Mapping

**Objective:** Detect discovery of local or network storage locations that might hold interesting data.

**What to Hunt:** Look for enumeration of filesystem or share surfaces and lightweight checks of available storage.

**Thought:** Mapping where data lives is a preparatory step for collection and staging.

**Hint:**
1. Storage assessment

**KQL Query:**

```kql
let StartTime = datetime(2025-10-01T00:00:00Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where ProcessCommandLine contains "logical"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`  
**Finding:** The "storage assessment" hint directly correlates with this finding, as the command explicitly retrieves disk metadata (drive letters, free space, size) to map storage surfaces. This is critical for adversaries planning data exfiltration or persistence, aligning perfectly with the flag question's context.

---

### 🚩 Flag 6 – Connectivity & Name Resolution Check

**Objective:** Identify checks that validate network reachability and name resolution.

**What to Hunt:** Network or process events indicating DNS or interface queries and simple outward connectivity probes.

**Thought:** Confirming egress is a necessary precondition before any attempt to move data off-host.

**Side Note:** 2/2

**Hint:**
1. session

**KQL Query:**

```kql
let StartTime = datetime(2025-10-01T12:51:44.3425653Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where ProcessCommandLine contains 'nslookup'
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessCommandLine
| order by TimeGenerated desc
```
**Output:** `RuntimeBroker.exe`  
**Finding:** `RuntimeBroker.exe` is a legitimate system process in Windows, specifically associated with the Windows Runtime (WinRT) and Universal Windows Platform (UWP) applications. The attacker access "nslookup" to ping to the external networks to test out its connectivity. And we look for 'InitiatingProcessParentFileName' field to see triggering file for the ping command.

---

### 🚩 Flag 7 – Interactive Session Discovery

**Objective:** Reveal attempts to detect interactive or active user sessions on the host.

**What to Hunt:** Signals that enumerate current session state or logged-in sessions without initiating a takeover.

**Thought:** Knowing which sessions are active helps an actor decide whether to act immediately or wait.

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T12:51:32.6223466Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where ProcessCommandLine has_any ("net user", "group", "whoami", "systeminfo", "wmic", "logon", "login", "login", "eventvwr", "taskmgr", "rundll32", "cmd.exe")
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessUniqueId, InitiatingProcessUniqueId, ProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `2533274790397065`  
**Finding:** The enumerations are consistently spawned by the same PowerShell process, evidenced by the stable InitiatingProcessUniqueId (2533274790397065). The 'cmd.exe' popping up numerous times but no obfuscation or encoding is present in these commands; they are plain cmd invocations via PowerShell.

---

### 🚩 Flag 8 – Runtime Application Inventory

**Objective:** Detect enumeration of running applications and services to inform risk and opportunity.

**What to Hunt:** Events that capture broad process/process-list snapshots or queries of running services.

**Thought:** A process inventory shows what's present and what to avoid or target for collection.

**Hint:** 
1. Task
2. List
3. Last

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T12:51:32.6223466Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where ProcessCommandLine has_any ("net user", "group", "whoami", "systeminfo", "wmic", "logon", "login", "login", "eventvwr", "taskmgr", "rundll32", "cmd.exe", "List", "last","task")
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `tasklist.exe`  
**Finding:** The file name `tasklist.exe` demonstrates a runtime process enumeration event, as it lists all running processes on the target host, providing the attacker with visibility into active applications and services.

---

### 🚩 Flag 9 – Privilege Surface Check

**Objective:** Detect attempts to understand privileges available to the current actor.

**What to Hunt:** Telemetry that reflects queries of group membership, token properties, or privilege listings.

**Thought:** Privilege mapping informs whether the actor proceeds as a user or seeks elevation.

**Hint:** 
1. Who

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T12:51:32.6223466Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where ProcessCommandLine contains 'who'
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `2025-10-09T12:52:14.3135459Z`  
**Finding:** The earliest timestamp in the filtered logs corresponds to the first execution of a privilege-checking command (`whoami /groups`), and no obfuscation or hidden data is present at that stage. Grabbing the first time stamp of the outputted log aligns with the hint "who /think" (likely referencing `whoami` commands). No obfuscation or encoding is present in the command lines, and the timestamps are unambiguous.

---

### 🚩 Flag 10 – Proof-of-Access & Egress Validation

**Objective:** Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**What to Hunt:** Look for combined evidence of outbound network checks and artifacts created as proof the actor can view or collect host data.

**Thought:** This step demonstrates both access and the potential to move meaningful data off the host...

**Side Note:** 1/3

**Hint:**
1. support

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T12:52:14.3135459Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceNetworkEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where RemoteUrl != "" and RemoteUrl contains "www"
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, InitiatingProcessFileName
```
**Output:** `www.msftconnecttest.com`  
**Finding:** PowerShell (InitiatingProcessFileName = powershell.exe, account = g4bri3lintern) performed an outbound HTTP GET to www.msftconnecttest.com (RemoteIP 23.218.218.182, URI = /connecttest.txt) to validate outbound reachability. In the same session/timeframe (see previous Flag 8), tasklist.exe was executed to capture host process state for exfiltration value.

---

### 🚩 Flag 11 – Bundling / Staging Artifacts

**Objective:** Detect consolidation of artifacts into a single location or package for transfer.

**What to Hunt:** File system events or operations that show grouping, consolidation, or packaging of gathered items.

**Thought:** Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

**Hint:** 
1. Include the file value

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T12:55:05.7658713Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceFileEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `C:\Users\Public\ReconArtifacts.zip`  
**Finding:** We are focusing on the indication of possible artifacts that involves in staging steps to exfiltration of the first folder used to drop in the executable files. And the file name 'ReconArtifacts.zip' is discovered in the 'DeviceFileEvents' log under the 'C:\Users\Public\' directory, which marks the first location hacker used to gather the exfiltration file onto the victim's system.

---

### 🚩 Flag 12 – Outbound Transfer Attempt (Simulated)

**Objective:** Identify attempts to move data off-host or test upload capability.

**What to Hunt:** Network events or process activity indicating outbound transfers or upload attempts, even if they fail.

**Thought:** Succeeded or not, attempt is still proof of intent — and it reveals egress paths or block points.

**Side Note:** 2/3

**Hint:**
1. chat

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T12:55:05.7658713Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceNetworkEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where RemoteIPType != ''
| project TimeGenerated, ActionType, RemoteIP, RemoteIPType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**Output:** `100.29.147.161`  
**Finding:** 'powershell.exe' is a classic tool used both for legitimate admin and attacker (LOLBIN) tasks—commonly in data exfiltration, C2, or upload tests.  '100.29.147.161' is not a Microsoft/Akamai/Cloud-native IP (usually 13.x, 52.x, 23.x, etc.), but an Amazon AWS EC2/Lightsail IP (ASN: Amazon, US). Attackers often spin up ephemeral cloud IPs for receiving exfiltrated data or as drop-points for upload tests. The scenario expects us to ignore "expected noisy" uploaders (like wermgr.exe, which could be triggering a real or simulated fake upload).

---

### 🚩 Flag 13 – Scheduled Re-Execution Persistence

**Objective:** Detect creation of mechanisms that ensure the actor's tooling runs again on reuse or sign-in.

**What to Hunt:** Process or scheduler-related events that create recurring or logon-triggered executions tied to the same actor pattern.

**Thought:** Re-execution mechanisms are the actor's way of surviving beyond a single session — interrupting them reduces risk.

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T13:00:40.045127Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where AccountName == 'g4bri3lintern'
| where FileName contains 'schtasks' or FileName contains 'powershell'
| project TimeGenerated, ProcessCommandLine, ActionType, FileName, FolderPath, AdditionalFields
| order by TimeGenerated asc
```
**Output:** `SupportToolUpdater`  
**Finding:** Due to the logon‑triggered scheduled task the attacker created via 'schtasks.exe' to silently re‑run the malicious 'SupportTool.ps1' script on every user sign‑in, making it the specific re‑execution persistence mechanism in order to persist beyond that single execution with the name 'SupportToolUpdater'.

---

### 🚩 Flag 14 – Autorun Fallback Persistence

**Objective:** Spot lightweight autorun entries placed as backup persistence in user scope.

**What to Hunt:** Registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**Thought:** Redundant persistence increases resilience; find the fallback to prevent easy re-entry.

**Side Note:** 3/3

**Hint:**
1. log

**⚠️ If table returned nothing: RemoteAssistUpdater**

**DM the CTF admin should you wish to see how it would normally look like**

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T13:00:40.045127Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceRegistryEvents
| where TimeGenerated between (StartTime .. EndTime)
| where InitiatingProcessFileName contains 'update'
| where ActionType == 'RegistryValueSet'
| order by TimeGenerated asc
```
**Output:** `RemoteAssistUpdater`  
**Finding:** The answer is 'RemoteAssistUpdater' because the CTF question is asking for the registry value name, which in the DeviceRegistryEvents table is stored in the RegistryValueName field. In the simulated event the author used, that field's value is RemoteAssistUpdater, so by definition that is the correct flag when identifying the right registry event row.

---

### 🚩 Flag 15 – Planted Narrative / Cover Artifact

**Objective:** Identify a narrative or explanatory artifact intended to justify the activity.

**What to Hunt:** Creation of explanatory files or user-facing artifacts near the time of suspicious operations; focus on timing and correlation rather than contents.

**Thought:** A planted explanation is a classic misdirection. The sequence and context reveal deception more than the text itself.

**Hint:**
1. The actor opened it for some reason

**KQL Query:**

```kql
let StartTime = datetime(2025-10-09T13:00:40.045127Z);
let EndTime = datetime(2025-10-15T23:59:59Z);
DeviceFileEvents
| where TimeGenerated between (StartTime .. EndTime)
| where DeviceName contains 'gab-intern-vm'
| where InitiatingProcessAccountName == 'g4bri3lintern'
| project TimeGenerated, InitiatingProcessCommandLine, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
**Output:** `SupportChat_log.lnk`  
**Finding:** SupportChat_log.lnk is the answer because it is the malicious shortcut file the attacker placed and that the user executed, making it the key artifact indicating compromise, and .lnk is the Windows shortcut extension, which stores a link that launches another program, while .txt is a plain text file extension that stores human‑readable text and does not execute code when opened. The '.lnk' shortcut (SupportChat_log.lnk) was created immediately before the text log was created and opened by the same user account, and support-related PowerShell activity followed. The timing, process chain (explorer.exe → notepad.exe → powershell.exe), and plain-text command lines strongly indicate SupportChat_log.lnk is the narrative/explanatory artifact intended to justify the activity.



<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🔎 Analyst Workflow

### From an investigative standpoint, the workflow progressed as follows:

**0 ➝ 1 🚩:** An unfamiliar script surfaced in the user's Downloads directory. Was this SupportTool.ps1 executed under the guise of IT diagnostics?

**1 ➝ 2 🚩:** Initial execution often precedes an attempt to weaken defenses. Did the operator attempt to tamper with security tools to reduce visibility?

**2 ➝ 3 🚩:** With protections probed, the next step is quick data checks. Did they sample clipboard contents to see if sensitive material was immediately available?

**3 ➝ 4 🚩:** Attackers rarely stop with clipboard data. Did they expand into broader environmental reconnaissance to understand the host and user context?

**4 ➝ 5 🚩:** Recon of the system itself is followed by scoping available storage. Did the attacker enumerate drives and shares to see where data might live?

**5 ➝ 6 🚩:** After scoping storage, connectivity is key. Did they query network posture or DNS resolution to validate outbound capability?

**6 ➝ 7 🚩:** Once network posture is confirmed, live session data becomes valuable. Did they check active users or sessions that could be hijacked or monitored?

**7 ➝ 8 🚩:** Session checks alone aren't enough — attackers want a full picture of the runtime. Did they enumerate processes to understand active applications and defenses?

**8 ➝ 9 🚩:** Process context often leads to privilege mapping. Did the operator query group memberships and privileges to understand access boundaries?

**9 ➝ 10 🚩:** With host and identity context in hand, attackers often validate egress and capture evidence. Was there an outbound connectivity check coupled with a screenshot of the user's desktop?

**10 ➝ 11 🚩:** After recon and evidence collection, staging comes next. Did the operator bundle key artifacts into a compressed archive for easy movement?

**11 ➝ 12 🚩:** Staging rarely stops locally — exfiltration is tested soon after. Were outbound HTTP requests attempted to simulate upload of the bundle?

**12 ➝ 13 🚩:** Exfil attempts imply intent to return. Did the operator establish persistence through scheduled tasks to ensure continued execution?

**13 ➝ 14 🚩:** Attackers rarely trust a single persistence channel. Was a registry-based Run key added as a fallback mechanism to re-trigger the script?

**14 ➝ 15 🚩:** Persistence secured, the final step is narrative control. Did the attacker drop a text log resembling a helpdesk chat to possibly justify these suspicious activities?
