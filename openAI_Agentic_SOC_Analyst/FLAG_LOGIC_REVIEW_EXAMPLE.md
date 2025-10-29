# 📝 Flag Logic Review Stage - Terminal Example

## When This Stage Appears

After **Completion Stage** (all flags captured) or **Exit** (partial completion), you'll see:

---

## Terminal Experience

```bash
══════════════════════════════════════════════════════════════════════
🎊 CONGRATULATIONS! INVESTIGATION COMPLETE!
══════════════════════════════════════════════════════════════════════

[... completion summary shown ...]

══════════════════════════════════════════════════════════════════════
📝 FLAG LOGIC REVIEW (Optional)
══════════════════════════════════════════════════════════════════════

Would you like to add detailed investigation notes for each flag?
This is useful for:
  • Documentation and write-ups
  • Detailed reasoning beyond automated capture
  • Sharing investigation methodology
  • Future reference and learning

Add flag investigation notes? [y/N]: y

══════════════════════════════════════════════════════════════════════
FLAG INVESTIGATION NOTES CAPTURE
══════════════════════════════════════════════════════════════════════

You can add detailed notes for each flag.
Enter notes in your preferred format (paste your writeup).
Type 'DONE' on a new line when finished with each flag.

──────────────────────────────────────────────────────────────────────
Flag 1: Attacker IP Address
Current answer: 159.26.106.84
──────────────────────────────────────────────────────────────────────

Add detailed notes for Flag 1? [y/N]: y

Paste your investigation notes for Flag 1:
(Include: scenario, objective, KQL, output, findings, etc.)
Type 'DONE' on new line when finished

🚩 Flag 1: Attacker IP Address

MITRE Technique: 🔸 T1110.001 – Brute Force: Password Guessing

Scenario Context:
Suspicious RDP login activity has been detected on a cloud-hosted Windows server. 
Multiple failed attempts were followed by a successful login, suggesting brute-force 
or password spraying behavior.

Objective:
Identify the external IP address that successfully logged in via RDP after a series 
of failures.

Guidance:
Review the authentication telemetry and look for signs of repeated failed logins 
followed by a successful one. Focus on logins that originated from external IP addresses.

Flag Format:
xxx.xxx.xxx.xxx

KQL Query Used:
```kql
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime = datetime(2025-09-22T23:59:59Z);
DeviceLogonEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonType
| sort by Timestamp asc
```

Output:
159.26.106.84

Finding:
The tricky part of the opening premise states the event took place on the date of 
14th of Sept. So the KQL time frame sets as far back as the 13th. We filter the 
`DeviceName` contains `flare` while look for the first `LogonSuccess` under 
`ActionType` under the earliest `RemoteIP`
DONE

✓ Notes captured for Flag 1

──────────────────────────────────────────────────────────────────────
Flag 2: Compromised Account
Current answer: slflare
──────────────────────────────────────────────────────────────────────

Add detailed notes for Flag 2? [y/N]: y

Paste your investigation notes for Flag 2:
(Include: scenario, objective, KQL, output, findings, etc.)
Type 'DONE' on new line when finished

🚩 Flag 2: Compromised Account

MITRE Technique: 🔸 T1078 – Valid Accounts

Scenario Context:
The attacker gained access to the system using valid credentials through RDP. 
Identifying which account was accessed is critical to understanding what level 
of control they have.

Objective:
Determine the username that was used during the successful RDP login associated 
with the attacker's IP.

Guidance:
Pivot from the successful login identified in Flag 1. Analyze the associated 
account used in that authentication event.

Flag Format:
username

KQL:
let StartTime = datetime(2025-09-13T00:00:00Z);
let EndTime = datetime(2025-09-22T23:59:59Z);
DeviceLogonEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceName contains "flare"
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonType
| sort by Timestamp asc

Output:
slflare

Finding:
Trailing from the first flag for all the `ActionType` status. We are looking 
for the `AccountName` based on the `LogonSuccess` and `slflare` is our first culprit.
DONE

✓ Notes captured for Flag 2

──────────────────────────────────────────────────────────────────────
Flag 3: Executed Binary Name
Current answer: msupdate.exe
──────────────────────────────────────────────────────────────────────

Add detailed notes for Flag 3? [y/N]: n

[Uses automated capture notes]

[... continues for all flags ...]

══════════════════════════════════════════════════════════════════════
✓ Flag investigation logic saved!
══════════════════════════════════════════════════════════════════════

Saved to: ctf_sessions/flag_investigation_logic.json

This file contains your detailed investigation methodology
and can be used for writeups, reports, or future reference.

══════════════════════════════════════════════════════════════════════
SESSION COMPLETE
══════════════════════════════════════════════════════════════════════
All findings have been logged to _threats.jsonl
══════════════════════════════════════════════════════════════════════
```

---

## 📄 Generated File: `flag_investigation_logic.json`

```json
{
  "scenario": "RDP Password Spray - Full Compromise",
  "session_id": "rdp_password_spray_20251010_153000",
  "completed_at": "2025-10-10T17:45:22",
  "flags_logic": [
    {
      "flag_number": 1,
      "title": "Attacker IP Address",
      "answer": "159.26.106.84",
      "stage": "Initial Access",
      "mitre": "T1110.001 - Brute Force: Password Guessing",
      "detailed_notes": "🚩 Flag 1: Attacker IP Address\n\nMITRE Technique: 🔸 T1110.001 – Brute Force: Password Guessing\n\nScenario Context:\nSuspicious RDP login activity has been detected on a cloud-hosted Windows server...\n\n[... full paste ...]",
      "kql_used": "DeviceLogonEvents | where DeviceName contains 'flare'...",
      "captured_at": "2025-10-10T15:32:18",
      "objective": "Identify the external IP address that successfully logged in via RDP after a series of failures",
      "output": "159.26.106.84",
      "finding": "The tricky part of the opening premise states the event took place on the date of 14th of Sept..."
    },
    {
      "flag_number": 2,
      "title": "Compromised Account",
      "answer": "slflare",
      "stage": "Initial Access",
      "mitre": "T1078 - Valid Accounts",
      "detailed_notes": "🚩 Flag 2: Compromised Account\n\nMITRE Technique: 🔸 T1078 – Valid Accounts...\n\n[... full paste ...]",
      "kql_used": "DeviceLogonEvents | where RemoteIP == '159.26.106.84'...",
      "captured_at": "2025-10-10T15:34:10",
      "objective": "Determine the username that was used during the successful RDP login",
      "output": "slflare",
      "finding": "Trailing from the first flag for all the ActionType status..."
    },
    {
      "flag_number": 3,
      "title": "Executed Binary Name",
      "answer": "msupdate.exe",
      "stage": "Execution",
      "mitre": "T1059.003",
      "notes": "Malicious binary from Public folder",
      "kql": "DeviceProcessEvents | where AccountName == 'slflare'...",
      "captured_at": "2025-10-10T16:07:22"
    }
    // ... flags 4-10
  ]
}
```

---

## 🎯 Key Features

### **1. Flexible Input:**
- Skip flags you don't want to document
- Paste entire writeups (your exact format)
- Or use automated notes from hunt

### **2. Auto-Parsing:**
System extracts structured fields from your paste:
- `Objective:` → extracted as `objective` field
- `Output:` → extracted as `output` field  
- `Finding:` → extracted as `finding` field
- KQL blocks → extracted as `kql_from_notes`

### **3. Complete Documentation:**
Full text preserved in `detailed_notes` field for human reading

### **4. Machine-Readable:**
Structured JSON for:
- Building enhanced reports
- Importing into other tools
- Analyzing investigation patterns
- Training material

---

## 💡 Use Cases

### **Use Case 1: CTF Writeup**
After completing CTF, paste all your investigation notes:
→ Generates structured JSON
→ Can convert to blog post, GitHub markdown, or PDF

### **Use Case 2: Team Documentation**
Share complete methodology with team:
→ JSON includes full reasoning, queries, findings
→ Others can learn from your approach

### **Use Case 3: Learning Reference**
Save for future CTFs:
→ See what queries worked
→ Understand correlation patterns
→ Reference for similar flags

### **Use Case 4: Report Building**
External tool can read JSON:
→ Generate PDF reports
→ Create slide presentations
→ Build knowledge base

---

## 📊 Complete File Output After Hunt

```
ctf_sessions/
├── session_20251010_153000.jsonl       # Audit trail (every action)
├── session_summary.json                 # Final state (all flags)
├── investigation_report.md              # Auto-generated report
└── flag_investigation_logic.json        # Your detailed notes ← NEW!
```

---

## 🔄 Updated Complete Flow

```
Hunt Flags → Completion Stage → Flag Logic Review → Done

Stage Flow:
  Stage 0-6 (per flag) → ... → All flags captured
                                       ↓
                            Completion Stage:
                              • Statistics
                              • All flags
                              • IOCs
                              • Attack chain
                              • Report generation
                                       ↓
                            Flag Logic Review:  ← NEW!
                              • Optional detail capture
                              • Paste full writeups
                              • Save to JSON
                                       ↓
                                  COMPLETE
```

---

## ✅ **Why This Is Useful:**

**Automated Hunt Captures:**
- Flag answers
- Brief notes
- KQL queries used
- Timestamps

**Flag Logic Review Adds:**
- ✅ Full investigation methodology
- ✅ Detailed reasoning and thought process
- ✅ Complete KQL with comments
- ✅ Screenshots/evidence references (as text)
- ✅ Lessons learned
- ✅ Correlation insights

**Result:** Complete investigation documentation in machine-readable format! 🎯

