# 🏆 CTF Mode - Quick Start Guide

## Overview

CTF Mode is an interactive flag hunting pipeline with session memory and automatic correlation. Perfect for CTF competitions where you need to discover multiple flags that build upon each other.

## Key Features

- **Session Memory**: Accumulates flags and IOCs across multiple hunts
- **Auto-Correlation**: Suggests filters based on previous flags
- **LLM-Assisted Queries**: Generates KQL queries from objectives
- **Progressive Capture**: Tracks progress through attack chain
- **Final Report**: Auto-generates investigation report in markdown

---

## How to Use

### 1. Start the Agent

```bash
python3 _main.py
```

### 2. Select CTF Mode

```
SELECT INVESTIGATION MODE:
[1] THREAT HUNTING
[2] ANOMALY DETECTION
[3] CTF MODE - Interactive Flag Hunting  ← Select this
[4] Exit

Select mode [1-4]: 3
```

### 3. Configure Settings

```
Model: gpt-4o (recommended for accuracy)
Severity: 1 (Critical - for maximum detection)
```

### 4. Interactive Hunt Flow

#### **Stage 0: Session Context** (shows accumulated knowledge)
```
Session Memory Loaded:
  ✓ Flag 1: Attacker IP = 159.26.106.84
  ✓ Flag 2: Compromised Account = slflare
  
Progress: 2/10 Flags (20%)
```

#### **Stage 1: Intel Briefing** (flag objective)
```
🚩 FLAG 3: EXECUTED BINARY

Objective:
Identify the binary executed by the attacker

Guidance:
Look for binaries from unusual paths (Public, Temp, Downloads)
Focus on compromised account from Flag 2
```

#### **Stage 2: Query Building** (LLM suggests KQL)
```
SUGGESTED QUERY:
DeviceProcessEvents
| where AccountName == "slflare"  // From Flag 2
| where ProcessCommandLine contains "Public"
| project FileName, ProcessCommandLine

OPTIONS:
  [1] Execute this query
  [2] Write custom KQL
  [3] Cancel
```

#### **Stage 3: Execution** (query runs)
```
✓ Query completed
Records returned: 47

RESULTS (first 10 rows):
Timestamp            | FileName        | ProcessCommandLine
---------------------|-----------------|--------------------------------
2025-09-14 18:41:28  | msupdate.exe    | "msupdate.exe" -ExecutionPo...
...
```

#### **Stage 4: Analysis** (LLM interprets)
```
FINDING:
The binary executed is: msupdate.exe

EVIDENCE:
- Executed at 18:41:28 (earliest suspicious binary)
- By account "slflare" (Flag 2)
- From C:\Users\Public\ (staging directory)

REASONING:
Name mimics Microsoft Update utility. First malicious binary after RDP login.
```

#### **Stage 5: Capture** (save answer)
```
SUGGESTED ANSWER: msupdate.exe

Accept this answer? [Y/n]: y

Add notes (optional): Malicious binary from Public folder

✓ FLAG 3 CAPTURED: msupdate.exe
Progress: 3/10 Flags (30%)
```

#### **Stage 6: Continue** (next action)
```
NEXT STEPS:
  [1] Continue to Flag 4
  [2] Re-investigate Flag 3
  [3] View progress summary
  [4] Generate report and exit

Select [1-4]: 1
```

### 5. Loop Continues

The system automatically:
- Loads session context for next flag
- Uses previous answers as filters
- Builds correlation hints
- Tracks accumulated IOCs

---

## File Structure

### During Hunt:
```
ctf_sessions/
├── session_20251010_153000.jsonl    # Event audit log
└── session_summary.json              # Current state (for LLM)
```

### After Completion:
```
ctf_sessions/
├── session_20251010_153000.jsonl
├── session_summary.json
└── investigation_report.md           # Final human-readable report
```

---

## Session Memory Format

### `session_summary.json`:
```json
{
  "flags_captured": [
    {
      "flag_number": 1,
      "title": "Attacker IP Address",
      "answer": "159.26.106.84",
      "stage": "Initial Access",
      "mitre": "T1110.001"
    }
  ],
  "accumulated_iocs": {
    "ips": ["159.26.106.84"],
    "accounts": ["slflare"],
    "binaries": ["msupdate.exe"]
  }
}
```

This JSON is loaded before each LLM call and formatted into readable context.

---

## Tips

### For Best Results:

1. **Use GPT-4o or GPT-4o-mini**
   - Better at KQL generation
   - More accurate analysis
   - Stronger correlation logic

2. **Set Severity to Critical (1)**
   - Maximum detection sensitivity
   - Reports everything including anomalies

3. **Review LLM Queries**
   - Check suggested KQL before executing
   - Add/remove filters as needed
   - Edit if LLM misunderstood objective

4. **Add Notes**
   - Brief explanations help final report
   - Useful for reviewing later
   - Documents your reasoning

5. **Use Correlation Hints**
   - System auto-suggests filters from previous flags
   - Saves time building queries
   - Ensures proper pivoting

---

## Example Workflow

```bash
# Flag 1: Find attacker IP
→ Query: DeviceLogonEvents | where RemoteIPType == 'Public'
→ Result: 159.26.106.84
→ Captured ✓

# Flag 2: Find compromised account
→ LLM suggests: where RemoteIP == '159.26.106.84'  ← Auto-correlation!
→ Query: DeviceLogonEvents | where RemoteIP == '159.26.106.84'
→ Result: slflare
→ Captured ✓

# Flag 3: Find executed binary
→ LLM suggests: where AccountName == 'slflare'  ← Uses Flag 2!
→ Query: DeviceProcessEvents | where AccountName == 'slflare'
→ Result: msupdate.exe
→ Captured ✓

# And so on...
```

Each flag builds on previous discoveries automatically!

---

## Troubleshooting

### Query Returns No Results:
- Select option [2] to modify query
- Broaden filters or change table
- Check time range

### LLM Wrong Answer:
- Review raw query results
- Select option [4] to enter manually
- Or reject and retry with different query

### Need Clarification:
- Chat with LLM about objective
- Review flag guidance
- Check correlation hints

---

## Final Report

At the end, you get a markdown report with all flags, queries, and findings - ready to share or submit!

**Happy hunting!** 🎯

