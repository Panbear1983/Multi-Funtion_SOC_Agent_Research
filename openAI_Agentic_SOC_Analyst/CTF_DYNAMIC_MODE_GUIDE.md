# 🎯 CTF Dynamic Mode - How It Actually Works

## Design Philosophy

**This is NOT a structured scenario runner.**  
**This IS a flag-by-flag CTF assistant.**

---

## 💡 What This Module Does

### **Per-Flag Assistance:**
```
You encounter ANY flag in ANY CTF
  ↓
Paste the flag objective/hints
  ↓
System helps:
  • Build KQL query (with LLM + correlation)
  • Execute against Azure
  • Analyze results
  • Capture answer
  ↓
You decide: Next flag / Rework / Finish
```

**No predefined structure. Completely dynamic.**

---

## 🔄 Complete Flow

### **Start:**
```bash
python3 _main.py
[3] CTF MODE

Project Name: Hide Your RDP: Password Spray Leads to Full Compromise

✓ Project created
```

---

### **Flag 1:**

```
══════════════════════════════════════════════════════════════════════
📋 FLAG INTEL CAPTURE
══════════════════════════════════════════════════════════════════════

Paste the flag objective and any hints/intel you have.
Type 'DONE' on a new line when finished

> 🚩 Flag 1: Attacker IP Address
> MITRE: T1110.001 - Brute Force
> Objective: Find external IP that logged in after brute-force
> Hint: Look for failed logins followed by success from public IPs
> Format: xxx.xxx.xxx.xxx
> DONE

✓ Flag intel captured
Title: 🚩 Flag 1: Attacker IP Address
Objective: Find external IP that logged in after brute-force

══════════════════════════════════════════════════════════════════════
🔨 BUILDING QUERY
══════════════════════════════════════════════════════════════════════

🤖 Generating KQL query...

SUGGESTED QUERY:

DeviceLogonEvents
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where DeviceName contains "flare"
| project Timestamp, RemoteIP, AccountName, ActionType
| sort by Timestamp asc

  [1] Execute this query
  [2] Edit query
  [3] Cancel

Select [1-3]: 1

══════════════════════════════════════════════════════════════════════
⚡ EXECUTING QUERY
══════════════════════════════════════════════════════════════════════

✓ Query completed
Records: 23

RESULTS (first 15 rows):
[Shows Azure log data...]

Press [Enter] for LLM analysis...

══════════════════════════════════════════════════════════════════════
🧠 ANALYZING RESULTS
══════════════════════════════════════════════════════════════════════

Analyzing with gpt-4o...

FINDING:

ANSWER: 159.26.106.84
EVIDENCE: First external IP with LogonSuccess at 2025-09-14 18:40:57
REASONING: Earliest public IP showing successful RDP login after brute-force pattern

──────────────────────────────────────────────────────────────────────

SUGGESTED ANSWER: 159.26.106.84

  [1] Accept answer
  [2] Enter different answer manually
  [3] Reject and retry flag

Select [1-3]: 1

Notes (optional): First external IP with successful RDP login

══════════════════════════════════════════════════════════════════════
✓ FLAG 1 CAPTURED: 159.26.106.84
══════════════════════════════════════════════════════════════════════
```

---

### **After Flag 1:**

```
WHAT'S NEXT?

  [1] Work on another flag
  [2] Finish hunt and generate report
  [3] Exit

Select [1-3]: 1
```

---

### **Flag 2 (with correlation):**

```
══════════════════════════════════════════════════════════════════════
📚 SESSION MEMORY  ← Shows what you know so far
══════════════════════════════════════════════════════════════════════

Flags Captured: 1

  ✓ 🚩 Flag 1: Attacker IP Address: 159.26.106.84

Accumulated IOCs:
  • Ips: 159.26.106.84

══════════════════════════════════════════════════════════════════════

📋 FLAG INTEL CAPTURE

Paste the flag objective...

> 🚩 Flag 2: Compromised Account
> Objective: Find username used during RDP login
> Hint: Pivot from Flag 1 IP
> Format: username
> DONE

✓ Flag intel captured

══════════════════════════════════════════════════════════════════════
🔨 BUILDING QUERY
══════════════════════════════════════════════════════════════════════

# SESSION CONTEXT  ← LLM sees previous flags
Flag 1: 159.26.106.84

🤖 Generating KQL query...

SUGGESTED QUERY:

DeviceLogonEvents
| where RemoteIP == "159.26.106.84"  ← Auto-uses Flag 1!
| where ActionType == "LogonSuccess"
| project AccountName

[Execute → Analyze → Capture "slflare"]
```

**Correlation happens automatically!**

---

## 🔑 Key Features

### **1. Dynamic Flag Entry**
- ❌ No predefined scenario files
- ✅ Paste objectives as you encounter them
- ✅ System parses intel automatically
- ✅ Works with ANY CTF

### **2. Session Memory**
- ✅ Remembers all captured flags
- ✅ Accumulates IOCs
- ✅ Provides context to LLM
- ✅ Auto-correlation in queries

### **3. Unknown Total**
- ❌ No "X/10 flags" progress bar
- ✅ Just shows: "5 flags captured"
- ✅ Finish when YOU decide
- ✅ Can have 3 flags or 20 flags

### **4. Flexible Workflow**
- ✅ Work on flags in any order
- ✅ Skip difficult ones
- ✅ Return to retry
- ✅ Stop and resume anytime

---

## 📋 What Gets Saved

### **session_summary.json:**
```json
{
  "project_name": "Hide Your RDP...",
  "status": "in_progress",
  "flags_completed": 5,  ← Just count, no total
  "total_flags": null,  ← Unknown
  "flags_captured": [
    {"flag_number": 1, "title": "...", "answer": "159.26.106.84", ...},
    {"flag_number": 2, "title": "...", "answer": "slflare", ...},
    ...
  ]
}
```

---

## 🎯 Use Cases

### **CTF Competition:**
```
Flag 1 appears → Paste → Solve → Capture
Flag 2 appears → Paste → Solve → Capture
Flag 3 appears → Paste → Solve → Capture
[Continue until CTF ends]
Finish → Generate report
```

### **Learning/Practice:**
```
Work on 3 easy flags
Skip hard one
Come back after learning more
Solve hard flag
Finish
```

---

## ✅ What Changed from V1

| Aspect | V1 (Structured) | V2 (Dynamic) |
|--------|----------------|--------------|
| Scenario file | Required | NOT needed |
| Total flags | Known (10) | Unknown |
| Flag sequence | Predefined 1→10 | User decides |
| Flag intel | Pre-loaded | Paste on-the-fly |
| Progress bar | X/10 (60%) | Just count (6 flags) |
| Use case | Specific CTF | ANY CTF |

---

**This is the correct design for a CTF assistant!** 🎯

Ready to test?

