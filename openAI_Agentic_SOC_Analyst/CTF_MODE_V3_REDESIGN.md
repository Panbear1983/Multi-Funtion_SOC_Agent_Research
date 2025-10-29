# 🚀 CTF Mode V3 - Complete Redesign

## ✅ **Major Overhaul: Human-Driven with LLM Advisory**

### **Philosophy Change:**
- **Before:** LLM generates KQL, human accepts/rejects
- **After:** Human writes KQL, LLM provides guidance and interpretation

---

## 📋 **Complete New Flow**

```
START
  ↓
Session Management (Resume or New)
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 1: FLAG INTEL CAPTURE                                    │
│ → User pastes flag objective, hints, context                   │
│ → Type DONE when finished                                      │
│ ✅ KEPT AS IS - No changes                                     │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 2: BOT'S INTEL INTERPRETATION & GUIDANCE 🆕              │
│ → LLM reads the intel                                          │
│ → Explains what to look for (advisory only)                   │
│ → Suggests log/table name                                      │
│ → Recommends fields to project                                 │
│ → Does NOT generate KQL!                                       │
│ → Asks human: "Log Name:" and "Field Name:"                   │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 3: HUMAN WRITES KQL 🆕                                   │
│ → Human types their own KQL query                              │
│ → Multi-line entry with KQL > prompts                         │
│ → Type DONE when finished                                      │
│ → Query executes automatically                                 │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 4: QUERY EXECUTION                                       │
│ → Executes human's KQL query                                   │
│ → Returns results                                              │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 5: RESULTS DISPLAY (Paginated) 🆕                        │
│ → Shows first 100 entries                                      │
│ → [SPACE] Show next 100 entries                               │
│ → [ENTER] Continue to next stage                              │
│ → All columns visible (wide format)                           │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 6: RESULT DOCUMENTATION MENU 🆕                          │
│ → [1] Circle back to Stage 3 (rewrite KQL)                    │
│ → [2] Document result (input answer + KQL for JSON)           │
│       → Enter flag answer                                      │
│       → Enter notes                                            │
│       → Press ENTER to continue                                │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 7: WHAT'S NEXT? 🆕                                       │
│ → [1] Work on next flag → Back to Stage 1                     │
│ → [2] Save and exit → Pause (resume later)                    │
│ → [3] Finish hunt → Stage 8                                    │
└─────────────────────────────────────────────────────────────────┘
  ↓ (if [3] selected)
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 8: FLAG LOGIC FLOW 🆕                                    │
│ → Human inputs detailed threat hunt flow notes                 │
│ → Multi-line entry, type DONE                                  │
│ → Notes appended to JSON                                       │
│ → Hunt marked as completed                                     │
└─────────────────────────────────────────────────────────────────┘
  ↓
END
```

---

## 🎯 **Key Design Changes**

### **1. LLM Role Changed**

**Before:**
- ✅ Generates KQL queries
- ✅ Analyzes results
- ✅ Suggests answers

**After:**
- ✅ **Advisory only** - interprets intel
- ✅ **Suggests** table/fields
- ✅ **Explains** what to look for
- ❌ **Does NOT** generate KQL
- ❌ **Does NOT** analyze results
- ❌ **Does NOT** suggest answers

### **2. Human Role Enhanced**

**Before:**
- Accept/reject LLM queries
- Optional manual entry

**After:**
- ✅ **Writes ALL KQL queries**
- ✅ **Reviews ALL results**
- ✅ **Documents findings**
- ✅ **Determines answers**
- ✅ **Full control**

---

## 📋 **Stage-by-Stage Breakdown**

### **STAGE 1: FLAG INTEL CAPTURE** (Unchanged ✅)

```
📋 FLAG 1 INTEL CAPTURE

Paste the flag objective...
Type 'DONE' when finished

🚩 Flag 1: Attacker IP Address
MITRE: T1110.001 - Brute Force
Objective: Find external IP...
DONE

✓ Flag intel captured
```

---

### **STAGE 2: BOT'S INTEL INTERPRETATION** (NEW 🆕)

```
🤖 BOT'S INTEL INTERPRETATION & GUIDANCE

LLM analyzing flag intel...

BOT'S GUIDANCE:

INTERPRETATION: You need to find an external IP address that successfully 
logged into a system after multiple failed brute-force attempts.

RECOMMENDED TABLE: DeviceLogonEvents

KEY FIELDS: 
  - TimeGenerated (for chronological analysis)
  - RemoteIP (to identify source IP)
  - AccountName (to track which account)
  - ActionType (to differentiate LogonSuccess vs LogonFailed)
  - DeviceName (to identify target system)

SEARCH CRITERIA:
  1. Filter for failed login attempts (ActionType == "LogonFailed")
  2. Find successful logins after failures (ActionType == "LogonSuccess")
  3. Look for external/public IPs (exclude local ranges)
  4. Sort chronologically to find earliest match
  5. Focus on devices containing "flare" (from scenario context)

CORRELATION: This is Flag 1, so no previous answers to correlate.

──────────────────────────────────────────────────────────────────────

Based on the guidance above, please specify:

Log Name (e.g., DeviceLogonEvents): DeviceLogonEvents
Field Names (comma-separated): TimeGenerated, DeviceName, RemoteIP, AccountName, ActionType

✓ Target: DeviceLogonEvents
✓ Fields: TimeGenerated, DeviceName, RemoteIP, AccountName, ActionType
```

**→ Moves to Stage 3**

---

### **STAGE 3: HUMAN WRITES KQL** (NEW 🆕)

```
══════════════════════════════════════════════════════════════════════
✍️  HUMAN KQL QUERY ENTRY
══════════════════════════════════════════════════════════════════════

Write your KQL query based on the bot's guidance.

Target Table: DeviceLogonEvents
Available Fields: AccountName, ActionType, DeviceName, RemoteDeviceName, RemoteIP, TimeGenerated

Instructions:
  • Type each line of your KQL query
  • Press Enter after each line
  • Type 'DONE' on a new line when finished
  • Query will execute after DONE

Example:
──────────────────────────────────────────────────────────────────────
KQL > DeviceLogonEvents
KQL > | where ActionType == "LogonSuccess"
KQL > | where isnotempty(RemoteIP)
KQL > | project TimeGenerated, RemoteIP, AccountName
KQL > DONE
──────────────────────────────────────────────────────────────────────

KQL > DeviceLogonEvents                        ← You type this
KQL > | where TimeGenerated between (datetime(2025-09-13) .. datetime(2025-09-22))
KQL > | where DeviceName contains "flare"
KQL > | where isnotempty(RemoteIP)
KQL > | project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType
KQL > | sort by TimeGenerated asc
KQL > DONE                                      ← Type DONE

Processing query...

[Moves to Stage 4 - Execution]
```

---

### **STAGE 4: EXECUTION** (Simplified)

```
⚡ EXECUTING QUERY

✓ Query completed
Records: 250
```

**→ Automatic to Stage 5**

---

### **STAGE 5: RESULTS DISPLAY** (Enhanced 🆕)

```
══════════════════════════════════════════════════════════════════════
📊 QUERY RESULTS
══════════════════════════════════════════════════════════════════════

RESULTS (rows 1-100 of 250):

TimeGenerated                      DeviceName       AccountName    RemoteIP         ActionType
2025-09-13 03:34:18.134390+00:00  slflarewinsysmo  administrator  125.212.225.61   LogonFailed
2025-09-13 03:37:08.294693+00:00  slflarewinsysmo  administrator  125.212.225.61   LogonFailed
2025-09-14 03:45:12.778901+00:00  slflarewinsysmo  slflare        159.26.106.84    LogonSuccess
...
[100 rows, all columns visible]

──────────────────────────────────────────────────────────────────────

[SPACE] Show next 100 rows
[ENTER] Continue to next stage

→ [Space or Enter]  ← Your choice
```

---

### **STAGE 6: RESULT DOCUMENTATION MENU** (NEW 🆕)

```
══════════════════════════════════════════════════════════════════════
📝 RESULT DOCUMENTATION
══════════════════════════════════════════════════════════════════════

  [1] ↩️  Rewrite KQL query (back to query entry)
  [2] ✍️  Document result (capture KQL + output)

Select [1-2]: 2  ← Document the result

══════════════════════════════════════════════════════════════════════
📋 DOCUMENT FLAG RESULT
══════════════════════════════════════════════════════════════════════

Document the correct KQL and output for this flag.

Your KQL Query:
──────────────────────────────────────────────────────────────────────
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-09-13) .. datetime(2025-09-22))
| where DeviceName contains "flare"
| project TimeGenerated, RemoteIP, AccountName, ActionType
──────────────────────────────────────────────────────────────────────

Query Output (first 5 rows):
──────────────────────────────────────────────────────────────────────
[First 5 rows shown]
──────────────────────────────────────────────────────────────────────

Enter the flag answer:
Answer: 159.26.106.84  ← You type the answer

Finding notes (optional): First public IP with success after brute-force

✓ FLAG 1 CAPTURED: 159.26.106.84

[ENTER] Continue

→ [Press Enter]
```

**→ Flag appended to JSON memory**

---

### **STAGE 7: WHAT'S NEXT?** (Simplified 🆕)

```
══════════════════════════════════════════════════════════════════════
📚 SESSION MEMORY
══════════════════════════════════════════════════════════════════════

Flags Captured: 1

  ✓ Flag 1: Attacker IP Address: 159.26.106.84

Accumulated IOCs:
  • Ips: 159.26.106.84

══════════════════════════════════════════════════════════════════════
WHAT'S NEXT?
══════════════════════════════════════════════════════════════════════

  [1] ➡️  Work on next flag
      → Start investigating the next flag

  [2] 💾 Save and exit
      → Pause investigation, resume later

  [3] 🏁 Finish hunt
      → Add detailed logic notes and complete investigation

Select [1-3]: 1  ← Next flag

[Returns to Stage 1 for Flag 2]
```

---

### **STAGE 8: FLAG LOGIC FLOW** (Only if Finish - NEW 🆕)

```
Select [1-3]: 3  ← Finish hunt

══════════════════════════════════════════════════════════════════════
📖 DETAILED THREAT HUNT LOGIC FLOW
══════════════════════════════════════════════════════════════════════

Add your detailed notes about the complete threat hunt.
This helps document the full investigation logic and approach.

Type your notes (multi-line), then type 'DONE' when finished:

This investigation tracked an RDP brute-force attack.
Flag 1 identified the attacker IP (159.26.106.84).
Flag 2 found the compromised account (slflare).
The attack followed a typical password spray pattern...
DONE

✓ Logic flow notes saved

[Hunt marked as completed]
[Final report generated]
```

---

## 🎯 **Key Features**

### **1. JSON Memory Management**
- ✅ **Created** when project name is entered
- ✅ **Named** after project (e.g., `Project_Name_summary.json`)
- ✅ **Updated** when project renamed (files rename too)
- ✅ **Appended** after each flag capture
- ✅ **Used** for next flag's bot interpretation (correlation)

### **2. Human-Written KQL**
- ✅ All queries written by human
- ✅ Bot provides guidance only
- ✅ Available fields shown
- ✅ Multi-line entry support

### **3. Complete Documentation**
- ✅ KQL query saved
- ✅ Output saved
- ✅ Answer documented
- ✅ Notes captured
- ✅ All stored in JSON

### **4. Paginated Results Everywhere**
- ✅ Stage 5: Results display
- ✅ 100 rows per page
- ✅ SPACE/ENTER navigation
- ✅ All columns visible

---

## 📊 **Comparison: V2 vs V3**

| Aspect | V2 (Old) | V3 (New) |
|--------|----------|----------|
| **KQL Generation** | LLM writes queries | **Human writes queries** ✅ |
| **LLM Role** | Active (generates/analyzes) | **Advisory (guides only)** ✅ |
| **Human Control** | Accept/reject | **Full control** ✅ |
| **Results Analysis** | LLM suggests answer | **Human determines answer** ✅ |
| **Interactive Chat** | Only in recovery | **Removed** (human-driven) |
| **Rework Flag** | Yes (complicated) | **Simplified** (rewrite query) |
| **Recovery Options** | 6 options | **Streamlined flow** |
| **Stages** | 6 stages | **8 stages** (more granular) |
| **Documentation** | Auto-captured | **Human documents** ✅ |
| **Logic Flow Notes** | None | **Added** (Stage 8) ✅ |

---

## 🔄 **Complete Workflow Example**

### **Flag 1 Complete Cycle:**

```
1. INTEL CAPTURE
   → Paste flag 1 objective
   → DONE

2. BOT INTERPRETATION
   → Bot explains what to look for
   → Suggests DeviceLogonEvents
   → You enter: Log Name, Field Names

3. HUMAN KQL ENTRY
   → You write KQL query
   → DONE

4. EXECUTION
   → Query runs (250 results)

5. RESULTS DISPLAY
   → View 100 rows
   → [SPACE] next 100
   → [ENTER] continue

6. DOCUMENTATION
   → [2] Document
   → Enter answer: 159.26.106.84
   → Enter notes
   → [ENTER]
   
   ✓ FLAG 1 CAPTURED
   ✓ JSON updated with Flag 1 data

7. WHAT'S NEXT?
   → [1] Next flag
```

### **Flag 2 Cycle:**

```
1. INTEL CAPTURE
   → Paste flag 2 objective
   → DONE

2. BOT INTERPRETATION  ← Uses Flag 1 answer!
   → Bot: "You can filter by IP 159.26.106.84 from Flag 1"
   → Suggests DeviceProcessEvents
   → You enter: Log Name, Field Names

3. HUMAN KQL ENTRY
   → DeviceProcessEvents
   → | where RemoteIP == "159.26.106.84"  ← Uses Flag 1!
   → DONE

[Continue through stages...]

✓ FLAG 2 CAPTURED
✓ JSON updated with Flag 2 data (appended)
```

---

## 📂 **JSON Structure**

### **File Created:**
```
ctf_sessions/
└── Project_Name_summary.json  ← Created on project creation
```

### **JSON Content (After 2 Flags):**

```json
{
  "project_name": "Hide Your RDP Attack",
  "status": "in_progress",
  "flags_completed": 2,
  "flags_captured": [
    {
      "flag_number": 1,
      "title": "Flag 1: Attacker IP Address",
      "answer": "159.26.106.84",
      "kql_used": "DeviceLogonEvents | where...",
      "notes": "First public IP after brute-force",
      "raw_intel": "🚩 Flag 1: Attacker IP...",
      "objective": "Find external IP..."
    },
    {
      "flag_number": 2,
      "title": "Flag 2: Compromised Account",
      "answer": "slflare",
      "kql_used": "DeviceLogonEvents | where RemoteIP == '159.26.106.84'...",
      "notes": "Account used in successful login",
      "raw_intel": "🚩 Flag 2: Compromised Account...",
      "objective": "Identify compromised account..."
    }
  ],
  "accumulated_iocs": {
    "ips": ["159.26.106.84"],
    "accounts": ["slflare"]
  },
  "logic_flow_notes": ""  ← Populated when finish selected
}
```

---

## ✅ **What Got Removed**

### **Deleted/Unused:**
- ❌ LLM query generation
- ❌ LLM result analysis
- ❌ Interactive chat mode (replaced with advisory)
- ❌ Accept/reject answer flow (human determines answer)
- ❌ Rejection recovery complex menu (simplified)
- ❌ Rework flag option (replaced with rewrite query)

### **Simplified:**
- ✅ Recovery menu → Documentation menu
- ✅ What's Next menu → 3 options (was 4)
- ✅ Flow is linear and straightforward

---

## 🎯 **Navigation Controls**

| Stage | Control | Action |
|-------|---------|--------|
| 1. Intel | Type DONE + Enter | → Stage 2 |
| 2. Bot Guidance | Enter Log + Fields | → Stage 3 |
| 3. Human KQL | Type DONE + Enter | → Stage 4 |
| 4. Execute | Automatic | → Stage 5 |
| 5. Results | SPACE/ENTER | → Stage 6 |
| 6. Document | Select [2] + Enter answer | → Stage 7 |
| 7. What's Next | Select [1/2/3] | → Stage 1 or Exit or Stage 8 |
| 8. Logic Flow | Type DONE + Enter | → End |

---

## 🚀 **Benefits of V3**

### **More Human Control:**
- ✅ You write all queries
- ✅ You determine all answers
- ✅ You document everything
- ✅ LLM just advises

### **Better Learning:**
- ✅ Understand KQL better
- ✅ Learn what fields to use
- ✅ Develop hunting skills
- ✅ Bot teaches, you execute

### **Better Documentation:**
- ✅ Every KQL query saved
- ✅ Every output documented
- ✅ Complete logic flow captured
- ✅ JSON contains full hunt history

### **Simpler Flow:**
- ✅ Linear progression
- ✅ Fewer options
- ✅ Clear purpose at each stage
- ✅ Less confusing than V2

---

## 📖 **Ready to Use!**

**Test the new V3 flow:**
```bash
python3 _main.py
[3] CTF MODE
```

**You'll experience:**
1. ✅ Clear bot guidance
2. ✅ Write your own KQL
3. ✅ Review paginated results
4. ✅ Document findings
5. ✅ Complete control over hunt

**Welcome to CTF Mode V3 - Human-Driven Threat Hunting!** 🎯✅

