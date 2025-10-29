# 🔄 Stage-to-Stage Transitions - How to Move Forward

## 📋 **Every Transition Explained**

This guide shows **exactly what happens** at the end of each stage and **how you move to the next stage**.

---

## 🎯 **The 6-Stage Flow**

```
START → Stage 1 → Stage 2 → Stage 3 → Stage 4 → Stage 5 → Stage 6 → LOOP/EXIT
```

---

## ✅ **Stage 1 → Stage 2 Transition**

### **At the End of Stage 1:**
```
🚩 Flag 1: Attacker IP Address
MITRE: T1110.001 - Brute Force
Objective: Find external IP...
DONE  ← You type this

✓ Flag intel captured          ← System confirms
Title: Attacker IP Address
Objective: Identify the external IP address...

[Stage 1 complete]
```

### **How Transition Happens:**
- ✅ **Automatic** - No action needed
- ✅ System parses your input
- ✅ Creates flag_intel object
- ✅ Immediately moves to Stage 2

### **You See Next:**
```
══════════════════════════════════════════════════════════════════════
🔨 BUILDING QUERY              ← Now at Stage 2!
══════════════════════════════════════════════════════════════════════
```

**💡 Key Point:** Once you type DONE and press Enter at Stage 1, the system **automatically** moves to Stage 2. You don't need to do anything extra.

---

## ✅ **Stage 2 → Stage 3 Transition**

### **At the End of Stage 2:**
```
SUGGESTED QUERY:
DeviceLogonEvents
| where RemoteIPType == "Public"
...

  [1] Execute this query
  [2] Edit query
  [3] Cancel

Select [1-3]: 1  ← You type this and press Enter
```

### **How Transition Happens:**
- ✅ System receives your selection (1, 2, or 3)
- ✅ If you selected [1]: Saves query and moves to Stage 3
- ✅ If you selected [2]: Let's you edit, then moves to Stage 3
- ✅ If you selected [3]: Exits hunt (no transition)

### **You See Next (if you selected [1] or [2]):**
```
══════════════════════════════════════════════════════════════════════
⚡ EXECUTING QUERY             ← Now at Stage 3!
══════════════════════════════════════════════════════════════════════

Running KQL against Azure Log Analytics...
```

**💡 Key Point:** Your selection ([1] or [2]) immediately triggers the transition to Stage 3 where the query executes.

---

## ✅ **Stage 3 → Stage 4 Transition**

### **At the End of Stage 3:**
```
✓ Query executed successfully
✓ 45 results returned

RESULTS (first 10 rows):
Timestamp                    RemoteIP        AccountName
2025-09-14 03:45:12         159.26.106.84   slflare
...

[Query results displayed]
```

### **How Transition Happens:**
- ✅ **100% Automatic** - No input needed from you
- ✅ Query finishes executing
- ✅ Results are captured
- ✅ System immediately moves to Stage 4

### **You See Next:**
```
══════════════════════════════════════════════════════════════════════
🧠 ANALYZING RESULTS           ← Now at Stage 4!
══════════════════════════════════════════════════════════════════════

The LLM will analyze the query results and suggest an answer.

Press [Enter] for LLM analysis... _
```

**💡 Key Point:** Stage 3 is fully automatic. Once the query completes, you're immediately at Stage 4. You just need to press Enter to start the analysis.

---

## ✅ **Stage 4 → Stage 5 Transition**

### **At the End of Stage 4:**
```
Press [Enter] for LLM analysis... ← You press Enter

Analyzing with gpt-oss:20b...

FINDING:

ANSWER: 159.26.106.84

EVIDENCE: This IP appears in the earliest successful RDP login...
REASONING: The query results show this pattern...

──────────────────────────────────────────────────────────────────────

[Analysis complete]
```

### **How Transition Happens:**
- ✅ **Automatic after you press Enter**
- ✅ LLM analyzes the results
- ✅ Extracts suggested answer
- ✅ System immediately moves to Stage 5

### **You See Next:**
```
══════════════════════════════════════════════════════════════════════
🎯 FLAG ANSWER                 ← Now at Stage 5!
══════════════════════════════════════════════════════════════════════

SUGGESTED: 159.26.106.84

  [1] ✓ Accept this answer
  [2] ✗ Reject (show recovery options)

Select [1-2]: _
```

**💡 Key Point:** You press Enter once at Stage 4, wait for analysis to complete, then you're automatically at Stage 5 where you accept or reject the answer.

---

## ✅ **Stage 5 → Stage 6 Transition**

### **At the End of Stage 5:**

**If You Accept ([1]):**
```
Select [1-2]: 1  ← You type this

Notes (optional): Verified from logs  ← Optional notes or just press Enter

✓ FLAG 1 CAPTURED: 159.26.106.84

[Flag saved to session]
```

### **How Transition Happens:**
- ✅ Your acceptance triggers flag capture
- ✅ System saves flag to session memory
- ✅ Updates session state
- ✅ System immediately moves to Stage 6

### **You See Next:**
```
══════════════════════════════════════════════════════════════════════
📚 SESSION MEMORY              ← Now at Stage 6!
══════════════════════════════════════════════════════════════════════

Flags Captured: 1

  ✓ 🚩 Flag 1: Attacker IP Address: 159.26.106.84

Accumulated IOCs:
  • Ips: 159.26.106.84

══════════════════════════════════════════════════════════════════════
WHAT'S NEXT?
══════════════════════════════════════════════════════════════════════

  [1] Rework current flag
  [2] Work on next flag
  [3] Pause and exit
  [4] Finish hunt

Select [1-4]: _
```

**💡 Key Point:** Once you accept and optionally add notes, the flag is immediately captured and you're at Stage 6 where you decide what to do next.

---

**If You Reject ([2]):**
```
Select [1-2]: 2  ← You type this

══════════════════════════════════════════════════════════════════════
⚠️  ANSWER REJECTED - RECOVERY OPTIONS
══════════════════════════════════════════════════════════════════════

[Shows recovery menu - see below]
```

---

## ✅ **Stage 6 → Stage 1 Transition (Loop)**

### **At Stage 6:**
```
WHAT'S NEXT?

  [1] Rework current flag
  [2] Work on next flag
  [3] Pause and exit
  [4] Finish hunt

Select [1-4]: _
```

### **How Transitions Happen:**

**If You Select [1] - Rework:**
```
Select [1-4]: 1  ← You type this

[System removes last flag from session]
[Returns to Stage 1 to re-hunt same flag]

══════════════════════════════════════════════════════════════════════
📋 FLAG INTEL CAPTURE          ← Back to Stage 1!
══════════════════════════════════════════════════════════════════════
```
→ You're back at Stage 1, can paste same or different intel

**If You Select [2] - Next Flag:**
```
Select [1-4]: 2  ← You type this

[System increments flag counter]
[Returns to Stage 1 for new flag]

══════════════════════════════════════════════════════════════════════
📋 FLAG INTEL CAPTURE          ← Back to Stage 1!
══════════════════════════════════════════════════════════════════════

Paste your flag objective...
```
→ You're at Stage 1 for Flag 2

**If You Select [3] - Pause:**
```
Select [1-4]: 3  ← You type this

💾 Pausing investigation...
✓ Session paused. You can resume later.
✓ Session saved

[Program exits]
```
→ Hunt ends (resumable later)

**If You Select [4] - Finish:**
```
Select [1-4]: 4  ← You type this

🏁 FINISHING HUNT
✓ Report generated
✓ Session marked as completed

[Program exits]
```
→ Hunt ends (completed)

---

## 🔄 **Special Transitions**

### **Recovery Menu → Various Stages**

**If You Reject at Stage 5:**
```
ANSWER REJECTED - RECOVERY OPTIONS

  [1] Build new query
  [2] Re-analyze results
  [3] Enter answer manually
  [4] View raw results
  [5] Skip flag
  [6] Exit hunt

Select [1-6]: _
```

**Transitions from Recovery Menu:**

| Choice | Goes To | What Happens |
|--------|---------|--------------|
| **[1]** | **Stage 2** | Returns to query building |
| **[2]** | **Stage 4** | Re-runs analysis with new LLM call |
| **[3]** | **Stage 5** | Prompts for manual entry, then capture |
| **[4]** | **Recovery Menu** | Shows data, returns to same menu |
| **[5]** | **Exit** | Skips flag and exits hunt |
| **[6]** | **Exit** | Exits hunt immediately |

---

## 📊 **Complete Transition Map**

```
┌─────────────┐
│   START     │
└──────┬──────┘
       │
       ↓
┌─────────────────────────────────────────┐
│ STAGE 1: FLAG INTEL CAPTURE             │
│ Action: Paste flag + Type DONE + Enter  │
│ Transition: Automatic                    │
└──────────────────┬──────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ STAGE 2: QUERY BUILDING                 │
│ Action: Type 1 (or 2) + Enter           │
│ Transition: On selection                │
└──────────────────┬──────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ STAGE 3: EXECUTION                      │
│ Action: None (automatic)                │
│ Transition: When query completes        │
└──────────────────┬──────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ STAGE 4: ANALYSIS                       │
│ Action: Press Enter once                │
│ Transition: When analysis completes     │
└──────────────────┬──────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ STAGE 5: FLAG CAPTURE                   │
│ Action: Type 1 (accept) + Enter         │
│ Transition: On acceptance               │
└──────────────────┬──────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ STAGE 6: WHAT'S NEXT?                   │
│ Action: Type 2 (next) + Enter           │
│ Transition: On selection                │
└──────────────────┬──────────────────────┘
                   │
                   ↓
     ┌─────────────┴─────────────┐
     │                            │
     ↓                            ↓
  [2] Next                    [3] Pause
     │                            │
     ↓                            ↓
  Stage 1                       EXIT
  (Flag 2)                   (Resume later)
```

---

## ✅ **Summary Table**

| From Stage | To Stage | Trigger | Type of Transition |
|-----------|----------|---------|-------------------|
| **1 → 2** | Intel → Query | Type `DONE` + Enter | Automatic |
| **2 → 3** | Query → Execute | Select `1` + Enter | On selection |
| **3 → 4** | Execute → Analyze | Query completes | Automatic |
| **4 → 5** | Analyze → Capture | Press Enter | On Enter press |
| **5 → 6** | Capture → Next | Type `1` + Enter | On acceptance |
| **6 → 1** | Next → Intel | Type `2` + Enter | On selection |
| **6 → Exit** | Next → End | Type `3` or `4` + Enter | On selection |

---

## 🎯 **Key Principles**

### **Automatic Transitions:**
- ✅ **Stage 1 → 2** - After you type DONE
- ✅ **Stage 3 → 4** - After query completes
- ✅ **Stage 4 → 5** - After analysis completes

### **Action-Triggered Transitions:**
- ✅ **Stage 2 → 3** - When you select [1] or [2]
- ✅ **Stage 5 → 6** - When you accept [1]
- ✅ **Stage 6 → ?** - Based on your choice [1-4]

### **User Control Points:**
- 🎯 **Stage 2** - Choose to execute or edit
- 🎯 **Stage 5** - Choose to accept or reject
- 🎯 **Stage 6** - Choose next action
- 🎯 **Recovery** - Multiple paths available

---

## ✅ **You're In Control!**

**The system smoothly transitions between stages, and you have control at key decision points:**

1. ✅ Stage 2: Execute or edit query
2. ✅ Stage 4: Start analysis (press Enter)
3. ✅ Stage 5: Accept or reject answer
4. ✅ Stage 6: Next flag, pause, or finish

**All transitions are clear and intentional - no surprises!** 🚀✅

