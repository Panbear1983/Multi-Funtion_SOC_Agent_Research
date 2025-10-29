# 🔄 CTF Hunt Recovery Options - Quick Reference

## When Things Don't Go Right

This guide shows all the ways you can recover when a flag hunt doesn't work on the first try.

---

## 📍 Decision Point 1: After LLM Suggests Answer (Stage 5)

```
SUGGESTED ANSWER: msupdate.exe

Accept this answer? [Y/n]: _
```

### **If Y (or Enter):**
→ Flag captured → Move to Stage 6 (Continue decision)

### **If N:**
→ Rejection Recovery Menu (Stage 5.5) appears

---

## 🔧 Rejection Recovery Options (Stage 5.5)

### **[1] 🔄 Build New Query**

**When to use:**
- Query returned 0 results
- Query returned wrong data
- Filters were too restrictive/broad
- Need to try different table

**What happens:**
```
Loop back to Stage 2
  ↓
Build new KQL query
  ↓
Execute new query
  ↓
Analyze new results
  ↓
Try capture again
```

**Example:**
```
Original query: DeviceProcessEvents | where FileName contains "malware"
  → 0 results
  
New query: DeviceProcessEvents | where ProcessCommandLine contains "Public"
  → 47 results
  → Find answer ✓
```

---

### **[2] 🧠 Re-analyze Same Results**

**When to use:**
- Query returned good data
- Answer is IN the results
- LLM focused on wrong field/row
- Need different interpretation

**What happens:**
```
You provide focus hint
  ↓
Loop to Stage 4 (Analysis)
  ↓
LLM re-analyzes SAME data with your hint
  ↓
Try capture again
```

**Example:**
```
Results show:
  powershell.exe
  msupdate.exe  ← This is the answer
  cmd.exe

LLM picked: powershell.exe (wrong - too generic)

You provide hint: "Look for non-standard binaries, not built-in tools"
  ↓
LLM re-analyzes
  ↓
LLM picks: msupdate.exe ✓
```

---

### **[3] ✏️ Enter Answer Manually**

**When to use:**
- You can SEE the answer in results
- Faster to input than wait for LLM
- LLM keeps getting it wrong
- Answer is obvious

**What happens:**
```
Enter answer directly
  ↓
Confirm answer
  ↓
Add optional notes
  ↓
Flag captured immediately
  ↓
Skip to Stage 6 (Continue)
```

**Example:**
```
Results clearly show:
  159.26.106.84 ← FIRST external IP with LogonSuccess

You: "It's obviously 159.26.106.84"

Enter answer: 159.26.106.84
Notes: First external IP in results
  ↓
✓ Flag 1 captured (manual)
```

---

### **[4] 🔍 Review Raw Results**

**When to use:**
- Need to see all query results again
- Want to examine data before deciding
- Scrolled past results

**What happens:**
```
Display full results
  ↓
User examines data
  ↓
Return to recovery menu
  ↓
Choose another option
```

---

### **[5] ⏭️ Skip This Flag**

**When to use:**
- Flag too difficult right now
- Need more context from other flags
- Want to come back later
- Stuck on this flag

**What happens:**
```
Confirm skip
  ↓
Flag marked as skipped in event log
  ↓
Move to next flag (Flag N+1)
  ↓
Continue hunt
```

**Example:**
```
Flag 5: Find scheduled task (stuck)
  ↓
Skip → Flag 6: Find Defender exclusion
  ↓
Flag 6 captured ✓
  ↓
Later: Return to Flag 5 with more context
```

---

### **[6] 🚪 Exit CTF Hunt**

**When to use:**
- Need to stop hunting
- Out of time
- Want to save progress

**What happens:**
```
Confirm exit
  ↓
Generate partial report? [Y/n]
  ↓
If yes: Create markdown report with captured flags
  ↓
Exit hunt
  ↓
Return to main menu
```

---

## 📍 Decision Point 2: After Flag Captured (Stage 6)

```
✓ FLAG 3 CAPTURED: msupdate.exe

NEXT STEPS:
  [1] Continue to Flag 4
  [2] Re-investigate Flag 3
  [3] View progress summary
  [4] Generate report and exit

Select [1-4]: _
```

### **[1] Continue to Next Flag**
→ Move to Flag N+1 → Loop to Stage 0

### **[2] Re-investigate Current Flag**
→ Stay on same flag → Loop to Stage 1 (Intel Briefing)

**Use when:**
- Want to try different approach
- Captured answer but not confident
- Want to verify with different query

### **[3] View Progress Summary**
→ Display session context → Return to Stage 6

**Shows:**
- All captured flags
- Accumulated IOCs
- Attack chain so far

### **[4] Generate Report and Exit**
→ Create report → Exit hunt

---

## 🔄 Complete Loop Paths

### **Path 1: Perfect First Try**
```
Stage 1 → 2 → 3 → 4 → 5 (Accept) → 6 (Next) → Stage 0 (next flag)
```

### **Path 2: Wrong Query, Retry**
```
Stage 1 → 2 → 3 (0 results) → Loop to Stage 2 → 3 → 4 → 5 (Accept) → 6
```

### **Path 3: LLM Wrong, Re-analyze**
```
Stage 1 → 2 → 3 → 4 → 5 (Reject) → [2] Re-analyze → 4 → 5 (Accept) → 6
```

### **Path 4: Manual Entry**
```
Stage 1 → 2 → 3 → 4 → 5 (Reject) → [3] Manual → Captured → 6
```

### **Path 5: Skip Hard Flag**
```
Stage 1 → 2 → 3 → 4 → 5 (Reject) → [5] Skip → Stage 0 (Flag N+1)
```

### **Path 6: Second Thoughts After Capture**
```
Stage 5 (Accept) → 6 → [2] Re-investigate → Stage 1 (same flag again)
```

---

## 🎯 Summary

**Total Recovery Options:**

| Stage | User Decision Point | Options Available |
|-------|-------------------|-------------------|
| **Stage 2** | Execute query? | 3 options (execute/custom/cancel) |
| **Stage 5** | Accept answer? | 2 options (yes/no) |
| **Stage 5.5** | Answer rejected | 6 recovery paths |
| **Stage 6** | What next? | 4 continuation options |

**Total Control Points: 4 per flag**  
**Total Recovery Paths: 15 different ways to proceed**

**You're never stuck!** There's always a way forward, back, or around. 🚀

