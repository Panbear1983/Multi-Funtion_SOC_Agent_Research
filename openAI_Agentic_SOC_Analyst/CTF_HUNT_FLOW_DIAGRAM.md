# 🔄 CTF Hunt Mode - Complete Flow Diagram

## Main Hunt Loop with Recovery Paths

```
┌─────────────────────────────────────────────────────────────────┐
│                    START CTF HUNT                                │
│                  Load Scenario Config                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ All flags done? │
                    └────────┬────────┘
                            │
                ┌───────────┴───────────┐
                │ No                 Yes│
                ▼                       ▼
    ┌────────────────────────┐   ┌──────────────────┐
    │  Continue Hunt Loop    │   │ COMPLETION STAGE │
    └───────────┬────────────┘   │  (See below)     │
                │                └──────────────────┘
                ▼
╔═══════════════════════════════════════════════════════════════════╗
║                        HUNT LOOP (Per Flag)                       ║
╚═══════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────┐
│ STAGE 0: Session Context                                        │
│ ─────────────────────────────────────────────────────────────── │
│ • Display: Captured flags, accumulated IOCs, progress           │
│ • Source: session_summary.json                                  │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 1: Intel Briefing                                         │
│ ─────────────────────────────────────────────────────────────── │
│ • Display: Flag objective, scenario, guidance, hints            │
│ • Source: ctf_scenario.json (flag config)                       │
│ • User: Press [Enter] to continue                               │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 2: Query Building                                         │
│ ─────────────────────────────────────────────────────────────── │
│ • LLM: Generate KQL with correlation hints                      │
│ • Context: Previous flags from session_summary.json             │
│ • User Options:                                                 │
│   [1] Execute suggested query                                   │
│   [2] Write custom KQL                                          │
│   [3] Cancel                                                    │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 3: Execution                                              │
│ ─────────────────────────────────────────────────────────────── │
│ • Execute: KQL query → Azure Log Analytics                      │
│ • Display: First 10 rows of results                             │
│ • Save: Results to CSV for analysis                             │
│ • Check: If 0 results → Loop back to Stage 2                   │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 4: Analysis                                               │
│ ─────────────────────────────────────────────────────────────── │
│ • LLM: Analyze results with session context                     │
│ • Context: Previous flags + current results                     │
│ • Output: Suggested answer + evidence + reasoning               │
│ • User: Press [Enter] to see analysis                           │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 5: Flag Capture                                           │
│ ─────────────────────────────────────────────────────────────── │
│ • Display: LLM suggested answer                                 │
│ • User: Accept this answer? [Y/n]                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
         Answer = Y                    Answer = N
              │                             │
              ▼                             ▼
    ┌──────────────────┐        ┌────────────────────────────┐
    │ Capture Flag     │        │ STAGE 5.5: Rejection       │
    │ • Add notes      │        │ Recovery Options           │
    │ • Save to state  │        └──────────┬─────────────────┘
    │ • Update IOCs    │                   │
    └────────┬─────────┘         ┌─────────┴────────────┐
             │                   │                      │
             ▼                   ▼                      │
    ┌──────────────────┐  [1] New Query        [2] Re-analyze
    │ STAGE 6:         │       │                      │
    │ Continue         │       ├──> Loop to Stage 2   │
    │ Decision         │       │                      │
    └────────┬─────────┘       │               Loop to Stage 4
             │                 │                (with focus hint)
             │                 │
   ┌─────────┴────────┐       │         [3] Manual Entry
   │ [1] Next flag    │       │               │
   │ [2] Retry flag   │       │               ├──> Capture manually
   │ [3] View summary │       │               │     & go to Stage 6
   │ [4] Exit         │       │               │
   └─────────┬────────┘       │         [4] Review Results
             │                │               │
     ┌───────┴───────┐        │               └──> Show data
     │               │        │                     & retry
  Next           Retry        │
   Flag           Flag        │         [5] Skip Flag
     │               │        │               │
     │               │        │               ├──> Go to next flag
     │               │        │               │     (skip current)
     │               │        │               │
     ▼               │        │         [6] Exit Hunt
  Continue          │        │               │
  to next           │        │               └──> Generate report
  iteration         │        │                     & quit
                    │        │
                    │        │
      Loop to ──────┴────────┘
      Stage 0
      (same or next flag)
```

---

## 🎯 Recovery Paths Explained

### **When Answer is Rejected (Stage 5.5):**

```
══════════════════════════════════════════════════════════════════════
❌ ANSWER REJECTED - RECOVERY OPTIONS
══════════════════════════════════════════════════════════════════════

What would you like to do?

  [1] 🔄 Build new query (different approach)
      → Loop back to query building stage
      → Try different table, filters, or time range

  [2] 🧠 Re-analyze same results (LLM missed it)
      → Keep current query results
      → Ask LLM to focus on different fields

  [3] ✏️  Enter answer manually (I found it)
      → You see the answer in the results
      → Skip LLM, input directly

  [4] 🔍 Review raw results again
      → Show full query results
      → Examine data before deciding

  [5] ⏭️  Skip this flag (come back later)
      → Move to next flag
      → Can return to this one later

  [6] 🚪 Exit CTF hunt
      → Generate report and quit

Select [1-6]: _
```

---

## 📊 Decision Tree

```
Answer Wrong? → What's the issue?
                       │
        ┌──────────────┼──────────────┬────────────────┐
        │              │              │                │
   Query Wrong   LLM Wrong     I Know It      Give Up
        │              │              │                │
        ▼              ▼              ▼                ▼
   Option [1]    Option [2]      Option [3]      Option [5][6]
   New Query     Re-analyze      Manual Entry    Skip/Exit
        │              │              │                │
        ▼              ▼              ▼                ▼
   Stage 2       Stage 4         Capture          Next/Quit
   (Query)      (Analysis)       (Stage 5)
```

---

## 🔄 Example Recovery Scenarios

### **Scenario A: Query Too Restrictive**

```bash
Flag 3: Find executed binary

Query: DeviceProcessEvents 
       | where AccountName == "slflare"
       | where FileName contains "malware"  ← Too specific!

Results: 0 records

User: Rejects answer
Select: [1] Build new query

→ Loops to Stage 2
→ LLM generates broader query without "malware" filter
→ Executes → Finds msupdate.exe ✓
```

### **Scenario B: LLM Focused on Wrong Field**

```bash
Query returned good data:
Timestamp | FileName      | ProcessCommandLine
18:41:23  | powershell.exe| ...
18:41:28  | msupdate.exe  | "msupdate.exe" -Execution...

LLM Answer: powershell.exe (wrong - too generic)

User: Rejects answer
Select: [2] Re-analyze same results

Analysis hint: Look for non-standard .exe files, not built-in tools

→ LLM re-analyzes with focus
→ Finds msupdate.exe ✓
```

### **Scenario C: User Sees Answer Immediately**

```bash
Results displayed:
18:41:28  | msupdate.exe  | ...

User: "I can see it's msupdate.exe!"
Select: [3] Enter manually

Enter answer: msupdate.exe
Notes: Obvious from query results

✓ Captured immediately (skips LLM analysis)
```

### **Scenario D: Flag Too Difficult Right Now**

```bash
Flag 7: Discovery command

Results: Too much data, confusing

User: "I'll come back to this"
Select: [5] Skip this flag

→ Moves to Flag 8
→ Flag 7 remains uncaptured
→ Can return later
```

---

## ✅ **Complete Flow Summary**

```
Normal Path:
Stage 0 → 1 → 2 → 3 → 4 → 5 (Accept) → 6 (Next) → Loop

Recovery Paths:
Stage 5 (Reject) → [1] → Stage 2 (new query)
Stage 5 (Reject) → [2] → Stage 4 (re-analyze)
Stage 5 (Reject) → [3] → Manual → Stage 6
Stage 5 (Reject) → [4] → Review → Stage 5
Stage 5 (Reject) → [5] → Skip → Stage 0 (next flag)
Stage 5 (Reject) → [6] → Exit → Completion

Completion:
All flags → Completion Stage → Report → Done
```

---

## 🎯 **Key Benefits:**

✅ **Flexible Recovery** - 6 different ways to handle wrong answers  
✅ **No Dead Ends** - Can always loop back or skip  
✅ **Manual Override** - You can input answer if you found it  
✅ **Progressive** - Can skip hard flags and return later  
✅ **Clean Exit** - Generate partial report anytime  

**The rejection recovery stage makes the system robust for real CTF hunting!** 🚀

