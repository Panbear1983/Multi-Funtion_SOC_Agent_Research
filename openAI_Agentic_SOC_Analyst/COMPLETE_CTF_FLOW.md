# 🔄 Complete CTF Hunt Flow - End-to-End

## ✅ **All Stages Connected Without Issues**

---

## 📋 **Complete Flow Diagram**

```
START
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ MODE SELECTION                                                  │
│ [3] CTF MODE - Interactive Flag Hunting                        │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ MODEL & SEVERITY SELECTION                                      │
│ - Select model (cloud/local auto-detected)                     │
│ - Select severity level (1-4)                                  │
└─────────────────────────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ SESSION MANAGEMENT                                              │
│ ┌─ Existing sessions? ─────────────────────────────────────┐   │
│ │  YES → Show resume menu                                  │   │
│ │    [C] Continue with existing hunts                      │   │
│ │       ├─ [1-N] Select project                           │   │
│ │       │    ├─ [1] Continue hunt                         │   │
│ │       │    ├─ [2] Rename project                        │   │
│ │       │    └─ [B] Back                                  │   │
│ │       └─ [N] Start new investigation                     │   │
│ │  NO → Prompt for project name                           │   │
│ └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
  ↓
  ↓ [NEW SESSION: Flag 1 auto-starts]
  ↓ [RESUMED SESSION: Goes to "WHAT'S NEXT?" menu]
  ↓
┌═════════════════════════════════════════════════════════════════┐
║ STAGE 1: FLAG INTEL CAPTURE                                    ║
╠═════════════════════════════════════════════════════════════════╣
║ User pastes flag objective:                                    ║
║   🚩 Flag 1: Attacker IP Address                              ║
║   MITRE: T1110.001 - Brute Force                              ║
║   Objective: Find external IP...                              ║
║   Hint: Look for failed logins...                             ║
║   DONE                                                          ║
║                                                                 ║
║ System parses intel → flag_intel object                       ║
╚═════════════════════════════════════════════════════════════════╝
  ↓
┌═════════════════════════════════════════════════════════════════┐
║ STAGE 2: QUERY BUILDING                                        ║
╠═════════════════════════════════════════════════════════════════╣
║ LLM generates KQL query:                                       ║
║   - Uses flag intel                                            ║
║   - Uses session context (previous flags)                      ║
║   - Auto-routes to Ollama/OpenAI                              ║
║                                                                 ║
║ SUGGESTED QUERY:                                               ║
║   DeviceLogonEvents                                            ║
║   | where RemoteIPType == "Public"                            ║
║   | where ActionType == "LogonSuccess"                        ║
║                                                                 ║
║ Options:                                                        ║
║   [1] Execute this query     → Continue                        ║
║   [2] Edit query             → Manual KQL entry → Continue     ║
║   [3] Cancel                 → Exit hunt                       ║
╚═════════════════════════════════════════════════════════════════╝
  ↓
┌═════════════════════════════════════════════════════════════════┐
║ STAGE 3: EXECUTION                                             ║
╠═════════════════════════════════════════════════════════════════╣
║ Execute KQL against Azure Log Analytics                        ║
║                                                                 ║
║ Results:                                                        ║
║   SUCCESS → results (CSV/JSON)                                ║
║   FAILURE → Offer retry or exit                               ║
╚═════════════════════════════════════════════════════════════════╝
  ↓
┌═════════════════════════════════════════════════════════════════┐
║ STAGE 4: ANALYSIS                                              ║
╠═════════════════════════════════════════════════════════════════╣
║ LLM analyzes query results:                                    ║
║   - Reviews results + flag objective                           ║
║   - Extracts answer                                            ║
║   - Provides reasoning                                         ║
║   - Auto-routes to Ollama/OpenAI                              ║
║                                                                 ║
║ FINDING:                                                        ║
║   ANSWER: 159.26.106.84                                       ║
║   EVIDENCE: First public IP after failures at 2025-09-14...   ║
║   REASONING: Matches brute-force pattern...                   ║
╚═════════════════════════════════════════════════════════════════╝
  ↓
┌═════════════════════════════════════════════════════════════════┐
║ STAGE 5: FLAG CAPTURE                                          ║
╠═════════════════════════════════════════════════════════════════╣
║ SUGGESTED: 159.26.106.84                                       ║
║                                                                 ║
║ Options:                                                        ║
║   [1] ✓ Accept this answer  → Capture flag                   ║
║   [2] ✗ Reject              → Recovery menu                   ║
╚═════════════════════════════════════════════════════════════════╝
  ↓                                   ↓
  ✓ ACCEPT                            ✗ REJECT
  ↓                                   ↓
  Enter notes (optional)              ┌─────────────────────────────┐
  ↓                                   │ REJECTION RECOVERY MENU     │
  ✓ FLAG CAPTURED                     ├─────────────────────────────┤
  ↓                                   │ [1] Build new query         │
  ↓                                   │     → Back to Stage 2      │
  ↓                                   │ [2] Re-analyze results      │
  ↓                                   │     → Back to Stage 4      │
  ↓                                   │ [3] Enter manually          │
  ↓                                   │     → Back to Stage 5      │
  ↓                                   │ [4] View raw results        │
  ↓                                   │     → Stay in recovery     │
  ↓                                   │ [5] Skip this flag          │
  ↓                                   │     → Exit hunt            │
  ↓                                   │ [6] Exit hunt               │
  ↓                                   │     → Exit hunt            │
  ↓                                   └─────────────────────────────┘
  ↓                                             ↓
  ↓ ←───────────────────────────────────────────┘
  ↓
┌═════════════════════════════════════════════════════════════════┐
║ STAGE 6: WHAT'S NEXT?                                          ║
╠═════════════════════════════════════════════════════════════════╣
║ SESSION MEMORY                                                  ║
║   ✓ Flag 1: 159.26.106.84                                     ║
║   Accumulated IOCs: 159.26.106.84                             ║
║                                                                 ║
║ Options:                                                        ║
║   [1] Rework current flag    → Back to Stage 2 for Flag 1     ║
║   [2] Work on next flag      → Stage 1 for Flag 2             ║
║   [3] Pause and exit         → Save & exit (resumable)        ║
║   [4] Finish hunt            → Completion flow                ║
╚═════════════════════════════════════════════════════════════════╝
  ↓
  ├─ [1] REWORK → Remove Flag 1 → Back to Stage 1
  ├─ [2] NEXT FLAG → Stage 1 for Flag 2
  ├─ [3] PAUSE → Save state (in_progress) → EXIT
  └─ [4] FINISH → Completion flow
        ↓
      ┌────────────────────────────────────────┐
      │ COMPLETION FLOW                        │
      ├────────────────────────────────────────┤
      │ Optional: Add detailed logic notes     │
      │ Generate final report                  │
      │ Mark session as 'completed'            │
      │ Save all files                         │
      │ Display summary                        │
      └────────────────────────────────────────┘
        ↓
      END
```

---

## 🎯 **Key Flow Features**

### **1. No Dead Ends**
- ✅ Every rejection has recovery options
- ✅ Every error has retry paths
- ✅ Can always pause and resume

### **2. Flexible Navigation**
- ✅ Can go back to any stage from recovery menu
- ✅ Can rework flags after completion
- ✅ Can skip difficult flags

### **3. State Preservation**
- ✅ All flags saved immediately
- ✅ IOCs accumulated across flags
- ✅ Session resumable at any point

### **4. Error Handling**
- ✅ LLM errors → Fallback or retry
- ✅ Query errors → Retry with new query
- ✅ Network errors → Graceful exit with save

---

## 📝 **Stage Transitions**

### **Normal Flow (Success Path):**
```
Stage 1 → Stage 2 → Stage 3 → Stage 4 → Stage 5 → Stage 6
  ↓         ↓         ↓         ↓         ↓         ↓
Intel → Query → Execute → Analyze → Capture → Next?
```

### **Rejection Recovery Flow:**
```
Stage 5 (Reject)
  ↓
Recovery Menu
  ├─ [1] → Stage 2 (new query)
  ├─ [2] → Stage 4 (re-analyze)
  ├─ [3] → Stage 5 (manual entry)
  ├─ [4] → Show results → Back to recovery
  ├─ [5] → Skip flag
  └─ [6] → Exit hunt
```

### **Rework Flow:**
```
Stage 6 → [1] Rework
  ↓
Remove last flag
  ↓
Stage 1 (same flag intel can be reused or new)
```

---

## ✅ **Connected Properly**

### **All Stages:**
| Stage | Input | Output | Error Path |
|-------|-------|--------|------------|
| **1. Intel Capture** | User input | flag_intel | Cancel → Exit |
| **2. Query Building** | flag_intel, session | KQL query | Cancel → Exit |
| **3. Execution** | KQL query | Results | Failure → Retry/Exit |
| **4. Analysis** | Results, flag_intel | Answer | N/A (always returns) |
| **5. Capture** | Answer | True/False | Reject → Recovery |
| **6. What's Next** | Session state | Action | Interrupt → Pause |

### **All Actions:**
| Action | Trigger | Next State |
|--------|---------|-----------|
| **Accept** | Stage 5 [1] | Stage 6 |
| **Reject** | Stage 5 [2] | Recovery Menu |
| **New Query** | Recovery [1] | Stage 2 |
| **Re-analyze** | Recovery [2] | Stage 4 |
| **Manual** | Recovery [3] | Stage 5 |
| **View Raw** | Recovery [4] | Recovery Menu |
| **Skip** | Recovery [5] | Exit hunt |
| **Rework** | Stage 6 [1] | Stage 1 |
| **Next Flag** | Stage 6 [2] | Stage 1 |
| **Pause** | Stage 6 [3] | Save & Exit |
| **Finish** | Stage 6 [4] | Completion |

---

## 🚀 **Ready to Use!**

**All stages are now connected with:**
- ✅ No missing transitions
- ✅ No dead ends
- ✅ Proper error handling
- ✅ Recovery options at every failure point
- ✅ State persistence throughout
- ✅ Clean exit paths

**The CTF Hunt Mode flow is complete and robust!** 🎯✅

