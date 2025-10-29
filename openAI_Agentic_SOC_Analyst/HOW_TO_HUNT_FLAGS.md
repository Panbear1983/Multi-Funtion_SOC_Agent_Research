# 🎯 How to Hunt Flags - Step-by-Step Guide

## 📋 **Complete Instructions for Moving Through All Stages**

---

## 🚀 **Starting a Hunt**

### **Step 1: Run the Program**
```bash
python3 _main.py
```

### **Step 2: Select CTF Mode**
```
SELECT INVESTIGATION MODE:
[1] THREAT HUNTING
[2] ANOMALY DETECTION
[3] CTF MODE - Interactive Flag Hunting  ← Type 3 and Enter
[4] Exit

Select mode [1-4]: 3
```

### **Step 3: Select Model**
```
SELECT LANGUAGE MODEL:
[1] gpt-4.1-nano
[2] gpt-4.1
[3] gpt-5-mini (Default)
[4] gpt-5
[5] qwen
[6] gpt-oss:20b  ← Your local model

Select model [1-6]: 6
```

### **Step 4: Select Severity**
```
SELECT INVESTIGATION SEVERITY LEVEL:
[1] CRITICAL
[2] STRICT
[3] NORMAL (Default)
[4] RELAXED

Select mode [1-4]: 1
```

### **Step 5: Enter Project Name (New Session)**
```
Enter a name for this CTF investigation:

Project Name: Hide Your RDP - Password Spray Attack

✓ Project: Hide Your RDP - Password Spray Attack
```

**OR Resume Existing Session:**
```
EXISTING SESSIONS FOUND

[C] Continue with existing hunts  ← Type C
[N] Start new investigation

Select [C/N]: C
```

---

## 🏆 **Hunting Flags - The 6 Stages**

### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**
### **STAGE 1: FLAG INTEL CAPTURE** 📋
### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**

**What You See:**
```
══════════════════════════════════════════════════════════════════════
📋 FLAG INTEL CAPTURE
══════════════════════════════════════════════════════════════════════

Paste the flag objective and any hints/intel you have.
Include:
  • Flag title/question
  • Objective (what you're looking for)
  • Hints, guidance, MITRE techniques
  • Expected format
Type 'DONE' on a new line when finished

Example:
──────────────────────────────────────────────────────────────────────
🚩 Flag 1: Attacker IP Address
MITRE: T1110.001 - Brute Force
Objective: Find external IP that logged in after brute-force
Hint: Look for failed logins followed by success
Format: xxx.xxx.xxx.xxx
DONE
──────────────────────────────────────────────────────────────────────

[Cursor waiting for input]
```

**What You Do:**

1. **Copy the flag description** from your CTF platform
2. **Paste it** into the terminal
3. **Press Enter** after pasting
4. **Type `DONE`** on a new line
5. **Press Enter** to proceed

**Example Input:**
```bash
# Copy this from your CTF platform and paste it:
🚩 Flag 1: Attacker IP Address
MITRE: T1110.001 – Brute Force: Password Guessing
Objective: Identify the external IP address that successfully logged in via RDP
Hint: Look for failed logins followed by success
Format: xxx.xxx.xxx.xxx

# Then type this:
DONE
```

**What to Type:**
```
[Paste flag info here]
DONE  ← Type exactly this and press Enter
```

**Result:**
```
✓ Flag intel captured
Title: Attacker IP Address
Objective: Identify the external IP address...

[Moves to Stage 2]
```

---

### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**
### **STAGE 2: QUERY BUILDING** 🔨
### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**

**What You See:**
```
══════════════════════════════════════════════════════════════════════
🔨 BUILDING QUERY
══════════════════════════════════════════════════════════════════════

Selected model is valid: gpt-oss:20b

🤖 Generating KQL query with gpt-oss:20b...

[Using local Ollama model]

SUGGESTED QUERY:

DeviceLogonEvents
| where Timestamp between (datetime(2025-09-13) .. datetime(2025-09-22))
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| project Timestamp, RemoteIP, AccountName, ActionType

──────────────────────────────────────────────────────────────────────

  [1] Execute this query
  [2] Edit query
  [3] Cancel

Select [1-3]: _
```

**What You Do:**

**Option A: Use LLM's Query (Recommended) ✅**
```bash
# What to type:
1

# Then press Enter
```
→ Proceeds to Stage 3

**Option B: Edit/Write Custom Query**
```bash
# What to type:
2

# Then the system shows:
# Enter your KQL (type DONE when finished):

# Type your custom query:
DeviceLogonEvents
| where RemoteIP != ""
| where ActionType == "LogonSuccess"
| take 10

# Then type:
DONE
```

**Example Edit Session:**
```bash
Select [1-3]: 2  ← Type this

Enter your KQL (type DONE when finished):

KQL > DeviceLogonEvents                    ← Your query line 1
KQL > | where Timestamp > ago(24h)         ← Line 2
KQL > | where RemoteIPType == "Public"     ← Line 3
KQL > | project Timestamp, RemoteIP        ← Line 4
KQL > DONE                                 ← Type DONE to finish

✓ Custom query saved
[Proceeds to Stage 3]
```

**Option C: Cancel**
```bash
# What to type:
3

# Then press Enter
# [Exits hunt]
```

---

### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**
### **STAGE 3: EXECUTION** ⚡
### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**

**What You See:**
```
══════════════════════════════════════════════════════════════════════
⚡ EXECUTING QUERY
══════════════════════════════════════════════════════════════════════

Running KQL against Azure Log Analytics...

✓ Query executed successfully
✓ 45 results returned

RESULTS (first 10 rows):
Timestamp                    RemoteIP        AccountName    ActionType
2025-09-14 03:45:12         159.26.106.84   slflare       LogonSuccess
2025-09-14 04:12:33         159.26.106.84   admin         LogonSuccess
...

[Automatically proceeds to Stage 4]
```

**What You Do:**

**Nothing!** Stage 3 is automatic. The query executes and results are displayed.

**If Query Fails:**
```
❌ Query failed: [Error message]

Query failed. Retry this flag? [Y/n]: Y  ← Type Y to retry, N to exit
```

---

### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**
### **STAGE 4: ANALYSIS** 🧠
### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**

**What You See:**
```
══════════════════════════════════════════════════════════════════════
🧠 ANALYZING RESULTS
══════════════════════════════════════════════════════════════════════

The LLM will analyze the query results and suggest an answer.

Press [Enter] for LLM analysis... _
```

**What You Do:**
```bash
# Just press Enter - nothing to type!
[Press Enter key]
```

**💡 What Happens:**
1. **LLM reads the query results** (the data from Stage 3)
2. **LLM reads the flag objective** (what you're looking for)
3. **LLM analyzes and extracts the answer**
4. **Displays findings** automatically

**Example Analysis Output:**
```
Analyzing with gpt-oss:20b...

FINDING:

ANSWER: 159.26.106.84

EVIDENCE: This IP appears in the earliest successful RDP login on 
2025-09-14 at 03:45:12, following multiple failed login attempts 
from the same IP between 03:40:12 and 03:44:58.

REASONING: The query results show this pattern:
  - 03:40:12 - 159.26.106.84 - LogonFailed (slflare)
  - 03:41:23 - 159.26.106.84 - LogonFailed (slflare)
  - 03:43:15 - 159.26.106.84 - LogonFailed (slflare)
  - 03:45:12 - 159.26.106.84 - LogonSuccess (slflare) ✓

This matches the brute-force pattern described in the objective.

──────────────────────────────────────────────────────────────────────

[Automatically proceeds to Stage 5]
```

**🎯 Key Point:**
- **You don't type anything at this stage**
- **Just press Enter once** to start the analysis
- **LLM does all the work** automatically
- **Wait for the suggested answer** to appear

---

### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**
### **STAGE 5: FLAG CAPTURE** 🎯
### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**

**What You See:**
```
══════════════════════════════════════════════════════════════════════
🎯 FLAG ANSWER
══════════════════════════════════════════════════════════════════════

SUGGESTED: 159.26.106.84

  [1] ✓ Accept this answer
  [2] ✗ Reject (show recovery options)

Select [1-2]: _
```

**What You Do:**

**Option A: Accept the Answer ✅**
```bash
# What to type:
1

# Then press Enter
# System asks for optional notes:
Notes (optional): First successful login after multiple failed attempts

# Or just press Enter to skip notes
```

**Full Example - Accept:**
```
Select [1-2]: 1  ← Type this

Notes (optional): Verified from logs - brute force pattern  ← Optional
# Or just press Enter to skip

══════════════════════════════════════════════════════════════════════
✓ FLAG 1 CAPTURED: 159.26.106.84
══════════════════════════════════════════════════════════════════════

[Proceeds to Stage 6]
```

**Option B: Reject the Answer ❌**
```bash
# What to type:
2

# Then press Enter
[Shows Recovery Menu - see below]
```

---

### **🔄 REJECTION RECOVERY MENU** (If You Reject)

```
══════════════════════════════════════════════════════════════════════
⚠️  ANSWER REJECTED - RECOVERY OPTIONS
══════════════════════════════════════════════════════════════════════

  [1] 🔨 Build new query (start from Stage 2)
  [2] 🧠 Re-analyze same results (new LLM analysis)
  [3] ✍️  Enter answer manually
  [4] 👁️  View raw results
  [5] ⏭️  Skip this flag
  [6] 🚪 Exit hunt

Select [1-6]: _
```

**Your Options:**

| Choice | What Happens | Goes To |
|--------|--------------|---------|
| **1** | Build new KQL query | Stage 2 |
| **2** | Re-run LLM analysis on same results | Stage 4 |
| **3** | Type answer manually, then capture | Stage 5 |
| **4** | Display full raw results, then back to menu | Recovery Menu |
| **5** | Skip this flag, exit hunt | Exit |
| **6** | Exit hunt immediately | Exit |

**Example 1 - Build New Query:**
```bash
# What to type:
1

# Then press Enter
# [Returns to Stage 2 - Query Building]
# You can now build a better query
```

**Example 2 - Re-analyze:**
```bash
# What to type:
2

# Then press Enter
# [Returns to Stage 4 - Analysis runs again with new LLM call]
```

**Example 3 - Enter Manually:**
```bash
# What to type:
3

# Then press Enter
# System prompts:
Enter answer manually: 159.26.106.84  ← Type the correct answer

Notes (optional): Verified manually from raw data  ← Optional

✓ FLAG 1 CAPTURED
[Proceeds to Stage 6]
```

**Example 4 - View Raw Results:**
```bash
# What to type:
4

# Then press Enter
# Shows full query results (first 2000 chars)
# Press Enter to return to recovery menu
```

---

### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**
### **STAGE 6: WHAT'S NEXT?** 🎯
### **━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━**

**What You See:**
```
══════════════════════════════════════════════════════════════════════
📚 SESSION MEMORY
══════════════════════════════════════════════════════════════════════

Flags Captured: 1

  ✓ 🚩 Flag 1: Attacker IP Address: 159.26.106.84

Accumulated IOCs:
  • Ips: 159.26.106.84

══════════════════════════════════════════════════════════════════════
WHAT'S NEXT?
══════════════════════════════════════════════════════════════════════

  [1] 🔄 Rework current flag (different query/approach)
      → Build new query for same flag, overwrite if different answer

  [2] ➡️  Work on next flag
      → Start a new flag investigation

  [3] 💾 Pause and exit
      → Save progress and exit cleanly (resume anytime)

  [4] 🏁 Finish hunt (complete investigation)
      → Generate reports, add detailed notes, mark as done

Select [1-4]: _
```

**What You Do:**

| Choice | What Happens | Next |
|--------|--------------|------|
| **1** | Rework Flag 1 with new approach | Removes Flag 1 → Stage 1 |
| **2** | Hunt Flag 2 | Stage 1 for next flag |
| **3** | Save and exit (resume later) | Exit (resumable) |
| **4** | Finish and generate report | Completion flow |

**Example 1 - Continue to Next Flag (Most Common):**
```bash
# What to type:
2

# Then press Enter
# [Returns to Stage 1 for Flag 2]
```

**Full Example - Next Flag:**
```
Select [1-4]: 2  ← Type this

[Returns to Stage 1 for Flag 2]

══════════════════════════════════════════════════════════════════════
📋 FLAG INTEL CAPTURE
══════════════════════════════════════════════════════════════════════

Paste your flag objective...

🚩 Flag 2: Compromised Account Name  ← Paste Flag 2 info
Objective: Identify the compromised account used in the attack
Hint: Check successful logins after brute force
Format: username
DONE  ← Type DONE when finished
```

**Example 2 - Rework Current Flag:**
```bash
# What to type:
1

# Then press Enter
# Removes Flag 1 from session
# Returns to Stage 1 to re-hunt same flag with different approach
```

**Example 3 - Pause and Exit:**
```bash
# What to type:
3

# Then press Enter
```

**Full Example - Pause:**
```
Select [1-4]: 3  ← Type this

💾 Pausing investigation...

✓ Session paused. You can resume later.

💾 Session saved
✓ State: ctf_sessions/Hide_Your_RDP_summary.json
✓ Event log: ctf_sessions/Hide_Your_RDP_20251010.jsonl

Session paused. Resume anytime by selecting CTF mode again.

[Program exits - you can resume later by running python3 _main.py]
```

**Example 4 - Finish Hunt:**
```bash
# What to type:
4

# Then press Enter
```

**Full Example - Finish:**
```
Select [1-4]: 4  ← Type this

══════════════════════════════════════════════════════════════════════
🏁 FINISHING HUNT
══════════════════════════════════════════════════════════════════════

All flags captured successfully!

📊 SESSION SUMMARY:
  • Total flags captured: 10
  • Project: Hide Your RDP - Password Spray Attack
  • Duration: 2h 15m

✓ Report generated: ctf_sessions/Hide_Your_RDP_report.md
✓ Session marked as completed

[Hunt complete! Well done! 🎉]
```

---

## 📝 **Quick Reference**

### **Moving Through Stages (Normal Flow):**

```bash
1. INTEL CAPTURE
   → Paste flag info
   → Type: DONE
   → Press: Enter

2. QUERY BUILDING  
   → Type: 1  (to execute LLM's query)
   → Press: Enter

3. EXECUTION
   → Nothing to type (automatic)
   → Just watch the query run

4. ANALYSIS
   → Press: Enter  (just once)
   → Wait for LLM analysis

5. FLAG CAPTURE
   → Type: 1  (to accept answer)
   → Press: Enter
   → Add notes (optional) or just press Enter

6. WHAT'S NEXT
   → Type: 2  (for next flag)
   → Press: Enter
   
→ Loop back to Stage 1 for next flag!
```

### **Quick Cheat Sheet:**

| Stage | What to Type | Then Press |
|-------|-------------|------------|
| 1. Intel | `[paste flag]` then `DONE` | Enter |
| 2. Query | `1` | Enter |
| 3. Execute | Nothing (automatic) | N/A |
| 4. Analyze | Nothing (just press Enter) | Enter |
| 5. Capture | `1` | Enter |
| 6. Next | `2` | Enter |

### **If You Reject at Stage 5:**
```
Recovery Menu appears:
[1] New query    → Back to Stage 2
[2] Re-analyze   → Back to Stage 4
[3] Manual entry → Back to Stage 5
[4] View raw     → Stay in recovery
[5] Skip flag    → Exit
[6] Exit         → Exit
```

### **At Stage 6 (After Flag Captured):**
```
[1] Rework this flag → Stage 1 (same flag)
[2] Next flag        → Stage 1 (new flag)
[3] Pause & exit     → Save and quit
[4] Finish hunt      → Complete
```

---

## ✅ **Key Points**

### **When to Type DONE:**
- ✅ **Stage 1** - After pasting flag intel
- ✅ **Stage 2** - Only if you selected [2] Edit query
- ❌ **Never** at the "Select [1-3]" prompt

### **What Happens Automatically:**
- ✅ **Stage 3** - Query executes automatically
- ✅ **Stage 4** - Analysis runs after you press Enter
- ✅ **Transitions** - Stages flow into each other

### **How to Save:**
- ✅ **Auto-save** - After each flag capture
- ✅ **Manual save** - Select [3] Pause and exit at Stage 6

### **How to Resume:**
1. Run `python3 _main.py`
2. Select CTF mode
3. Choose model/severity
4. Select [C] Continue
5. Pick your paused session
6. Select [1] Continue hunt

---

## 🎯 **You're Ready!**

**Follow these steps and you'll smoothly move through all stages of flag hunting!** 🚀✅

