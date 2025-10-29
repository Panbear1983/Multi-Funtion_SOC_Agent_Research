# 🗑️ Flag Deletion Feature - Complete Guide

## ✅ **Feature Implemented!**

You can now delete the last captured flag and redo it from scratch.

---

## 📍 **Where to Find It**

### **"What's Next?" Menu**

After documenting a flag, you'll see:

```
══════════════════════════════════════════════════════════════════════
WHAT'S NEXT?
══════════════════════════════════════════════════════════════════════

  [1] ➡️  Work on next flag
      → Start investigating the next flag

  [2] 💾 Save and exit
      → Pause investigation, resume later

  [3] 🏁 Finish hunt
      → Add detailed logic notes and complete investigation

  [4] 🗑️  Delete last flag and redo    ← NEW!
      → Remove Flag 5 and start over on it

Select [1-4]: _
```

**Note:** Option [4] only appears if you have at least 1 completed flag.

---

## 🎯 **How It Works**

### **Step 1: Select Delete Option**

```
Select [1-4]: 4

⚠️  WARNING: Delete Flag 5?
  • All data for Flag 5 will be permanently removed
  • You'll return to Flag 5 intel capture stage
  • This action cannot be undone

Continue? [y/N]: _
```

### **Step 2: Confirm Deletion**

**Confirm:**
```
Continue? [y/N]: y

✓ Flag 5 deleted successfully
↩️  Returning to Flag 5 hunt...

[Returns to Flag 5 Intel Capture stage]
```

**Cancel:**
```
Continue? [y/N]: n

Deletion cancelled

[Returns to "What's Next?" menu]
```

---

## 📂 **What Gets Deleted**

### **From session_summary.json:**

**Before:**
```json
{
  "flags_completed": 5,
  "current_flag": 6,
  "flags_captured": [
    {"flag_number": 1, "answer": "159.26.106.84", ...},
    {"flag_number": 2, "answer": "slflare", ...},
    {"flag_number": 3, "answer": "msupdate.exe", ...},
    {"flag_number": 4, "answer": "...", ...},
    {"flag_number": 5, "answer": "backup_sync.zip", ...}
  ]
}
```

**After (Flag 5 deleted):**
```json
{
  "flags_completed": 4,
  "current_flag": 5,
  "flags_captured": [
    {"flag_number": 1, "answer": "159.26.106.84", ...},
    {"flag_number": 2, "answer": "slflare", ...},
    {"flag_number": 3, "answer": "msupdate.exe", ...},
    {"flag_number": 4, "answer": "...", ...}
    // Flag 5 completely removed!
  ]
}
```

### **In current_session.jsonl:**

**Deletion event is logged:**
```json
{"event": "flag_deleted", "flag_number": 5, "deleted_at": "2025-10-13T16:30:00", "reason": "User requested deletion"}
```

**Previous events are preserved** (audit trail intact).

### **In investigation_report.md:**

**Flag 5 section is removed** from the report.

---

## 🔄 **What Happens Next**

### **You're Back at Flag 5 Hunt:**

```
══════════════════════════════════════════════════════════════════════
📋 FLAG 5 INTEL CAPTURE
══════════════════════════════════════════════════════════════════════

Paste your flag intel below (scenario, objective, MITRE, etc.)
Type 'DONE' when finished:

Flag > _  ← Start fresh!
```

**Complete flow:**
1. Paste new/corrected intel
2. Bot interprets
3. You write KQL
4. Execute query
5. Analyze results
6. Document findings
7. "What's Next?" menu appears again

---

## 💡 **Use Cases**

### **1. Wrong Answer Documented**
```
Flag 5: You documented "wrong_file.zip" 
→ Delete Flag 5
→ Redo the hunt
→ Find correct answer: "backup_sync.zip"
```

### **2. Wrong Table Queried**
```
Flag 6: You queried DeviceLogonEvents (no results)
→ Delete Flag 6
→ Redo the hunt
→ Query DeviceProcessEvents instead
```

### **3. Incomplete Analysis**
```
Flag 3: You rushed and missed important IOCs
→ Delete Flag 3
→ Redo with more thorough analysis
→ Capture all IOCs properly
```

### **4. Duplicate Flag**
```
Flag 7: You accidentally documented the same as Flag 6
→ Delete Flag 7
→ Start fresh on the real Flag 7
```

---

## ⚠️ **Important Notes**

### **1. Only Last Flag**
- ✅ Can delete: Most recent flag only (Flag 5 if you've completed 5)
- ❌ Cannot delete: Flag 3 when you've completed 5 flags
- **Reason:** Prevents breaking the sequence

### **2. Permanent Deletion**
- ✅ Removes flag from JSON completely
- ✅ Regenerates report without that flag
- ❌ Cannot undo (no "restore" feature)
- **Tip:** Save & exit before deleting if unsure

### **3. Audit Trail**
- ✅ Deletion event logged in `.jsonl` file
- ✅ Can see what was deleted and when
- ✅ Useful for review/compliance

### **4. IOCs Not Restored**
```json
"accumulated_iocs": {
  "ips": ["159.26.106.84", "185.92.220.87"],
  ...
}
```
**Note:** Accumulated IOCs from deleted flags are NOT automatically removed.  
**Why:** They might still be relevant for correlation.

---

## 📋 **Example Workflow**

### **Scenario: Flag 5 has wrong answer**

```
1. Complete Flag 5 with answer "wrong.zip" ✓

2. What's Next menu appears

3. Select [4] Delete last flag

4. Confirm deletion: y

   ✓ Flag 5 deleted successfully
   ↩️  Returning to Flag 5 hunt...

5. Back at Flag 5 Intel Capture:
   
   Flag > [Paste corrected intel]
   Flag > DONE

6. Bot interpretation → Human KQL → Execute → Analyze → Document

7. Enter correct answer: "backup_sync.zip" ✓

8. Flag 5 now has correct data!

9. What's Next menu → [1] Work on next flag (Flag 6)
```

---

## 🎯 **Quick Reference**

| Action | Shortcut | Result |
|--------|----------|--------|
| **Delete last flag** | Type `4` at "What's Next?" | Removes most recent flag |
| **Confirm deletion** | Type `y` at warning | Deletes flag permanently |
| **Cancel deletion** | Type `n` at warning | Returns to menu |
| **Redo flag** | After deletion | Returns to intel capture |

---

## ✅ **Summary**

**What Changed:**
- ✅ New option [4] in "What's Next?" menu
- ✅ Confirmation prompt before deletion
- ✅ Complete removal from JSON files
- ✅ Report regenerated without deleted flag
- ✅ Returns to intel capture for that flag

**What's Safe:**
- ✅ All other flags remain intact
- ✅ Session progress preserved
- ✅ Audit trail maintained
- ✅ Can continue hunt normally

---

## 🚀 **Test It Now!**

**Current Status:**
- Your hunt: 5 flags completed
- You're working on Flag 6

**To test deletion:**
1. Complete Flag 6 (or use existing Flag 5)
2. At "What's Next?" menu, select [4]
3. Confirm with `y`
4. Redo the flag properly
5. Continue your hunt!

**Ready to use!** 🎯✅

