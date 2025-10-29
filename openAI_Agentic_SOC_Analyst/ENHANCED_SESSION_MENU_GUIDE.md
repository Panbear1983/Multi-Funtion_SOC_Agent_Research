# 🔄 Enhanced Session Resume Menu - User Guide

## 🎯 New Features Added

✅ **Multi-level navigation menu**
✅ **Project renaming capability**
✅ **Back navigation at each level**
✅ **Auto-update all files on rename**

---

## 📋 Complete Menu Flow

### **Level 1: Main Session Menu**

```
══════════════════════════════════════════════════════════════════════
🔄 EXISTING SESSIONS FOUND
══════════════════════════════════════════════════════════════════════

You have 3 unfinished investigation(s):

  • RDP Password Spray (3 flags)
  • Operation Lurker (5 flags)
  • BlueTeam CTF Challenge (2 flags)

[C] Continue with existing hunts  ← Shows project list
[N] Start new investigation        ← Create new

Select [C/N]: _
```

**Options:**
- **[C]** → Go to Level 2 (Project List)
- **[N]** → Create new investigation

---

### **Level 2: Project Selection**

```
══════════════════════════════════════════════════════════════════════
📋 SELECT INVESTIGATION TO RESUME
══════════════════════════════════════════════════════════════════════

[1] RDP Password Spray
    Flags: 3

[2] Operation Lurker
    Flags: 5

[3] BlueTeam CTF Challenge
    Flags: 2

[B] Back  ← Returns to Level 1

Select [1-3/B]: _
```

**Options:**
- **[1-3]** → Go to Level 3 (Project Actions)
- **[B]** → Back to Level 1

---

### **Level 3: Project Actions**

```
══════════════════════════════════════════════════════════════════════
📂 SELECTED: RDP Password Spray
══════════════════════════════════════════════════════════════════════

Flags completed: 3

[1] Continue hunt   ← Resume hunting
[2] Rename project  ← Rename + update files
[B] Back to session list  ← Returns to Level 2

Select [1-2/B]: _
```

**Options:**
- **[1]** → Continue hunt (loads session)
- **[2]** → Rename project menu
- **[B]** → Back to Level 2

---

## 🔄 Navigation Examples

### **Example 1: Resume Existing Hunt**

```
Step 1 (Level 1):
  Select [C/N]: C

Step 2 (Level 2):
  Select [1-3/B]: 1

Step 3 (Level 3):
  Select [1-2/B]: 1

→ ✓ Resumed: RDP Password Spray
  Flags captured so far: 3
  
  [Hunt continues...]
```

---

### **Example 2: Rename Project**

```
Step 1 (Level 1):
  Select [C/N]: C

Step 2 (Level 2):
  Select [1-3/B]: 1

Step 3 (Level 3):
  Select [1-2/B]: 2

══════════════════════════════════════════════════════════════════════
📝 RENAME PROJECT
══════════════════════════════════════════════════════════════════════

Current name: RDP Password Spray

New project name: Hide Your RDP - Full Compromise

✓ Project renamed to: Hide Your RDP - Full Compromise
✓ Files updated:
  • ctf_sessions/Hide_Your_RDP_Full_Compromise_summary.json
  • ctf_sessions/Hide_Your_RDP_Full_Compromise_20251010_100000.jsonl
  • ctf_sessions/Hide_Your_RDP_Full_Compromise_report.md

══════════════════════════════════════════════════════════════════════
📂 SELECTED: Hide Your RDP - Full Compromise  ← Updated name!
══════════════════════════════════════════════════════════════════════

[1] Continue hunt
[2] Rename project
[B] Back to session list

Select [1-2/B]: 1  ← Continue with renamed project

→ ✓ Resumed: Hide Your RDP - Full Compromise
  [Hunt continues...]
```

---

### **Example 3: Navigate Back**

```
Step 1 (Level 1):
  Select [C/N]: C

Step 2 (Level 2):
  Select [1-3/B]: 1

Step 3 (Level 3):
  Select [1-2/B]: B  ← Go back

→ Returns to Level 2 (Project List)

Step 2 again:
  Select [1-3/B]: 2  ← Select different project

Step 3:
  Select [1-2/B]: 1  ← Continue

→ ✓ Resumed: Operation Lurker
```

---

### **Example 4: Start New Instead**

```
Step 1 (Level 1):
  Select [C/N]: N  ← Start new

══════════════════════════════════════════════════════════════════════
🎯 CTF INVESTIGATION - NEW SESSION
══════════════════════════════════════════════════════════════════════

Project Name: New Investigation Oct 2025

✓ Project: New Investigation Oct 2025

[New hunt begins...]
```

---

## 🎯 What Happens When You Rename

### **Files Updated:**

**Before:**
```
ctf_sessions/
├── RDP_Password_Spray_20251010_100000.jsonl
├── RDP_Password_Spray_summary.json
└── RDP_Password_Spray_report.md
```

**After Rename to "Hide Your RDP Attack":**
```
ctf_sessions/
├── Hide_Your_RDP_Attack_20251010_100000.jsonl  ← Renamed
├── Hide_Your_RDP_Attack_summary.json           ← Renamed
└── Hide_Your_RDP_Attack_report.md              ← Renamed
```

### **JSON State Updated:**

**summary.json:**
```json
{
  "project_name": "Hide Your RDP Attack",  ← Updated!
  "flags_completed": 3,
  "status": "in_progress",
  ...
}
```

**Event log (.jsonl):**
- File renamed, contents preserved
- All historical events maintained

**Report (.md):**
- File renamed
- Report contents preserved

---

## ✅ Key Features

| Feature | Works? | Description |
|---------|--------|-------------|
| **Multi-level navigation** | ✅ | Navigate through 3 menu levels |
| **Back button** | ✅ | Go back at any level |
| **Project renaming** | ✅ | Rename project + update files |
| **File sync** | ✅ | All files renamed automatically |
| **JSON update** | ✅ | State updated with new name |
| **Resume after rename** | ✅ | Continue hunt with new name |
| **Cancel rename** | ✅ | Press Enter to keep old name |

---

## 🎯 Usage Tips

### **Quick Resume:**
```
[C] → [1] → [1]
(3 keystrokes to resume first hunt)
```

### **Rename First Project:**
```
[C] → [1] → [2] → Enter new name → [1]
```

### **Browse Projects:**
```
[C] → [1] → [B] → [2] → [B] → [3] → [1]
(Navigate between projects freely)
```

### **Start Fresh:**
```
[N] → Enter project name
(Skip all menus, create new)
```

---

## 🚀 Ready to Use!

**The enhanced menu system is now active!**

Every time you run CTF mode with existing sessions, you'll see:
1. ✅ Summary of all unfinished hunts
2. ✅ Option to continue or start new
3. ✅ Detailed project selection
4. ✅ Per-project actions (continue/rename)
5. ✅ Full back navigation

**Much better UX for managing multiple CTF investigations!** 🎯✅

