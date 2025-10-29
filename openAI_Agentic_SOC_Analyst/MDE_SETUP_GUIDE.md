# 🔐 MDE Setup Guide - Where to Paste Your Credentials

## ✅ **MDE Support is Now Integrated!**

---

## 📍 **WHERE TO PASTE YOUR MDE CREDENTIALS**

### **Open this file:**
```
/Users/peter/Desktop/Old_Projects/GitHub/Multi-Funtion_SOC_Agent_Research/openAI_Agentic_SOC_Analyst/_keys.py
```

### **You'll see this section (lines 10-14):**

```python
# ═══════════════════════════════════════════════════════════════════════════
# Microsoft Defender for Endpoint (MDE) - Advanced Hunting API
# ═══════════════════════════════════════════════════════════════════════════
# 👉 PASTE YOUR MDE CREDENTIALS HERE:

MDE_TENANT_ID = "YOUR_TENANT_ID_HERE"        # ← REPLACE THIS
MDE_CLIENT_ID = "YOUR_CLIENT_ID_HERE"        # ← REPLACE THIS
MDE_CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"  # ← REPLACE THIS
```

---

## ✏️ **PASTE YOUR VALUES:**

### **Replace the placeholder text with your actual values:**

**Before:**
```python
MDE_TENANT_ID = "YOUR_TENANT_ID_HERE"
MDE_CLIENT_ID = "YOUR_CLIENT_ID_HERE"
MDE_CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"
```

**After (example format):**
```python
MDE_TENANT_ID = "12345678-1234-1234-1234-123456789abc"
MDE_CLIENT_ID = "87654321-4321-4321-4321-cba987654321"
MDE_CLIENT_SECRET = "AbC~123XyZ456_VeryLongSecretStringHere789"
```

**⚠️ Keep the quotes!** Just replace the text inside the quotes.

---

## 🎯 **What You Have:**

From your Azure App Registration, you should have:

```
1. Directory (tenant) ID:
   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   👆 Paste into MDE_TENANT_ID

2. Application (client) ID:
   yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
   👆 Paste into MDE_CLIENT_ID

3. Client secret value:
   zZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZ~abc123
   👆 Paste into MDE_CLIENT_SECRET
```

---

## ✅ **After Pasting:**

### **Your _keys.py should look like:**

```python
# Get your API Key: https://platform.openai.com/settings/organization/api-keys
OPENAI_API_KEY = "sk-proj-rDDprNQtLxEjSKD5UWTTbHVdaNgFVFIEjCKycZztkgO75kX2svS7dsGzIBC..."

# Azure Sentinel / Log Analytics
LOG_ANALYTICS_WORKSPACE_ID = "60c7f53e-249a-4077-b68e-55a4ae877d7c"

# ═══════════════════════════════════════════════════════════════════════════
# Microsoft Defender for Endpoint (MDE) - Advanced Hunting API
# ═══════════════════════════════════════════════════════════════════════════
# 👉 PASTE YOUR MDE CREDENTIALS HERE:

MDE_TENANT_ID = "12345678-1234-1234-1234-123456789abc"                    # ✅ PASTED
MDE_CLIENT_ID = "87654321-4321-4321-4321-cba987654321"                    # ✅ PASTED
MDE_CLIENT_SECRET = "AbC~123XyZ456_VeryLongSecretStringHere789"          # ✅ PASTED
```

**Save the file!**

---

## 🚀 **How It Works Now**

### **When You Run the Tool:**

```bash
python3 _main.py
```

### **You'll See (NEW!):**

```
SELECT INVESTIGATION MODE:
[1] THREAT HUNTING
[2] ANOMALY DETECTION
[3] CTF MODE - Interactive Flag Hunting
[4] Exit

Select mode [1-4]: 3

[Model selection...]
[Severity selection...]

══════════════════════════════════════════════════════════════════════
SELECT DATA SOURCE
══════════════════════════════════════════════════════════════════════

[1] Microsoft Defender for Endpoint (MDE) ← Recommended
    • All tables available (DeviceRegistryEvents included!)
    • Real-time data (no ingestion delay)
    • Free (included in MDE license)
    • Best for CTF hunting

[2] Azure Sentinel / Log Analytics
    • Configured tables only
    • Multi-source correlation
    • Long-term storage

Select data source [1-2] (default: 1): _  ← Just press Enter for MDE!
```

---

## ⌨️ **Data Source Selection:**

### **Option 1: Use MDE (Default)** ✅
```
Select data source [1-2] (default: 1): [Press Enter]

OR

Select data source [1-2] (default: 1): 1

✓ Using MDE Advanced Hunting
✓ MDE client initialized

[Hunt begins with ALL tables available!]
```

### **Option 2: Use Azure Sentinel**
```
Select data source [1-2] (default: 1): 2

✓ Using Azure Sentinel

[Hunt begins with configured tables only]
```

---

## 🔄 **Easy Switching:**

### **Per Session:**
Each time you start a hunt, you choose:
- Press Enter = MDE (default)
- Type 2 = Sentinel

### **Saved Hunts:**
Your progress is saved regardless of data source!
```
Flags 1-2: Queried from Sentinel ✓
[Save & Exit]
[Resume later]
[Select MDE this time]
Flags 3+: Queried from MDE ✓
```

**Completely transparent!**

---

## 🎯 **What Changed in the Code:**

### **New Files:**
1. ✅ `MDE_CLIENT.py` - MDE Advanced Hunting client

### **Modified Files:**
1. ✅ `_keys.py` - Added MDE credential section (← YOU PASTE HERE!)
2. ✅ `_main.py` - Added data source selector
3. ✅ `CTF_HUNT_MODE.py` - Accepts data_source parameter

### **Unchanged (Your Progress is Safe!):**
1. ✅ `CTF_SESSION_MANAGER.py` - No changes
2. ✅ Session JSON files - No changes
3. ✅ All hunt logic - No changes
4. ✅ All other modules - No changes

---

## ✅ **Testing Checklist:**

### **Step 1: Paste Credentials**
```
Open: _keys.py
Find lines 12-14
Paste your 3 MDE values
Save file
```

### **Step 2: Test Connection**
```bash
python3 _main.py
[3] CTF MODE
Select data source [1-2]: 1

# Should see:
✓ MDE client initialized  ← Success!

# If error:
Failed to initialize MDE client: [error message]
→ Check your credentials
→ Verify app permissions granted
```

### **Step 3: Test Query**
```
[Create or resume hunt]
[Enter flag intel]
[Write KQL query with DeviceRegistryEvents]
[Execute]

# Should now return results! ✓
```

---

## 🔧 **If You Get Errors:**

### **Error: "invalid_client"**
```
Problem: Wrong CLIENT_ID or CLIENT_SECRET
Fix: Double-check you copied them correctly from Azure Portal
```

### **Error: "unauthorized_client"**
```
Problem: App permissions not granted
Fix: Go to app → API permissions → Grant admin consent (green checkmarks)
```

### **Error: "invalid_resource"**
```
Problem: Wrong API scope
Fix: Verify permission is "AdvancedHunting.Read.All" (not Delegated permissions)
```

---

## 📋 **Quick Reference:**

| What | Where | Action |
|------|-------|--------|
| **Paste Credentials** | `_keys.py` lines 12-14 | Replace placeholder text |
| **Select MDE** | At data source prompt | Press Enter (default) |
| **Select Sentinel** | At data source prompt | Type 2 + Enter |
| **Switch Sources** | Each hunt startup | Choose 1 or 2 |

---

## 🎯 **Summary:**

✅ **Files Modified:** 3 files
✅ **New Credentials Needed:** 3 values (Tenant ID, Client ID, Secret)
✅ **Where to Paste:** `_keys.py` lines 12-14
✅ **Default Behavior:** Uses MDE (press Enter)
✅ **Easy Switch:** Type 2 for Sentinel
✅ **Your Progress:** 100% safe, no changes to sessions

---

## 🚀 **YOU'RE READY!**

**Next steps:**
1. ✅ Open `_keys.py`
2. ✅ Go to lines 12-14
3. ✅ Paste your MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET
4. ✅ Save the file
5. ✅ Run `python3 _main.py`
6. ✅ Select CTF mode
7. ✅ Press Enter to use MDE (default)
8. ✅ Resume your hunt
9. ✅ Query DeviceRegistryEvents successfully!

**All done! Just paste your 3 values into _keys.py and you're good to go!** 🎯✅

