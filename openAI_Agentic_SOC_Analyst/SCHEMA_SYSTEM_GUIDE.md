# 🏗️ Comprehensive Azure Schema System

## ✅ **New Architecture Implemented**

We've built a **comprehensive schema reference system** that teaches the LLM the exact structure of Azure Log Analytics tables.

---

## 🎯 **The Problem**

**Before:** LLM had no knowledge of:
- ❌ Exact field names in Azure tables
- ❌ Field data types
- ❌ Allowed values for categorical fields  
- ❌ KQL syntax rules
- ❌ Common query patterns

**Result:** Generated queries with wrong field names like `IPAddress`, `Computer`, `LogonType`, etc.

---

## ✅ **The Solution**

### **New Module: `AZURE_SCHEMA_REFERENCE.py`**

A comprehensive reference system containing:

1. **Complete Table Schemas**
   - Every field with its data type
   - Field descriptions
   - Required vs optional fields
   - Allowed values for categorical fields
   - Example values

2. **KQL Syntax Rules**
   - Filtering patterns
   - Time-based queries
   - Aggregation rules
   - Join warnings
   - Projection examples

3. **Common Query Patterns**
   - Pre-built examples for each table
   - Best practices

---

## 📋 **Schema Structure**

### **Example: DeviceLogonEvents**

```python
"DeviceLogonEvents": {
    "description": "Logon events on Windows devices",
    "fields": {
        "TimeGenerated": {
            "type": "datetime",
            "description": "Timestamp when event was generated",
            "required": True,
            "example": "datetime(2025-09-14T03:45:12Z)"
        },
        "DeviceName": {
            "type": "string",
            "description": "Name of the device/computer",
            "required": True,
            "example": "flare-vm-01"
        },
        "ActionType": {
            "type": "string",
            "description": "Type of logon action",
            "required": True,
            "allowed_values": ["LogonSuccess", "LogonFailed"],  # ✅ Explicit values!
            "example": "LogonSuccess"
        },
        "RemoteIP": {
            "type": "string",
            "description": "Source IP address of the logon attempt",
            "required": False,
            "example": "159.26.106.84"
        }
    },
    "common_queries": [
        "Filter by ActionType: | where ActionType == \"LogonSuccess\"",
        "Filter by device: | where DeviceName contains \"hostname\"",
        "Time range: | where TimeGenerated between (datetime(...) .. datetime(...))"
    ]
}
```

---

## 🔧 **How It Works**

### **1. LLM Receives Comprehensive Schema**

When building a query, the LLM now gets:

```
**Table: DeviceLogonEvents**
Description: Logon events on Windows devices

**Available Fields:**

• **TimeGenerated** (datetime)
  - Timestamp when event was generated
  - Example: datetime(2025-09-14T03:45:12Z)

• **DeviceName** (string)
  - Name of the device/computer
  - Example: flare-vm-01

• **ActionType** (string)
  - Type of logon action
  - Allowed values: LogonSuccess, LogonFailed
  - Example: LogonSuccess

• **RemoteIP** (string)
  - Source IP address of the logon attempt
  - Example: 159.26.106.84

**Common Query Patterns:**
  Filter by ActionType: | where ActionType == "LogonSuccess"
  Filter by device: | where DeviceName contains "hostname"
```

### **2. LLM Receives KQL Syntax Rules**

```
**KQL SYNTAX RULES:**

**FILTERING:**
Use 'where' to filter rows

✅ CORRECT Examples:
  | where DeviceName == "hostname"
  | where ActionType == "LogonSuccess"
  | where RemoteIP != ""

❌ INCORRECT Examples:
  | where Computer == "hostname"  // Wrong field name
  | where LogonSuccess == true  // Wrong field name

**TIME_FILTERING:**
Use TimeGenerated for time-based filtering

✅ CORRECT Examples:
  | where TimeGenerated between (datetime(2025-09-13) .. datetime(2025-09-14))
  | where TimeGenerated > ago(24h)

**AGGREGATION:**
Use summarize for aggregations

💡 Tips:
  • After summarize, only aggregated fields are available
  • Use 'by' clause to group results
```

### **3. LLM Receives Critical Rules**

```
**CRITICAL RULES:**
1. Use ONLY the field names listed in the schema above
2. Field names are CASE-SENSITIVE - use exact spelling
3. For DeviceLogonEvents, ActionType values are: "LogonSuccess" or "LogonFailed"
4. Do NOT invent field names like Computer, IPAddress, LogonType, LogonSuccess
5. Always use TimeGenerated for time filtering (not Timestamp)
6. After joins or aggregations, only projected/aggregated fields are available
7. Keep queries simple - avoid complex joins if possible
```

---

## 📊 **Supported Tables**

### **1. DeviceLogonEvents**
```
Fields: TimeGenerated, DeviceName, AccountName, ActionType, RemoteIP, RemoteDeviceName
ActionType values: "LogonSuccess", "LogonFailed"
```

### **2. DeviceProcessEvents**
```
Fields: TimeGenerated, DeviceName, AccountName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
ActionType values: "ProcessCreated", "ProcessTerminated"
```

### **3. DeviceNetworkEvents**
```
Fields: TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort
ActionType values: "ConnectionSuccess", "ConnectionFailed", "ConnectionRequest"
```

### **4. DeviceFileEvents**
```
Fields: TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, SHA256
ActionType values: "FileCreated", "FileModified", "FileDeleted", "FileRenamed"
```

### **5. DeviceRegistryEvents**
```
Fields: TimeGenerated, DeviceName, ActionType, RegistryKey
ActionType values: "RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted"
```

---

## 🔍 **Helper Functions**

### **Get Table Schema:**
```python
schema = AZURE_SCHEMA_REFERENCE.get_table_schema("DeviceLogonEvents")
```

### **Get Field List:**
```python
fields = AZURE_SCHEMA_REFERENCE.get_field_list("DeviceLogonEvents")
# Returns: ['TimeGenerated', 'DeviceName', 'AccountName', 'ActionType', 'RemoteIP', 'RemoteDeviceName']
```

### **Get Field Info:**
```python
info = AZURE_SCHEMA_REFERENCE.get_field_info("DeviceLogonEvents", "ActionType")
# Returns: {'type': 'string', 'description': '...', 'allowed_values': [...]}
```

### **Generate Schema Prompt:**
```python
prompt = AZURE_SCHEMA_REFERENCE.generate_schema_prompt("DeviceLogonEvents")
# Returns formatted prompt for LLM
```

### **Generate KQL Rules:**
```python
rules = AZURE_SCHEMA_REFERENCE.generate_kql_rules_prompt()
# Returns KQL syntax rules for LLM
```

---

## ✅ **What This Fixes**

| Problem | Before | After |
|---------|--------|-------|
| **Wrong field names** | IPAddress, Computer, LogonType | ✅ RemoteIP, DeviceName, ActionType |
| **Unknown field types** | LLM guesses | ✅ Explicit types provided |
| **Wrong ActionType values** | LogonSuccess == true | ✅ ActionType == "LogonSuccess" |
| **Ambiguous after joins** | No guidance | ✅ Warnings about field scope |
| **No examples** | LLM invents | ✅ Concrete examples provided |

---

## 🔧 **How to Add New Tables**

Edit `AZURE_SCHEMA_REFERENCE.py`:

```python
AZURE_TABLE_SCHEMAS = {
    "YourNewTable": {
        "description": "Description of the table",
        "fields": {
            "FieldName": {
                "type": "string",  # or datetime, int, etc.
                "description": "What this field contains",
                "required": True,  # or False
                "allowed_values": ["Value1", "Value2"],  # Optional
                "example": "ExampleValue"
            }
        },
        "common_queries": [
            "Example query pattern 1",
            "Example query pattern 2"
        ]
    }
}
```

---

## 🎯 **Integration with CTF Mode**

The CTF module now:
1. ✅ Imports `AZURE_SCHEMA_REFERENCE`
2. ✅ Gets comprehensive schema for suggested table
3. ✅ Displays available fields to user
4. ✅ Sends full schema + KQL rules to LLM
5. ✅ LLM generates query with correct field names

---

## 📝 **Example LLM Prompt (Now)**

```
You are a cybersecurity analyst helping with a CTF investigation.
You MUST generate a syntactically correct KQL query using ONLY the exact field names provided.

[Session Context]

CURRENT FLAG:
🚩 Flag 1: Attacker IP Address
Find external IP that logged in via RDP after brute-force attempts

**Table: DeviceLogonEvents**
Description: Logon events on Windows devices

**Available Fields:**
• TimeGenerated (datetime) - Timestamp when event was generated
• DeviceName (string) - Name of the device/computer
• AccountName (string) - Username of the account
• ActionType (string) - Type of logon action
  - Allowed values: LogonSuccess, LogonFailed
• RemoteIP (string) - Source IP address
• RemoteDeviceName (string) - Name of remote device

**Common Query Patterns:**
  Filter by ActionType: | where ActionType == "LogonSuccess"
  Filter by device: | where DeviceName contains "hostname"

**KQL SYNTAX RULES:**
[Comprehensive rules...]

**CRITICAL RULES:**
1. Use ONLY the field names listed in the schema above
2. Field names are CASE-SENSITIVE
3. ActionType values are: "LogonSuccess" or "LogonFailed"
4. Do NOT use: Computer, IPAddress, LogonType, LogonSuccess
5. Use TimeGenerated for time filtering
...

Return ONLY the KQL query, no markdown, no explanations.
```

---

## ✅ **Benefits**

1. **Accurate Queries** - LLM knows exact field names
2. **Type Safety** - LLM knows field data types
3. **Value Constraints** - LLM knows allowed values
4. **Syntax Rules** - LLM follows KQL best practices
5. **Examples** - LLM has concrete patterns to follow
6. **Maintainable** - Single source of truth for schema
7. **Extensible** - Easy to add new tables
8. **Self-Documenting** - Schema includes descriptions

---

## 🚀 **Result**

**The LLM should now generate syntactically correct KQL queries with valid field names!**

Test it:
```bash
python3 _main.py
[3] CTF MODE
...
```

**Expected: Queries with correct fields like `RemoteIP`, `DeviceName`, `ActionType == "LogonSuccess"`**

---

## 📖 **Files Updated**

1. ✅ **`AZURE_SCHEMA_REFERENCE.py`** (NEW) - Comprehensive schema system
2. ✅ **`CTF_HUNT_MODE.py`** - Integrated schema system
3. ✅ **`GUARDRAILS.py`** - Original allowed fields (still used for validation)

---

**The schema-based approach provides the LLM with complete, accurate information about Azure tables!** 🎯✅

