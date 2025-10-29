# 💻 CUSTOM KQL EXPERT MODE - Complete Guide

## **✅ IMPLEMENTED! Your Requested Pipeline:**

```
Hint (Human Input)
    ↓
Custom KQL Query (Human Input)
    ↓
Execute Query (Get Raw Results)
    ↓
LLM Filter & Inference (Based on CTF Hints)
    ↓
Output Suggestions (Flag, IOCs, Next Steps)
```

---

## **🎯 HOW IT WORKS:**

### **Step 1: Provide CTF Hints**
```
Investigation Context:
"Flag format: flag{username_ip_time}
 Look for base64 encoding in PowerShell commands"
```

### **Step 2: Select Custom KQL Mode**
```
Query Method:
[1] Natural Language
[2] Structured  
[3] Custom KQL  ← Choose this!

Select: 3
```

### **Step 3: Write Your KQL**
```
Enter your KQL query (type 'END' when done):
  DeviceProcessEvents
  | where ProcessCommandLine contains "powershell"
  | where ProcessCommandLine contains "-enc"
  | project TimeGenerated, AccountName, ProcessCommandLine, SHA256
  END
```

### **Step 4: Auto Time Filter Added**
```
FINAL KQL QUERY (with time filter):
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-09...) .. datetime(2025-10-09...))
| where ProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "-enc"
| project TimeGenerated, AccountName, ProcessCommandLine, SHA256
```

### **Step 5: Query Executes**
```
✓ Query returned 15 record(s)
```

### **Step 6: LLM Filters Based on Context**
```
🎯 ANALYZING WITH CONTEXT:
- Flag format: flag{username_ip_time}
- Looking for: base64 encoding

Processing 15 records...

FILTERED RESULTS:
1. Record #3: PowerShell encoded command
   - AccountName: slflare
   - Decoded: "Invoke-WebRequest http://79.76.123.251"
   - Timestamp: 2025-10-07 15:05:01

SUGGESTIONS:
flag{slflare_79.76.123.251_1505}

Confidence: High
Recommendations: This matches the flag format exactly
```

---

## **🚀 COMPLETE EXAMPLE:**

```bash
python3 _main.py

# Inputs:
Mode: 1 (Threat Hunting)
Model: 1 (gpt-4.1-nano)
Severity: [Enter]
Context: Flag is base64 encoded in PowerShell, format flag{user_ip_time}
Query Method: 3 (Custom KQL)

# Your KQL:
DeviceProcessEvents
| where AccountName contains "slflare"
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, AccountName, ProcessCommandLine, RemoteIP
END

# System executes and gets 5 results
# LLM analyzes with your context:

OUTPUT:
"Found encoded PowerShell command from slflare:
 Decoded base64: flag{slflare_79.76.123.251_1505}
 
 This matches your flag format pattern!"
```

---

## **💡 POWERFUL KQL EXAMPLES FOR CTF:**

### **Example 1: Flag in ProcessCommandLine**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "flag{"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
END
```

**LLM Output:** "Found flag{admin_192.168.1.1_1234} in command"

---

### **Example 2: Base64 Decoding**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| project TimeGenerated, AccountName, ProcessCommandLine
END
```

**LLM Output:** "Decoded 3 commands, flag found: flag{...}"

---

### **Example 3: Multi-Table Correlation**
```kql
union DeviceProcessEvents, DeviceNetworkEvents
| where AccountName contains "slflare"
| project TimeGenerated, Type, AccountName, ProcessCommandLine, RemoteIP
| order by TimeGenerated asc
END
```

**LLM Output:** "Timeline correlation shows: PowerShell at 15:05:01, connection to IP at 15:05:02 → flag{...}"

---

### **Example 4: Specific IOC Hunt**
```kql
DeviceNetworkEvents
| where RemoteIP == "79.76.123.251"
| project TimeGenerated, DeviceName, RemotePort, LocalIP
| summarize count() by DeviceName, RemotePort
END
```

**LLM Output:** "Suspicious connections on port 443, likely C2 beacon"

---

### **Example 5: File Hash Investigation**
```kql
DeviceFileEvents
| where SHA256 == "abc123def456..."
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
END
```

**LLM Output:** "Malware dropped by PowerShell, parent process: flag{...}"

---

## **🔥 ADVANCED KQL TECHNIQUES:**

### **Decode Base64 in KQL:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| extend DecodedCommand = base64_decode_tostring(extract("

-enc ([A-Za-z0-9+/=]+)", 1, ProcessCommandLine))
| project TimeGenerated, AccountName, DecodedCommand
END
```

### **Extract Flag Pattern:**
```kql
DeviceProcessEvents
| extend ExtractedFlag = extract("(flag\\{[^}]+\\})", 1, ProcessCommandLine)
| where isnotempty(ExtractedFlag)
| project TimeGenerated, AccountName, ExtractedFlag
END
```

### **Time-Based Correlation:**
```kql
let suspiciousTime = datetime(2025-10-07 15:05:00);
DeviceProcessEvents
| where TimeGenerated between (suspiciousTime .. suspiciousTime + 5m)
| project TimeGenerated, AccountName, ProcessCommandLine
END
```

### **Join Multiple Tables:**
```kql
let processes = DeviceProcessEvents | where AccountName contains "slflare";
let network = DeviceNetworkEvents | where AccountName contains "slflare";
processes
| join kind=inner (network) on DeviceName, $left.TimeGenerated == $right.TimeGenerated
| project TimeGenerated, DeviceName, ProcessCommandLine, RemoteIP
END
```

---

## **📊 WORKFLOW COMPARISON:**

| Step | Manual Mode | LLM Mode | Custom KQL Mode |
|------|-------------|----------|-----------------|
| **Query Building** | Select table/filters | LLM decides | YOU write KQL |
| **Execution** | Automatic | Automatic | Automatic |
| **Results** | All records | All records | All records |
| **Analysis** | Full analysis | Full analysis | **Filtered by CTF hints** |
| **Best For** | Simple queries | Complex requests | Expert KQL + CTF |

---

## **🎯 WHY CUSTOM KQL IS PERFECT FOR CTF:**

### **Advantage 1: Expert Control**
✅ Write complex joins, aggregations, extractions  
✅ Use KQL functions (extract, decode, parse)  
✅ Multi-table correlation  

### **Advantage 2: LLM Intelligence**
✅ LLM filters results based on your CTF hints  
✅ Decodes encoded data automatically  
✅ Suggests flags and patterns  

### **Advantage 3: Best of Both Worlds**
✅ YOUR expertise in KQL  
✅ LLM's intelligence in pattern recognition  
✅ Cost-effective (focused analysis)  

---

## **💡 CTF USE CASES:**

### **Use Case 1: You Know the Table**
```
CTF Hint: "Flag is in PowerShell process execution"

Your KQL:
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "flag"

LLM Output: Extracts and highlights the flag
```

### **Use Case 2: Complex Aggregation**
```
CTF Hint: "Flag parts are scattered across events"

Your KQL:
DeviceLogonEvents
| summarize 
    Users = make_set(AccountName),
    IPs = make_set(RemoteIP),
    Times = make_set(TimeGenerated)
| extend FlagCandidate = strcat("flag{", Users[0], "_", IPs[0], "_", Times[0], "}")

LLM Output: Validates and formats the assembled flag
```

### **Use Case 3: Decoding in KQL**
```
CTF Hint: "Flag is base64 encoded"

Your KQL:
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| extend Decoded = base64_decode_tostring(extract("-enc ([^ ]+)", 1, ProcessCommandLine))
| where Decoded contains "flag{"

LLM Output: Confirms decoded flag and explains context
```

---

## **⚡ QUICK START:**

```bash
python3 _main.py

# Selections:
1 → Threat Hunting
1 → gpt-4.1-nano
[Enter] → Normal severity
"Flag in encoded PowerShell" → Context
3 → Custom KQL

# Your Query:
DeviceProcessEvents | where ProcessCommandLine contains "flag{"
END

# LLM filters and finds your flag!
```

---

## **📚 TIPS:**

### **Tip 1: Use 'END' to Finish Multi-line Queries**
```
Enter your KQL:
  DeviceProcessEvents
  | where AccountName == "slflare"
  | project ProcessCommandLine
  END  ← Type this when done
```

### **Tip 2: Time Filter is Automatic**
```
You write:
DeviceLogonEvents | where RemoteIP == "79.76.123.251"

System adds:
| where TimeGenerated between (...)  ← Auto-added!
```

### **Tip 3: Provide Rich Context**
```
Good context:
"Flag format: flag{user_ip_time}
 Look for base64 in column 3
 Suspicious IP: 79.76.123.251"

LLM will filter results focusing on:
- Usernames in results
- IP addresses matching 79.76.123.251
- Base64 patterns
- Time correlations
```

### **Tip 4: Use KQL Functions**
```kql
| extend Decoded = base64_decode_tostring(...)
| extend Parsed = parse_json(...)
| extend Flag = extract("(flag\\{[^}]+\\})", 1, ...)
```

---

## **🏆 COMPLETE PIPELINE ACHIEVED:**

```
✅ Hint Input (Human)
   "Flag in encoded PowerShell, format flag{user_ip_time}"

✅ Custom KQL (Human)
   "DeviceProcessEvents | where ProcessCommandLine contains '-enc'"

✅ Execute Query (Automatic)
   Returns 15 records with encoded commands

✅ LLM Filter & Analyze (With CTF Hints)
   - Decodes base64
   - Filters for flag pattern
   - Correlates with context

✅ Output Suggestions (LLM)
   "FLAG FOUND: flag{slflare_79.76.123.251_1505}
    Confidence: High
    Found in record #3, matches format exactly"
```

---

## **📁 FILES UPDATED:**

1. **_main.py** - Added Custom KQL option [3]
2. **THREAT_HUNT_PIPELINE.py** - Custom KQL execution path
3. **CUSTOM_KQL_MODE_GUIDE.md** - This guide

---

## **🎯 YOUR EXACT REQUEST - DELIVERED!**

You asked for:
> "input KQL → output result → LM filter based on CTF hint → make suggestion"

You got:
✅ Custom KQL input (multi-line support)  
✅ Query execution with results  
✅ LLM filtering based on investigation context  
✅ Intelligent suggestions for CTF flags  

**Exactly what you requested!** 🏆


