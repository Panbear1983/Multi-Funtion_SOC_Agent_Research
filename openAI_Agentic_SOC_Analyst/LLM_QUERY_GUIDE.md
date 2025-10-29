# 🤖 LLM-ASSISTED QUERY BUILDING - USER GUIDE

## **✅ IMPLEMENTED - READY TO USE!**

The agent now supports **TWO query methods** after severity selection:

---

## **📊 NEW WORKFLOW:**

```
1. Select Mode: Threat Hunting
2. Select Model: gpt-4.1-nano
3. Select Severity: Normal

4. 🆕 Investigation Context (Optional):
   → "Look for exfiltration, IP 192.168.1.100, flag{...}"

5. 🆕 Query Method Selection:
   
   [1] 🤖 Natural Language (LLM-Assisted)
   [2] 📋 Structured Input (Manual)

   → Select [1]

6. 🤖 Natural Language Query:
   → "Find PowerShell with encoded commands from slflare"

7. ✨ LLM automatically:
   • Picks table (DeviceProcessEvents)
   • Sets filters (AccountName=slflare, CommandLine contains base64)
   • Includes investigation context

8. 🎯 Analysis runs with targeted query!
```

---

## **🤖 OPTION 1: NATURAL LANGUAGE (LLM-Assisted)**

### **How It Works:**
1. You describe what you want in plain English
2. LLM interprets your request + investigation context
3. LLM picks the best table and filters
4. Query executes automatically
5. Results analyzed with full context

### **Examples:**

#### **Example 1: CTF Flag Hunt**
```
Context: "Flag format is flag{username_action_time}"

Your hunt: "Find unusual PowerShell execution from slflare"

LLM decides:
  Table: DeviceProcessEvents
  Filters: AccountName=slflare, FileName=powershell.exe
  Focus: Encoded commands, script blocks, unusual parameters
```

#### **Example 2: IOC Investigation**
```
Context: "Malware hash: abc123..., communicates with 192.168.1.100"

Your hunt: "Track lateral movement from infected host"

LLM decides:
  Table 1: DeviceProcessEvents (find parent/child processes)
  Table 2: DeviceNetworkEvents (find network connections to 192.168.1.100)
  Filters: Related to hash abc123... and IP
```

#### **Example 3: Credential Dumping**
```
Context: "Look for T1003 - Credential Dumping technique"

Your hunt: "Detect LSASS access or registry credential theft"

LLM decides:
  Table: DeviceProcessEvents
  Filters: Target=lsass.exe OR Target contains SAM/SECURITY
  Focus: Process injection, memory access, registry access
```

---

## **📋 OPTION 2: STRUCTURED INPUT (Manual)**

### **How It Works:**
1. Select table from menu (1-6)
2. Enter DeviceName filter (optional)
3. Enter AccountName filter (optional)
4. Query executes with your selections

### **Best For:**
- Simple, targeted queries
- When you know exactly what table to query
- No extra LLM cost for query planning

---

## **🔥 NATURAL LANGUAGE QUERY EXAMPLES:**

### **Authentication & Access:**
```
• "Show failed login attempts from external IPs"
• "Find successful logins after multiple failures"
• "Track privileged account usage on server-01"
• "Detect brute force attacks on admin accounts"
```

### **Malware & Execution:**
```
• "Find suspicious process creation chains"
• "Detect PowerShell with encoded commands"
• "Show files downloaded from external sources"
• "Track execution from temp directories"
```

### **Network & C2:**
```
• "Find connections to suspicious IPs"
• "Detect beaconing behavior to external domains"
• "Show unusual outbound connections on high ports"
• "Track data exfiltration attempts"
```

### **Persistence & Privilege:**
```
• "Find registry Run key modifications"
• "Detect scheduled task creation"
• "Show privilege escalation attempts"
• "Track service installation or modification"
```

---

## **💡 TIPS FOR BETTER LLM QUERIES:**

### **1. Be Specific:**
✅ Good: "Find PowerShell with encoded commands from user slflare"  
❌ Bad: "Find PowerShell"

### **2. Include Context:**
✅ Good: "Track lateral movement from compromised host server-01"  
❌ Bad: "Show logins"

### **3. Use IOCs:**
✅ Good: "Find connections to IP 192.168.1.100 or hash abc123..."  
❌ Bad: "Find bad stuff"

### **4. Reference Techniques:**
✅ Good: "Detect T1003 credential dumping on domain controller"  
❌ Bad: "Find hacking"

### **5. Combine Investigation Context:**
```
Context: "Flag format flag{user_IP_time}, malware hash abc123..."
Query: "Find exfiltration attempts related to the malware"

→ LLM combines both for optimal results!
```

---

## **🎯 CTF-SPECIFIC STRATEGIES:**

### **Strategy 1: Flag Format Clues**
```
Context: "Flag is in format flag{encoded_base64}"
Query: "Find commands with base64 encoding or encoded data"

→ LLM will focus on:
  - PowerShell -EncodedCommand
  - certutil -decode
  - Base64 strings in logs
```

### **Strategy 2: Time-Based Hints**
```
Context: "Attack occurred between 2-3 PM on Oct 7"
Query: "Show all suspicious activity in that timeframe"

→ LLM will:
  - Query that specific time window
  - Correlate multiple event types
  - Build attack timeline
```

### **Strategy 3: IOC Correlation**
```
Context: "Known bad IP: 192.168.1.100, file hash: def456..."
Query: "Find all activity related to these IOCs"

→ LLM will:
  - Query network events for IP
  - Query file events for hash
  - Find parent/child processes
  - Build full attack chain
```

---

## **⚡ QUICK START:**

```bash
python3 _main.py

# Follow prompts:
1. Mode: 1 (Threat Hunting)
2. Model: 1 (gpt-4.1-nano - fast & cheap)
3. Severity: [Enter] (Normal)
4. Context: Look for flag{...}, IP 192.168.1.100
5. Query Method: 1 (Natural Language)
6. Hunt: Find exfiltration attempts from slflare
7. ✨ LLM builds query and finds your flag!
```

---

## **📊 COST COMPARISON:**

### **Manual Mode:**
- Query Planning: Free (no LLM)
- Analysis: 1 LLM call
- **Total: ~$0.002**

### **LLM Mode:**
- Query Planning: 1 LLM call (~$0.0001)
- Analysis: 1 LLM call (~$0.002)
- **Total: ~$0.0021**

**Extra cost for LLM query: $0.0001 (basically free!)**

---

## **🎯 WHEN TO USE EACH:**

### **Use Natural Language (LLM) When:**
- ✅ Complex multi-table queries
- ✅ CTF flag hunting
- ✅ Don't know exact table
- ✅ Want context-aware query
- ✅ Need correlation across tables

### **Use Structured (Manual) When:**
- ✅ Simple single-table query
- ✅ Know exact table/filters
- ✅ Want predictable results
- ✅ Testing specific hypothesis

---

**The LLM query building is NOW LIVE and ready for CTF action!** 🏆

