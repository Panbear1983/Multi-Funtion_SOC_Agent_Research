# Enhanced Anomaly Detection System - User Guide

## Overview

The Enhanced Anomaly Detection Pipeline transforms routine security scanning into production-grade SOC operations with deep analysis, behavioral learning, and professional reporting.

---

## What's New

### **Previous System (ANOMALY_DETECTION_PIPELINE.py)**
- ❌ Basic table-by-table scanning
- ❌ Generic "find anomalies" prompts
- ❌ No statistical analysis
- ❌ No behavioral baseline
- ❌ No cross-table correlation
- ❌ Simple findings list output
- ❌ 4 tables scanned

### **Enhanced System (ENHANCED_ANOMALY_DETECTION_PIPELINE.py)**
- ✅ **7 comprehensive tables** (all security categories)
- ✅ **4-stage analysis pipeline** (Statistical → Baseline → LLM → Correlation)
- ✅ **Behavioral baseline learning** (persistent, improves over time)
- ✅ **Cross-table attack chain detection** (identifies multi-stage attacks)
- ✅ **Statistical outlier detection** (Z-score, frequency, temporal analysis)
- ✅ **Executive summary generation** (professional SOC reporting)
- ✅ **Cost optimization** (only sends outliers to LLM, 90% token reduction)
- ✅ **Scan persistence** (reports saved to JSON files)

---

## How It Works

### **4-Stage Analysis Pipeline**

```
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: Multi-Table Scanning                                  │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                 │
│  For each table:                                                │
│    1. Query Azure Log Analytics                                │
│    2. Statistical Analysis (Fast, Factual)                     │
│       • Time-based anomalies (off-hours, weekends)             │
│       • Frequency anomalies (Z-score > 3σ)                     │
│       • Rare events (< 1% frequency)                           │
│       • Network diversity (unusual IPs)                        │
│    3. Baseline Comparison (Behavioral)                         │
│       • Compare to learned normal patterns                     │
│       • Detect deviations from typical behavior                │
│    4. LLM Analysis (Only on outliers)                          │
│       • Send filtered records to model                         │
│       • Confirm true anomalies vs false positives              │
│       • Generate detailed findings                             │
│    5. Track entities for correlation                           │
│       • Users, devices, IPs, processes                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ PHASE 2: Cross-Table Correlation                               │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                 │
│  • User-based: Multi-stage attacks (same user, multiple tables)│
│  • Device-based: Compromised hosts (3+ findings on one device) │
│  • IP-based: Lateral movement (one IP, multiple devices)       │
│                                                                 │
│  Output: Attack chains with severity, timeline, recommendations│
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ PHASE 3: Executive Summary                                     │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                 │
│  • Professional SOC analyst summary                            │
│  • Risk assessment                                             │
│  • Prioritized recommendations                                 │
│  • Attack narratives/timelines                                 │
│  • Optional GPT-4 refinement (anti-hallucination protected)    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ PHASE 4: Baseline Update                                       │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                 │
│  • Update behavioral baseline with new data                    │
│  • Exponential moving average (70% old, 30% new)               │
│  • Saves to _anomaly_baseline.json                             │
│  • Future scans improve accuracy                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Usage

### **Running a Scan**

1. Start the application:
   ```bash
   python _main.py
   ```

2. Select mode:
   ```
   [2] 🔍 ANOMALY DETECTION - Automated Scanning
   ```

3. Choose model:
   - **Recommended**: `qwen` or `gpt-oss:20b` (FREE, handles large datasets)
   - Alternative: `gpt-5-mini` or `gpt-4.1-nano` (requires manageable data size)

4. Configure scan:
   ```
   Time range (hours) [168 = 7 days]: <Enter or specify>
   Filter by device (optional): <Enter or specify>
   Filter by user (optional): <Enter or specify>
   
   Scan scope:
   [1] Comprehensive (all 7 tables) - Recommended ← Choose this
   [2] Authentication only
   [3] Execution only
   [4] Network only
   
   Update behavioral baseline? [Y/n]: Y ← Keep learning
   ```

5. Review results:
   - Executive summary displayed
   - Correlated attack chains highlighted
   - Press Enter to see detailed findings
   - Report saved to `_anomaly_scan_<scan_id>.json`

---

## Tables Scanned

### **Comprehensive Coverage (7 Tables)**

| Category | Tables | What It Detects |
|----------|--------|----------------|
| **Authentication** | DeviceLogonEvents<br>SigninLogs | Failed logins, unusual locations, off-hours access, brute force |
| **Execution** | DeviceProcessEvents | PowerShell abuse, LOLBins, suspicious commands, privilege escalation |
| **Network** | DeviceNetworkEvents<br>AzureNetworkAnalytics_CL | C2 communication, beaconing, unusual ports, malicious IPs |
| **File Activity** | DeviceFileEvents | Ransomware indicators, data staging, malware downloads |
| **Registry** | DeviceRegistryEvents | Persistence mechanisms, autorun keys, suspicious modifications |
| **Cloud** | AzureActivity | Resource manipulation, privilege escalation, unauthorized changes |

---

## Output Example

### **Console Output**

```
═══════════════════════════════════════════════════════════════════
🔍 ENHANCED ANOMALY DETECTION - SOC ROUTINE SCAN
═══════════════════════════════════════════════════════════════════
Scan ID: scan_20251021_154233
Baseline: 5 previous scans
Model: qwen
═══════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════
PHASE 1: Multi-Table Anomaly Scanning
═══════════════════════════════════════════════════════════════════

Scanning Authentication Tables
──────────────────────────────────────────────────────────────────

Scanning: DeviceLogonEvents
  1,245 records returned
  Running statistical analysis... 3 patterns
  Comparing to baseline... 1 deviations
  Analyzing 42 outliers with qwen...
  ✓ 2 findings detected

Scanning: SigninLogs
  892 records returned
  Running statistical analysis... 2 patterns
  Comparing to baseline... 0 deviations
  ✓ No anomalies detected

[... continues for all tables ...]

═══════════════════════════════════════════════════════════════════
PHASE 2: Cross-Table Correlation Analysis
═══════════════════════════════════════════════════════════════════
Analyzing cross-table correlations...
✓ Identified 2 correlated attack patterns

═══════════════════════════════════════════════════════════════════
PHASE 3: Executive Summary Generation
═══════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════
PHASE 4: Baseline Update
═══════════════════════════════════════════════════════════════════
✓ Baseline updated (scan #6)

═══════════════════════════════════════════════════════════════════
ANOMALY SCAN COMPLETE
═══════════════════════════════════════════════════════════════════
Scan duration: 143.25 seconds
Tables scanned: 7
Records analyzed: 12,458
Total anomalies: 8
Correlated attacks: 2
═══════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY

═══════════════════════════════════════════════════════════════════
        ANOMALY DETECTION SCAN REPORT - EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════
Scan ID: scan_20251021_154233
Date: 2025-10-21 15:42:33 UTC
Duration: 143s
Records Analyzed: 12,458
Tables Scanned: 7

FINDINGS SUMMARY
───────────────────────────────────────────────────────────────────
Total Anomalies: 8
  • High Confidence: 3
  • Medium Confidence: 4
  • Low Confidence: 1

Statistical Outliers Detected: 8
Baseline Deviations: 3
Correlated Attack Chains: 2

Affected Systems: 3
Affected Users: 2

═══════════════════════════════════════════════════════════════════
CORRELATED ATTACK CHAINS
═══════════════════════════════════════════════════════════════════

Attack Chain #1: MULTI STAGE ATTACK
  Actor: john.doe (user)
  Stages: 4
  Severity: HIGH
  MITRE Tactics: Initial Access, Execution, Credential Access

Attack Chain #2: COMPROMISED HOST
  Actor: DESKTOP-ABC123 (device)
  Stages: 3
  Severity: CRITICAL
  → Isolate DESKTOP-ABC123 immediately
```

---

## Behavioral Baseline System

### **How It Works**

The system learns "normal" behavior over time:

1. **First Scan** (Scan #1):
   - No baseline exists
   - Creates `_anomaly_baseline.json`
   - Records normal patterns from this scan

2. **Subsequent Scans** (Scan #2+):
   - Compares new data to baseline
   - Detects deviations from learned patterns
   - Updates baseline with exponential moving average (70% old, 30% new)

3. **Patterns Tracked**:
   - Login hours per user
   - Process execution frequency
   - Network destinations
   - Login locations
   - User-device relationships

4. **Anomaly Examples**:
   - User logs in at 3 AM (normally logs in 9-5)
   - Process executed 50x more than baseline
   - User logs in from new country
   - User accesses device they've never used

### **Baseline File Location**

`_anomaly_baseline.json` - Automatically created and updated

---

## Hybrid Mode (SLM + GPT Refinement)

### **What Is Hybrid Mode?**

Uses local SLM for data crunching (free, unlimited), then GPT-4/5 for output refinement:

```
Step 1: Qwen/GPT-OSS processes ALL data (FREE)
   ↓
Step 2: GPT-4o refines findings (minimal cost, high quality)
   ↓
Step 3: Anti-hallucination validation (ensures accuracy)
```

### **Benefits**

- ✅ Process massive datasets (local SLM)
- ✅ Professional output quality (GPT-4)
- ✅ Cost-effective (~$0.05 per scan vs. $50+)
- ✅ Hallucination protection (facts preserved)

### **How to Enable**

Currently disabled by default. To enable, modify `EXECUTOR.py`:

```python
# Line 45 in EXECUTOR.py
use_gpt_refinement=True,  # Change False to True
```

**Note**: Requires OpenAI API key and credits.

---

## Cost Analysis

### **Traditional Approach (All data to GPT-4)**
- 10K records = ~3.8M tokens
- **Result**: ❌ Exceeds model limits, fails

### **Enhanced System (Statistical filtering)**
- 10K records → 100 outliers = ~50K tokens
- Qwen processing: **$0.00**
- Optional GPT-4o refinement: **~$0.05**
- **Total**: **~$0.05** (vs. impossible/expensive)

### **Savings**
- **90% token reduction** through intelligent filtering
- **99% cost reduction** using local models
- **100% coverage** - can handle unlimited data

---

## Scan Reports

### **Saved Report Files**

Each scan generates:
- `_anomaly_scan_<scan_id>.json` - Complete scan report

### **Report Contents**

```json
{
  "scan_metadata": {
    "scan_id": "scan_20251021_154233",
    "start_time": "2025-10-21T15:42:00Z",
    "end_time": "2025-10-21T15:44:23Z",
    "tables_scanned": 7,
    "records_analyzed": 12458,
    "anomalies_found": 8,
    "statistical_outliers": 8,
    "baseline_deviations": 3,
    "correlated_attacks": 2
  },
  "executive_summary": "...",
  "findings": [...],
  "correlated_attacks": [...],
  "baseline_info": {...}
}
```

---

## Best Practices

### **For Best Results**

1. **Run regularly** (daily/weekly):
   - Baseline improves with each scan
   - Detects trends over time

2. **Use comprehensive scan**:
   - All 7 tables provide full picture
   - Cross-table correlation requires multiple tables

3. **Adjust time range based on environment**:
   - Small environment: 7 days (168 hours)
   - Large environment: 24 hours to reduce data
   - Investigation: Custom range for incident timeframe

4. **Review correlated attacks first**:
   - Higher confidence (multiple indicators)
   - Shows full attack chain
   - Prioritized by system

5. **Update baseline regularly**:
   - Keep learning enabled
   - Improves accuracy over time
   - Reduces false positives

### **Troubleshooting**

**"Too much data" errors**:
- ✅ Use local models (qwen/gpt-oss:20b)
- ✅ Reduce time range
- ✅ Filter by device/user
- ❌ Don't use OpenAI models for large datasets without filters

**No anomalies detected**:
- Environment may be normal (good!)
- Check if baseline is too permissive (run more scans)
- Try longer time range
- Review statistical thresholds

**Too many false positives**:
- Run more scans to improve baseline
- Review severity configuration
- Check if environment patterns changed legitimately

---

## Technical Details

### **Statistical Methods**

1. **Z-Score Analysis**:
   - Identifies values > 3 standard deviations from mean
   - Catches frequency anomalies

2. **Temporal Analysis**:
   - Off-hours detection (2-5 AM, weekends)
   - Time-based pattern matching

3. **Rare Event Detection**:
   - Events occurring < 1% of the time
   - Novel behavior identification

4. **Exponential Moving Average**:
   - Baseline updates: 70% historical, 30% new
   - Gradual adaptation to environment changes

### **Anti-Hallucination Protection**

When GPT refinement is enabled:

1. **Input Validation**:
   - Only factual data sent to GPT
   - Clear constraints in prompts
   - Low temperature (0.1)

2. **Output Validation**:
   - Cross-reference all IOCs against originals
   - Verify no added findings
   - Check confidence levels didn't inflate

3. **Automatic Reversion**:
   - Hallucinated content rejected
   - Original findings preserved
   - User notified of violations

---

## Comparison with Original System

| Feature | Original | Enhanced |
|---------|----------|----------|
| Tables | 4 | 7 |
| Analysis stages | 1 (LLM only) | 4 (Stats → Baseline → LLM → Correlation) |
| Baseline | None | Persistent, learning |
| Correlation | None | Cross-table attack chains |
| Reports | Basic list | Executive summary + JSON |
| Statistical analysis | None | Z-score, frequency, temporal |
| Cost optimization | None | 90% token reduction |
| Output quality | Generic | Professional SOC-grade |
| Data capacity | Limited by model | Unlimited (local SLM) |
| Learning | None | Improves over time |

---

## Support & Maintenance

### **Files Created**

- `_anomaly_baseline.json` - Behavioral baseline (persistent)
- `_anomaly_scan_<id>.json` - Scan reports (one per scan)

### **Safe to Delete**

- Scan report files (`_anomaly_scan_*.json`) - Archives only
- Baseline file (`_anomaly_baseline.json`) - Will recreate, but loses learning

### **Do NOT Delete**

- `ENHANCED_ANOMALY_DETECTION_PIPELINE.py` - Core system
- `GUARDRAILS.py` - Security controls
- Configuration files

---

## Future Enhancements

Potential additions (not yet implemented):

- [ ] Automatic remediation suggestions
- [ ] SIEM integration (Sentinel, Splunk)
- [ ] Email/Slack alerting
- [ ] Trend visualization
- [ ] Machine learning anomaly scoring
- [ ] Threat intelligence enrichment
- [ ] Automated incident tickets

---

**System Status**: ✅ **Production Ready**

**Last Updated**: October 21, 2025

**Version**: 2.0 - Enhanced SOC Operations

