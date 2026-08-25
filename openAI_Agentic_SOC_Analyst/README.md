# 🛡️ Agentic SOC Analyst

**Advanced Threat Hunting & Anomaly Detection System**

An AI-powered Security Operations Center (SOC) analyst that uses Large Language Models (LLMs) to detect threats, anomalies, and attack patterns in Azure Log Analytics data. Features self-learning capabilities, multi-tier severity modes, and hybrid rule-based + LLM detection.

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture Overview](#-architecture-overview)
- [System Components](#-system-components)
- [Operational Modes](#-operational-modes)
- [3-Tier Severity System](#-3-tier-severity-system)
- [Active Learning System](#-active-learning-system)
- [Model Support](#-model-support)
- [Detection System](#-detection-system)
- [Attack Chain Correlation](#-attack-chain-correlation)
- [Behavioral Baseline](#-behavioral-baseline)
- [Data Flow](#-data-flow)
- [Installation](#-installation)
- [Usage & Workflow](#-usage--workflow)
- [Configuration](#-configuration)
- [Real-World Use Cases](#-real-world-use-cases)
- [Performance Metrics](#-performance-metrics)
- [Troubleshooting](#-troubleshooting)
- [Best Practices](#-best-practices)
- [CTF Mode - Interactive Flag Hunting](#-ctf-mode---interactive-flag-hunting)
- [Enhanced Model Management](#-enhanced-model-management)
- [Setup & Configuration Guides](#-setup--configuration-guides)
- [Advanced Features](#-advanced-features)
- [Reference Materials](#-reference-materials)

---

## 🚀 Quick Start

```bash
# 1. Run the agent
python start_button.py

# 2. Select investigation mode
[1] Threat Hunting  [2] Anomaly Detection  [3] CTF Mode

# 3. Select model
[5] gpt-oss:20b (best for Threat Hunting)
[6] qwen (best for Anomaly Detection)

# 4. Select severity level
[1] Relaxed  [2] Balanced  [3] Strict

# 5. Select framework profile
[1] None (General Hunting)
[2] OWASP (App/API)
[3] STIG (Hardening)
[4] CIS (Baseline)
[5] MITRE ATT&CK

# 6. Select result view mode
[1] Strict (default)
[2] Only Critical (High-Signal subset)
[3] Critical + Strict (two sets)

# 7. Set investigation timeframe (shows available data)
✓ Data Available: July 17 - Oct 9 (84 days)
Start date: 720  (30 days ago)
End date: (press Enter for now)

# 8. Confirmation (shows time estimate and processing details)
Model: gpt-oss:20b
Mode: Threat Hunt
Severity: Balanced
Input size: 45,230 tokens
Estimated time: 28s
Cost: FREE (Local/Offline model)
Proceed with analysis? (y/n): y

# 9. Specify hunt parameters (Threat Hunting mode only)
Select table: 1 (DeviceLogonEvents)
DeviceName: (optional)
AccountName: admin

# 10. Review findings with labeled IOCs
Indicators of Compromise:
  - AccountName: admin
  - DeviceName: DESKTOP-001

# 11. Provide feedback for learning
Rate this analysis: 4
Comments: Good detection
```

---

## 🏗️ Architecture Overview

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│                          (start_button.py)                             │
│                                                                 │
│  ┌──────────────────┐              ┌──────────────────────┐    │
│  │ Threat Hunting   │              │ Anomaly Detection    │    │
│  │ (Targeted)       │              │ (Automated)          │    │
│  └──────────────────┘              └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ORCHESTRATION LAYER                        │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │ Model Selector  │  │ Severity Levels │  │ Guardrails     │  │
│  │ MODEL_SELECTOR  │  │ SEVERITY_LEVELS │  │ GUARDRAILS     │  │
│  └─────────────────┘  └─────────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EXECUTION LAYER                            │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    EXECUTOR.py                          │   │
│  │  • Query Planning (get_query_context)                   │   │
│  │  • Log Analytics Querying (query_log_analytics)         │   │
│  │  • Threat Analysis (hunt)                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Prompt Mgmt      │  │ Model Mgmt       │  │ Local Parser │  │
│  │ PROMPT_MGMT      │  │ MODEL_MGMT       │  │ LOCAL_QUERY  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     INTELLIGENCE LAYER                          │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Correlation      │  │ Learning Engine  │  │ Behavioral   │  │
│  │ Engine           │  │                  │  │ Baseline     │  │
│  │ CORRELATION_     │  │ LEARNING_ENGINE  │  │ BEHAVIORAL_  │  │
│  │ ENGINE           │  │                  │  │ BASELINE     │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
│                                                                 │
│  • Links events across tables                                  │
│  • Builds attack chains                                        │
│  • Self-learning from feedback                                 │
│  • Detects behavioral anomalies                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MODEL INTERFACE LAYER                        │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │ OpenAI Client   │  │ Ollama Client   │  │ Enhancers      │  │
│  │ (Cloud API)     │  │ (Local)         │  │ • Qwen         │  │
│  │                 │  │                 │  │ • GPT-OSS      │  │
│  └─────────────────┘  └─────────────────┘  └────────────────┘  │
│                                                                 │
│  Models Supported:                                              │
│  • gpt-4.1-nano, gpt-4.1 (OpenAI)                              │
│  • gpt-5-mini, gpt-5 (OpenAI)                                  │
│  • qwen3:8b (Ollama - Local)                                   │
│  • gpt-oss:20b (Ollama - Local)                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DATA SOURCES                              │
│                                                                 │
│  Azure Log Analytics Workspace                                  │
│  • DeviceLogonEvents                                            │
│  • DeviceProcessEvents                                          │
│  • DeviceNetworkEvents                                          │
│  • DeviceFileEvents                                             │
│  • DeviceRegistryEvents                                         │
│  • SigninLogs                                                   │
│  • AzureActivity                                                │
│  • AzureNetworkAnalytics_CL                                     │
│  • AlertInfo, AlertEvidence                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PERSISTENCE LAYER                            │
│                                                                 │
│  • _threats.jsonl          (Detected threats)                   │
│  • _analysis_feedback.jsonl (User feedback for learning)        │
│  • pattern_weights.json    (Learned pattern weights)            │
└─────────────────────────────────────────────────────────────────┘
```

### Key Capabilities

```
┌─────────────────────────────────────────────────┐
│  AGENTIC SOC ANALYST                            │
│  Coffee-Fueled Paranoid Intern                  │
├─────────────────────────────────────────────────┤
│  ✅ 3-tier severity (Relaxed/Balanced/Strict)  │
│  ✅ Active learning (1-5 rating system)        │
│  ✅ Smart log chunking (adaptive)              │
│  ✅ Rule-based + LLM hybrid                    │
│  ✅ 165+ threat patterns                       │
│  ✅ 610+ MITRE ATT&CK mappings                 │
│  ✅ Auto IOC extraction                        │
│  ✅ Attack chain correlation                   │
│  ✅ Behavioral baseline detection              │
│  ✅ Confidence scoring                         │
│  ✅ Human escalation logic                     │
│  ✅ Self-tuning from feedback                  │
│  ✅ Offline operation (no API calls)           │
│  ✅ Privacy-preserving (local models)          │
└─────────────────────────────────────────────────┘
```

---

## 🔧 System Components

### Core Modules

#### 1. **Main Entry Point** (`start_button.py`)
- System orchestrator and user interface
- Pipeline selection (Threat Hunting vs Anomaly Detection vs CTF Mode)
- Model and severity level configuration
- Investigation context and guidance support
- Query method selection (Natural Language vs Custom KQL)
- Result view mode configuration
- Session management and results display

#### 2. **Execution Layer** (`EXECUTOR.py`)
- **Query Planning**: Uses LLM to generate KQL queries from natural language
- **Log Analytics Querying**: Executes KQL against Azure Log Analytics
- **Threat Hunting**: Analyzes logs using selected LLM or hybrid models
- **Hybrid Model Support**: Integrated support for `local-mix` (Qwen + GPT-OSS parallel processing)
- **Intelligent Model Selection**: Table-based routing (volume vs reasoning-heavy tables)
- **Chunked Processing**: Automatic chunking for large datasets
- **Error Handling**: Rate limit and token management

#### 3. **Threat Hunt Pipeline** (`THREAT_HUNT_PIPELINE.py`)
- User-directed targeted investigation
- Hypothesis-driven threat hunting
- Investigation context support (IOCs, hints, techniques)
- Guidance/killchain exemplar integration
- Query method selection (Natural Language LLM-assisted vs Custom KQL)
- Single-table focused analysis
- Interactive chat mode for local models
- Best for: Incident response, alert triage

#### 4. **Anomaly Detection Pipeline** (`ANOMALY_DETECTION_PIPELINE.py`)
- Automated multi-table scanning
- Behavioral baseline comparison
- Statistical outlier detection
- Unknown threat discovery
- Best for: Proactive hunting, scheduled scans

#### 5. **Correlation Engine** (`CORRELATION_ENGINE.py`)
- Cross-table event linking
- Attack chain identification
- Entity-based correlation (users, devices, IPs)
- MITRE ATT&CK tactic mapping
- Confidence assessment for attack chains

#### 6. **Learning Engine** (`LEARNING_ENGINE.py`)
- Self-learning pattern weight adjustment
- Analyzes user feedback to improve detection
- Adaptive confidence scoring
- Pattern performance tracking
- Weights persist across sessions

#### 7. **Feedback Manager** (`FEEDBACK_MANAGER.py`)
- Collects user ratings (1-5 scale)
- Tracks analysis quality over time
- Identifies improvement areas
- Provides tuning recommendations
- Enables continuous improvement

### Model Management

#### 8. **Model Selector** (`MODEL_SELECTOR.py`)
- Interactive model selection menu
- Displays cost and context window information
- Supports both cloud (OpenAI) and local (Ollama) models
- Token counting and estimation
- Automatic model selection based on context size
- Default fallback to `local-mix` (hybrid local models)
- **Offline Guardrails**: Defense-in-depth security controls for local models
- Runtime token validation and limit checking
- Cost estimation and model switching

#### 9. **Ollama Client** (`OLLAMA_CLIENT.py`)
- Local model interface for offline operation
- Privacy-preserving analysis
- No API costs
- 300-second timeout (handles large analyses)

#### 10. **Model Enhancers**
- **`QWEN_ENHANCER.py`**: Rule-based enhancement for Qwen models (128K context)
- **`GPT_OSS_ENHANCER.py`**: Optimized enhancement for GPT-OSS (32K context)
- 165+ threat pattern detection
- Severity-aware filtering
- Compensates for smaller model limitations

### Security & Configuration

#### 11. **Guardrails** (`GUARDRAILS.py`)
- Table and field validation
- Model validation
- Allowed tables and fields enforcement
- Security controls to prevent unauthorized access
- **Offline Model Guardrails**: Additional security layer for local models

#### 12. **Severity Levels** (`SEVERITY_LEVELS.py`)
- 3-tier severity system (Relaxed, Balanced, Strict)
- Confidence-based filtering
- Adjustable sensitivity
- False positive reduction

#### 13. **Prompt Management** (`PROMPT_MANAGEMENT.py`)
- Centralized system prompts
- Context-aware prompt building
- Tool selection prompts
- Function calling definitions
- **CTF-specific formatting**: Specialized prompts for CTF flag extraction

### Utilities

#### 14. **Utilities** (`UTILITIES.py`)
- Query context sanitization
- Threat display formatting
- Data validation
- Helper functions

#### 15. **Chat Mode** (`CHAT_MODE.py`)
- Interactive discussion of findings
- Local model conversation interface
- Context-aware responses

#### 16. **Local Query Parser** (`LOCAL_QUERY_PARSER.py`)
- Fallback query planning without API
- Pattern-based KQL generation
- Offline operation support

### Response Processing

#### 17. **Response Parser** (`RESPONSE_PARSER.py`)
- **Unified response parsing** for different output formats
- Threat Hunt format: `{"findings": [...]}`
- CTF format: `{"suggested_answer": "...", "confidence": "...", ...}`
- Fallback parsing for partial/invalid JSON
- Pattern extraction from text when JSON parsing fails

### Compliance & Framework Integration

#### 18. **Compliance Profiles** (`COMPLIANCE_PROFILES.py`)
- Framework profile selection (OWASP, STIG, CIS, MITRE)
- Table scope filtering per profile
- Profile-aware severity configuration

### Analysis & Confirmation

#### 19. **Confirmation Manager** (`CONFIRMATION_MANAGER.py`)
- Pre-commit confirmation with time estimates
- Analysis parameters display
- Cost information
- Processing details preview

#### 20. **Time Estimator** (`TIME_ESTIMATOR.py`)
- Universal time estimation for all models
- OpenAI and Ollama model profiles
- Chunked processing time calculation
- Hybrid model time estimates

#### 21. **Hybrid Engine** (`HYBRID_ENGINE.py`)
- **Dynamic hybrid model selection** based on investigation context
- **Parallel processing** (Qwen + GPT-OSS simultaneously)
- **Intelligent result fusion** with adaptive strategies
- **Context-aware model routing** (volume vs reasoning-heavy tables)
- **Adaptive configuration** per investigation mode and severity level
- **Chunked processing** for large datasets
- Supports all investigation modes (threat_hunt, anomaly, ctf)
- Supports all query methods (llm, structured, custom_kql)

### Memory & Validation

#### 22. **Retrieval Memory** (`RETRIEVAL_MEMORY.py`)
- Killchain exemplar retrieval
- Pattern matching hints
- Evidence-focused guidance
- Known attack pattern recognition

#### 23. **Schemas** (`SCHEMAS.py`)
- Pydantic schema validation
- Finding structure validation
- Evidence-bound extensions
- MITRE mapping schema

---

## 🎯 Operational Modes

### Mode 1: Threat Hunting (Targeted Investigation)

**Use Cases:**
- 🚨 Incident response
- 🔍 Alert triage
- 🎯 Specific hypothesis testing
- 👤 Deep dive on devices/users

**Workflow:**
1. Select investigation mode: Threat Hunting
2. Select model (default: `local-mix` for hybrid processing)
3. Select severity level (Relaxed/Balanced/Strict)
4. Select framework profile (optional: OWASP, STIG, CIS, MITRE)
5. Select result view mode (Strict/Critical-only/Critical+Strict)
6. **Provide investigation context** (optional):
   - Known IOCs (IPs, hashes, domains)
   - Techniques to focus on (credential dumping, lateral movement)
   - Time hints (attack occurred around 3PM)
   - Suspicious users/devices
7. **Enable guidance** (optional): Killchain exemplar and evidence requirements
8. **Select query method**:
   - **Natural Language (LLM-Assisted)**: Describe hunt in plain English
   - **Custom KQL (Expert Mode)**: Write your own KQL query
9. Set investigation timeframe (auto-set to 365 days, configurable)
10. System builds and executes KQL query with explicit dates
11. Analyzes results using selected LLM or hybrid models
12. Displays findings with labeled IOCs (DeviceName:, AccountName:)
13. Optional: Interactive chat mode for deeper analysis (local models)
14. Collects feedback for learning

**New Features:**
- **Investigation Context**: Provide hints, IOCs, or context to guide analysis
- **Guidance Mode**: Enable killchain exemplar retrieval for known attack patterns
- **Query Method Selection**: Choose between LLM-assisted or expert KQL mode
- **Hybrid Model Support**: `local-mix` automatically uses Qwen + GPT-OSS in parallel

**Example Investigations:**
- Table: DeviceLogonEvents → AccountName: admin → Last 48 hours
- Table: DeviceProcessEvents → DeviceName: DESKTOP-ABC123 → Sept 12-14
- Table: DeviceNetworkEvents → DeviceName: SERVER-001 → Last 7 days

---

### Mode 2: Anomaly Detection (Automated Scanning)

**Use Cases:**
- 📊 Proactive threat hunting
- ⏰ Scheduled security scans
- 🔎 Unknown threat discovery
- 📈 Baseline deviation detection

**Workflow:**
1. Configure scan parameters (time range, filters)
2. Automatically scan multiple tables:
   - DeviceLogonEvents
   - DeviceProcessEvents
   - DeviceNetworkEvents
   - SigninLogs
3. Compare against behavioral baselines
4. Detect statistical outliers
5. Correlate findings across tables
6. Build attack chains
7. Display aggregated results

**Detection Types:**
- First-time behaviors (new device, new IP)
- Unusual time-of-day activity
- Statistical anomalies
- Behavioral deviations
- Cross-table correlation

---

### Mode 3: CTF Mode (Interactive Flag Hunting)

**Use Cases:**
- 🏆 CTF competitions
- 🎯 Multi-stage attack investigations
- 📋 Progressive flag discovery
- 🔗 Attack chain reconstruction

**Workflow:**
1. Select CTF Mode from main menu
2. Choose data source (MDE or Azure Log Analytics)
3. Start new investigation or resume existing session
4. Follow 6-stage interactive hunt flow:
   - Stage 1: Intel Briefing (flag objective)
   - Stage 2: Query Building (LLM-assisted KQL)
   - Stage 3: Execution (query runs)
   - Stage 4: Analysis (LLM interprets results)
   - Stage 5: Flag Capture (save answer)
   - Stage 6: Continue to next flag
5. System automatically correlates flags and suggests filters
6. Generate final report with all findings

**Key Features:**
- Session memory accumulates flags and IOCs
- Auto-correlation suggests filters from previous flags
- Resume capability - pause and continue anytime
- Multiple sessions supported
- Comprehensive reporting

**Example Workflow:**
- Flag 1: Find attacker IP → 159.26.106.84
- Flag 2: System auto-suggests filter using IP from Flag 1
- Flag 3: System uses account from Flag 2
- Each flag builds on previous discoveries automatically

---

## 🎚️ 3-Tier Severity System

### Overview

The system offers three severity modes that control detection sensitivity, analysis depth, and false positive rates.

### 🔴 TIER 1: STRICT (High Security)

**When to Use:**
- 🚨 Active security incident
- 🔍 Breach investigation
- 🎯 High-value target monitoring
- 📊 Forensic analysis
- ⚠️ Ransomware outbreak

**Configuration:**
```python
{
    'name': 'Strict',
    'confidence_threshold': 'Low',      # Report Low, Medium, High
    'pattern_multiplier': 1.5,          # 150% sensitivity
    'max_log_lines': 100,               # Thorough analysis
    'min_iocs_to_flag': 1               # Flag with 1 IOC
}
```

**What You Get:**
- ✅ Maximum coverage (catches weak signals)
- ✅ All confidence levels reported
- ✅ 100 log lines analyzed (most thorough)
- ⚠️ Higher false positive rate
- ⚠️ Slower analysis (~45 seconds)

**Example Output:**
```
════════════════════════════════════════════════════════════
INVESTIGATION MODE: STRICT (High Security)
════════════════════════════════════════════════════════════
• Confidence Threshold: Low
• Pattern Sensitivity: 150%
• Max Log Lines: 100
════════════════════════════════════════════════════════════

Cognitive hunt complete. Took 38.45 seconds.
Raw findings: 87
Reported (STRICT): 87 potential threat(s)
Suppressed: 0 low-confidence findings
```

---

### 🟡 TIER 2: BALANCED (Default)

**When to Use:**
- 📅 Daily SOC operations
- 🎯 Routine threat hunting
- 📊 General monitoring
- 🔎 Standard investigations
- 🌐 Most use cases

**Configuration:**
```python
{
    'name': 'Balanced',
    'confidence_threshold': 'Medium',   # Report Medium, High
    'pattern_multiplier': 1.0,          # 100% baseline
    'max_log_lines': 50,                # Balanced analysis
    'min_iocs_to_flag': 2               # Need 2+ IOCs
}
```

**What You Get:**
- ✅ Good balance (accuracy vs. coverage)
- ✅ Medium and High confidence reported
- ✅ 50 log lines analyzed
- ✅ Reasonable speed (~30 seconds)
- ✅ Moderate false positive rate

**Example Output:**
```
════════════════════════════════════════════════════════════
INVESTIGATION MODE: BALANCED
════════════════════════════════════════════════════════════
• Confidence Threshold: Medium
• Pattern Sensitivity: 100%
• Max Log Lines: 50
════════════════════════════════════════════════════════════

Cognitive hunt complete. Took 28.12 seconds.
Raw findings: 87
Reported (BALANCED): 23 potential threat(s)
Suppressed: 64 low-confidence findings
```

---

### 🟢 TIER 3: RELAXED (Low Noise)

**When to Use:**
- 📈 Executive reports
- 📋 Weekly summaries
- 🎯 Low-priority assets
- ☕ Routine monitoring
- 📊 Baseline establishment

**Configuration:**
```python
{
    'name': 'Relaxed',
    'confidence_threshold': 'High',     # High confidence only
    'pattern_multiplier': 0.5,          # 50% sensitivity
    'max_log_lines': 25,                # Fast analysis
    'min_iocs_to_flag': 3               # Need 3+ IOCs
}
```

**What You Get:**
- ✅ Minimal false positives
- ✅ High confidence only
- ✅ 25 log lines (fastest)
- ✅ Fast analysis (~15 seconds)
- ✅ High accuracy, low noise

**Example Output:**
```
════════════════════════════════════════════════════════════
INVESTIGATION MODE: RELAXED (Low Noise)
════════════════════════════════════════════════════════════
• Confidence Threshold: High
• Pattern Sensitivity: 50%
• Max Log Lines: 25
════════════════════════════════════════════════════════════

Cognitive hunt complete. Took 14.23 seconds.
Raw findings: 87
Reported (RELAXED): 5 potential threat(s)
Suppressed: 82 low-confidence findings
```

---

### 📊 Severity Comparison Table

| Feature | STRICT 🔴 | BALANCED 🟡 | RELAXED 🟢 |
|---------|-----------|-------------|------------|
| **Pattern Sensitivity** | 150% | 100% | 50% |
| **Confidence Reported** | Low, Med, High | Med, High | High only |
| **Threshold** | Low | Medium | High |
| **Max Log Lines** | 100 | 50 | 25 |
| **Min IOCs** | 1 | 2 | 3 |
| **Analysis Speed** | ~45s | ~30s | ~15s |
| **False Positives** | High | Moderate | Low |
| **Coverage** | Maximum | Balanced | Focused |
| **Use Case** | Incidents | Daily ops | Reports |

---

## 🧠 Active Learning System

### How It Works

The system **actively learns** from your 1-5 ratings and automatically adjusts future detection.

### Learning Cycle

```
┌─────────────────────────────────────────────────┐
│  1. Run Analysis → Show Findings                │
│                  ↓                               │
│  2. You Rate: 4/5 (Good lateral movement catch) │
│                  ↓                               │
│  3. Record to _analysis_feedback.jsonl          │
│                  ↓                               │
│  4. Next Run: Load feedback at startup          │
│                  ↓                               │
│  5. Calculate weights per pattern               │
│                  ↓                               │
│  6. Adjust confidence: lateral_movement → HIGH  │
│                  ↓                               │
│  7. Show findings with learned confidence       │
│                  ↓                               │
│  8. You rate again... (cycle continues)         │
└─────────────────────────────────────────────────┘
```

### Rating Scale

```
5 = Excellent - Perfect detection, no false positives
4 = Good - Mostly accurate, minor issues
3 = Acceptable - Some value but needs improvement
2 = Poor - Many false positives or missed threats
1 = Very Poor - Unhelpful or completely wrong
```

### Real Example

#### **First Run (No Learning)**
```
=============== Potential Threat #1 ===============
Title: Suspicious PowerShell Obfuscation Activity
Confidence Level: Medium
Notes: Detected by rule-based pattern matching.
```
**You rate:** 2/5 (too many false positives)

#### **After 5 Low Ratings**
System learns: `powershell_obfuscation` → weight 0.7

#### **Next Run (With Learning)**
```
=============== Potential Threat #1 ===============
Title: Suspicious PowerShell Obfuscation Activity
Confidence Level: Low  ⬅️ ADJUSTED DOWN
Notes: Detected by rule-based pattern matching.
       [Reduced: low user rating history]  ⬅️ SHOWS WHY
```

### Learning Algorithm

```python
# Weight Calculation (needs ≥3 occurrences)
if high_ratings > low_ratings * 2:
    weight = 1.3  # Boost 30%
elif low_ratings > high_ratings * 2:
    weight = 0.7  # Reduce 30%

# Confidence Mapping
if weight >= 1.2:
    confidence = "High"    # User likes this pattern
elif weight <= 0.8:
    confidence = "Low"     # User dislikes this pattern
else:
    confidence = "Medium"  # Neutral
```

### Pattern Weight Examples

| Pattern | High Ratings | Low Ratings | Weight | Effect |
|---------|-------------|-------------|--------|--------|
| `lateral_movement` | 8 | 1 | **1.3** | ✅ Boost to **High** confidence |
| `powershell_obfuscation` | 2 | 7 | **0.7** | ⚠️ Reduce to **Low** confidence |
| `credential_dumping` | 5 | 1 | **1.3** | ✅ Boost to **High** confidence |

### Combining Severity + Learning

```
Original confidence: Medium
User feedback weight: 0.7 (rated low)
Severity mode: STRICT (1.5x multiplier)
Total weight: 0.7 × 1.5 = 1.05
Final confidence: Medium (slightly boosted but still reduced)
Note: [Reduced: low user rating history]
```

### What Gets Recorded

Saved to `_analysis_feedback.jsonl`:
```json
{
  "timestamp": "2025-10-07T14:30:00",
  "findings": [
    {
      "title": "Suspicious Lateral Movement Activity",
      "tags": ["lateral_movement", "rule-based-detection"],
      "confidence": "Medium"
    }
  ],
  "user_rating": 4,
  "user_comments": "Good catch on lateral movement"
}
```

### Learning Statistics

**At Startup:**
```
LEARNING HISTORY
─────────────────────────────────────────────────
Total Sessions: 15
Average Rating: 3.8/5.0
Recent Trend: 3 → 4 → 4 → 5 → 4 📈

Loaded learning: 3 pattern adjustments from feedback
```

**In Finding Notes:**
```
Notes: Detected by rule-based pattern matching. Pattern: psexec.*\\\\
       [Boosted: high user rating history]  ⬅️ Shows learning applied
```

### Key Benefits

✅ **Self-improving**: Gets better with each rating  
✅ **Transparent**: Shows why confidence changed  
✅ **Fast**: Loads at startup, no slowdown  
✅ **Offline**: All learning stored locally  
✅ **Reversible**: Delete file to reset learning  

---

## 🤖 Model Support

### Cloud Models (OpenAI API)

| Model | Context | Cost (Input/Output per M) | Best For |
|-------|---------|---------------------------|----------|
| **gpt-4.1-nano** | 1M+ tokens | $0.10 / $0.40 | Large log volumes, cost-sensitive |
| **gpt-4.1** | 1M+ tokens | $1.00 / $8.00 | Complex analysis, high accuracy |
| **gpt-5-mini** | 272K tokens | $0.25 / $2.00 | **Default**, balanced performance |
| **gpt-5** | 272K tokens | $1.25 / $10.00 | Advanced reasoning, critical analysis |

### Local Models (Ollama - Offline)

| Model | Context | Params | Cost | Best For |
|-------|---------|--------|------|----------|
| **qwen3:8b** | 128K tokens | 8B | Free | **Anomaly Detection** - Fast, large context, daily scans |
| **gpt-oss:20b** | 32K tokens | 20B | Free | **Threat Hunting** - Better reasoning, deep analysis |

**Model Comparison:**

| Aspect | Qwen3:8B | GPT-OSS:20B |
|--------|----------|-------------|
| **Speed** | ⚡⚡⚡ Fast (~25s) | ⚡ Slower (~45s) |
| **Reasoning** | 🧠 Good | 🧠🧠🧠 Excellent |
| **Context Size** | 📚📚📚 128K | 📚 32K |
| **Max Log Lines** | 50-100 | 15-25 |
| **Parameters** | 8 billion | 20 billion |
| **Best Use** | Multi-table scans | Focused investigations |
| **Task** | Anomaly Detection | Threat Hunting |

**Local Model Features:**
- ✅ No API costs
- ✅ Privacy-preserving (data stays local)
- ✅ Offline operation
- ✅ 165+ rule-based threat patterns
- ✅ Interactive chat mode with actual IOC data
- ✅ Field-labeled IOCs (DeviceName:, AccountName:)

---

## 🎯 Detection System

### Rule-Based Detection

**165+ Threat Patterns:**
- PowerShell obfuscation (7 patterns)
- LOLBins abuse (11 patterns)
- Credential dumping (8 patterns)
- Lateral movement (8 patterns)
- Persistence mechanisms (6 patterns)
- Defense evasion (8 patterns)
- Data exfiltration (7 patterns)
- Network suspicious (8 patterns)
- Privilege escalation (7 patterns)
- ...and 95+ more

**Example Patterns:**
```python
'powershell_obfuscation': [
    r'powershell.*-enc',
    r'iex\s*\(',
    r'invoke-expression',
    r'base64.*decode',
    r'powershell.*-windowstyle.*hidden'
]
```

### MITRE ATT&CK Mapping

**610+ Technique Mappings:**
- Initial Access (9 techniques)
- Execution (8 techniques)
- Persistence (6 techniques)
- Privilege Escalation (4 techniques)
- Defense Evasion (9 techniques)
- Credential Access (7 techniques)
- Discovery (8 techniques)
- Lateral Movement (5 techniques)
- Collection (7 techniques)
- Command & Control (8 techniques)
- Exfiltration (5 techniques)
- Impact (7 techniques)

**Example Mapping:**
```python
'lateral_movement': {
    'tactic': 'Lateral Movement',
    'technique': 'T1021.001',
    'description': 'Remote Services: Remote Desktop Protocol'
}
```

### IOC Extraction

Automatic extraction of:
- IP addresses (`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
- Domain names
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- Usernames / Account names
- Device names

---

## 🔗 Attack Chain Correlation

### How It Works

The Correlation Engine links related events across multiple log sources to build attack chains.

### Correlation Process

1. **Entity Extraction**: Extract users, devices, IPs from all findings
2. **Entity Mapping**: Map which findings involve each entity
3. **Timeline Building**: Chronologically order events
4. **Chain Identification**: Find entities appearing in multiple findings
5. **Confidence Assessment**: Calculate chain confidence from individual findings

### Example Attack Chain Output

```
━━━ Attack Chain #1 ━━━
Pivot Entity: user: john@company.com
Linked Findings: 3
Chain Confidence: High
MITRE Tactics: Initial Access → Lateral Movement → Exfiltration

Linked Findings:
  [Finding #1] Suspicious Login from New IP
  [Finding #2] SMB Connection to Domain Controller
  [Finding #3] Large Data Transfer to External IP

CHAIN ANALYSIS:
This attack chain involves user: john@company.com across 3 separate 
activities. The attacker progressed through multiple tactics: 
Initial Access → Lateral Movement → Exfiltration. This indicates 
a coordinated, multi-stage attack. High confidence correlation 
suggests active compromise requiring immediate response.
```

### Entity Types Correlated

- **Users**: Account names, UPNs, email addresses
- **Devices**: Computer names, hostnames
- **IPs**: Internal and external IP addresses

---

## 📊 Behavioral Baseline

### Overview

The Behavioral Baseline System learns normal behavior patterns and detects deviations.

### What Gets Learned

**User Behavior:**
- Typical devices accessed
- Normal login hours
- Common IP addresses
- Access patterns

**Device Behavior:**
- Normal user accounts
- Typical process counts
- Network connections

### Anomaly Types Detected

1. **First-Time Device**: User accesses a device for the first time
2. **Unusual Time**: Activity at atypical hours
3. **New IP**: Connection from previously unseen IP
4. **New User**: First-time user appearance

### Example Baseline Data

```json
{
  "users": {
    "john@company.com": {
      "devices": ["LAPTOP-001", "DESKTOP-002"],
      "login_hours": [8, 9, 10, 11, 14, 15],
      "ips": ["10.0.1.100", "10.0.1.101"]
    }
  },
  "devices": {
    "LAPTOP-001": {
      "users": ["john@company.com", "admin@company.com"],
      "process_count": 1247
    }
  }
}
```

---

## 🔄 Data Flow

### Threat Hunting Flow

```
Structured Parameter Input
  ├─ Select Table (menu)
  ├─ DeviceName Filter (optional)
  └─ AccountName Filter (optional)
         ↓
Timeframe Selection
  ├─ Auto-detect available data
  ├─ Show retention span
  └─ User selects start/end dates
         ↓
KQL Query Construction
  ├─ Explicit TimeGenerated filter
  ├─ Field-specific filters
  └─ Proper field name mapping
         ↓
Azure Log Analytics Query
  ├─ Query with timespan parameter
  └─ Diagnostics if no data found
         ↓
Log Data Retrieved
         ↓
Threat Analysis (LLM + 165+ Rules)
  ├─ Rule-based pattern matching
  └─ LLM deep analysis
         ↓
Severity Filtering
         ↓
Results Display (Labeled IOCs)
  ├─ DeviceName: xxx
  ├─ AccountName: xxx
  └─ Clear field labels
         ↓
Feedback Collection
         ↓
Learning Update
```

### Anomaly Detection Flow

```
Configuration Input
         ↓
Multi-Table Scan Loop
  ├─ DeviceLogonEvents
  ├─ DeviceProcessEvents
  ├─ DeviceNetworkEvents
  └─ SigninLogs
         ↓
Behavioral Baseline Comparison
         ↓
Anomaly Identification
         ↓
Cross-Table Correlation
         ↓
Attack Chain Building
         ↓
Results Aggregation
         ↓
Display & Feedback
```

### Complete Workflow

```
1. User starts analysis
   python start_button.py
   
2. Select mode & severity
   [1] Threat Hunting [2] Anomaly Detection
   [1] Relaxed [2] Balanced [3] Strict
   
3. System loads learning
   Loaded learning: 3 pattern adjustments from feedback
   
4. Enter threat hunt query
   "Check DeviceLogonEvents for suspicious logins in last 24h"
   
5. System queries logs
   Query Log Analytics → Returns 187 log lines
   
6. Log chunking applied
   Chunking to 50 lines max (BALANCED mode)
   
7. Rule-based detection runs (fast)
   Applying rule-based threat detection...
   Found 8 suspicious patterns, 12 IOCs
   
8. LLM analysis (if needed)
   Getting LLM analysis from qwen3:8b...
   Enhanced analysis complete: 8 total findings
   
9. Severity filtering applied
   Raw findings: 45
   Reported (BALANCED): 12 potential threats
   Suppressed: 33 low-confidence findings
   
10. Display findings
    =============== Potential Threat #1 ===============
    Title: Suspicious Lateral Movement Activity
    Confidence: High [Boosted: high user rating history]
    
11. Show investigation narrative
    INVESTIGATIVE NARRATIVE:
    Target Accounts: admin@domain.com
    Source IPs: 10.0.1.45, 192.168.1.100
    Attack Progression: Initial Access → Lateral Movement
    
12. Correlation (if multi-table scan)
    🔗 Correlating findings across tables...
    Found 2 attack chains
    
13. Request feedback
    Rate this analysis call: 1-5: 4
    Comments: Good catch on lateral movement
    
14. Save feedback
    Feedback logged to _analysis_feedback.jsonl
    
15. System learns for next run
    [Next analysis will boost lateral_movement patterns]
```

---

## 📦 Installation

### Prerequisites

```bash
# Python 3.9+
python --version

# Azure CLI (for authentication)
az --version

# Ollama (for local models, optional)
ollama --version
```

### Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install packages
pip install -r requirements.txt
```

**Required Packages:**
- `openai` - OpenAI API client
- `azure-identity` - Azure authentication
- `azure-monitor-query` - Log Analytics querying
- `pandas` - Data manipulation
- `colorama` / `color-support` - Terminal colors

### Azure Configuration

1. **Authenticate with Azure:**
```bash
az login
```

2. **Set Log Analytics Workspace ID:**
```python
# _keys.py
LOG_ANALYTICS_WORKSPACE_ID = "Peterwpan1983"
OPENAI_API_KEY = "your-openai-api-key"
```

### Local Model Setup (Optional)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull models
ollama pull qwen3:8b
ollama pull gpt-oss:20b
```

---

## 🚀 Usage & Workflow

### Basic Execution

```bash
python start_button.py
```

### Example: Threat Hunting

```
Mode: [1] Threat Hunting
Model: [5] gpt-oss:20b (recommended for Threat Hunting)
Severity: [2] Balanced
Framework Profile: [1] None (General Hunting)
Result View Mode: [1] Strict (default)

Timeframe:
  ✓ Data Available: July 17 - Oct 9 (84 days)
  Start date: 720 (30 days)
  End date: (press Enter)

Hunt Parameters:
  Table: [2] DeviceProcessEvents
  DeviceName: LAPTOP-001
  AccountName: (press Enter - all accounts)

Confirmation:
  Model: gpt-oss:20b
  Mode: Threat Hunt
  Severity: Balanced
  Input size: 42,180 tokens
  Estimated time: 25s
  Cost: FREE (Local/Offline model)
  Proceed with analysis? (y/n): y

→ KQL query built with TimeGenerated filter
→ Queries Azure Log Analytics
→ Analyzes 145 events
→ Detects 2 threats
→ Displays findings with labeled IOCs:
    - DeviceName: LAPTOP-001
    - AccountName: admin
→ Requests feedback
```

### Example: Anomaly Detection

```
Mode: [2] Anomaly Detection
Model: [6] qwen (recommended for Anomaly Detection)
Severity: [2] Balanced
Framework Profile: [5] MITRE ATT&CK
Result View Mode: [2] Only Critical

Timeframe:
  ✓ Data Available: July 17 - Oct 9 (84 days)
  Start date: 168 (7 days)
  End date: (press Enter)

Scan Configuration:
  Time range: 168 hours
  Device filter: (all)
  User filter: (all)
  Tables: [1] All tables

Confirmation:
  Model: qwen3:8b
  Mode: Anomaly Detection
  Severity: Balanced
  Input size: 98,450 tokens
  Estimated time: 52s (2 chunks)
  Cost: FREE (Local/Offline model)
  Proceed with analysis? (y/n): y

→ Scans DeviceLogonEvents (23 anomalies)
→ Scans DeviceProcessEvents (5 anomalies)
→ Scans DeviceNetworkEvents (12 anomalies)
→ Scans SigninLogs (3 anomalies)
→ Detects 43 total anomalies with labeled IOCs
→ Filters to Critical findings only (12 high-confidence)
→ Correlates findings across tables
→ Identifies 2 attack chains
→ Displays results with clear field labels
```

---

## ⚙️ Configuration

### Severity Configuration

Edit `SEVERITY_LEVELS.py`:

```python
SEVERITY_CONFIGS = {
    'relaxed': {
        'name': 'Relaxed',
        'confidence_threshold': 'High',
        'max_log_lines': 25,
        'pattern_multiplier': 0.5
    },
    'balanced': {
        'name': 'Balanced',
        'confidence_threshold': 'Medium',
        'max_log_lines': 50,
        'pattern_multiplier': 1.0
    },
    'strict': {
        'name': 'Strict',
        'confidence_threshold': 'Low',
        'max_log_lines': 100,
        'pattern_multiplier': 1.5
    }
}
```

### Add Custom Severity Tier

```python
'critical': {
    'name': 'CRITICAL (Emergency)',
    'description': 'Wartime mode - flag everything',
    'confidence_threshold': 'Low',
    'pattern_multiplier': 2.0,         # 200% sensitivity
    'max_log_lines': 200,              # Maximum thoroughness
    'min_iocs_to_flag': 1
}
```

### Allowed Tables & Fields

Edit `GUARDRAILS.py`:

```python
ALLOWED_TABLES = {
    "DeviceProcessEvents": {
        "TimeGenerated", "AccountName", "DeviceName", 
        "ProcessCommandLine", "InitiatingProcessCommandLine"
    },
    # Add more tables/fields
}
```

### Customize Detection Patterns

Edit `QWEN_ENHANCER.py`:

```python
self.suspicious_patterns = {
    'custom_c2_detection': [
        r'connection.*30.*per.*minute',  # Your C2 burst rule
        r'beacon.*interval',
        r'callback.*timer'
    ]
}
```

### Pattern Weights

Learned weights are stored in `pattern_weights.json`:

```json
{
  "suspicious_powershell": 1.85,
  "unusual_login_time": 0.75,
  "lateral_movement": 2.40
}
```

### Compliance Profile Configuration

Edit `COMPLIANCE_PROFILES.py`:

```python
PROFILES = {
    'none': {
        'name': 'No Framework',
        'description': 'General threat hunting without framework constraints.',
        'table_scope': None,
        'include_rulepacks': [],
    },
    'owasp': {
        'name': 'OWASP (App/API Focus)',
        'description': 'Web/app/API centric checks and detections.',
        'table_scope': ['SigninLogs', 'AppGatewayFirewallLog'],
        'include_rulepacks': ['owasp_auth_abuse'],
    },
    'stig': {
        'name': 'STIG (Hardening/Compliance)',
        'description': 'System hardening, policy drift, control compliance.',
        'table_scope': ['DeviceRegistryEvents', 'DeviceEvents', 'AzureActivity'],
        'include_rulepacks': ['stig_baseline_controls'],
    },
    'cis': {
        'name': 'CIS Benchmarks',
        'description': 'Baseline configuration controls and deviations.',
        'table_scope': ['AzureActivity', 'SigninLogs', 'DeviceEvents'],
        'include_rulepacks': ['cis_baseline_controls'],
    },
    'mitre': {
        'name': 'MITRE ATT&CK',
        'description': 'Technique-aligned detections and prioritization.',
        'table_scope': None,
        'include_rulepacks': ['mitre_core_ttps'],
    },
}
```

**Profile Features:**
- **Table Scope**: Limits analysis to specific tables (e.g., OWASP focuses on SigninLogs)
- **Rulepacks**: Loads profile-specific detection rules
- **Alert Style**: Custom color coding per framework
- **Merging**: Profiles merge with severity config (non-destructive)

### Result View Mode

Controls post-processing of findings:

- **Strict (default)**: All findings per severity level
- **Only Critical**: High-confidence findings only (High-Signal subset)
- **Critical + Strict**: Two separate sets for comprehensive analysis

---

## 🌍 Real-World Use Cases

### Use Case 1: Active Ransomware Investigation

```bash
Situation: Ransomware alert triggered
Mode: STRICT
Goal: Catch every possible indicator

Result:
- 156 findings (87 High, 42 Med, 27 Low)
- Found: Initial access via phishing
- Found: Credential dumping (mimikatz)
- Found: Lateral movement to 12 hosts
- Found: Encryption prep (volume shadow delete)
- Time saved: 4 hours vs manual review
```

### Use Case 2: Daily Threat Hunt

```bash
Situation: Routine morning hunt
Mode: BALANCED
Goal: Balance speed and accuracy

Result:
- 23 findings (12 High, 11 Med)
- Found: 2 suspicious PowerShell executions
- Found: 1 potential lateral movement
- False positives: 3 (acceptable)
- Time: 30 seconds
```

### Use Case 3: Weekly CISO Report

```bash
Situation: Executive summary
Mode: RELAXED
Goal: High-confidence only, no noise

Result:
- 3 findings (all High confidence)
- 0 false positives
- Clean, actionable report
- Escalated: 1 confirmed incident
- Time: 15 seconds
```

---

## 📈 Performance Metrics

### Speed Comparison

| Dataset Size | STRICT | BALANCED | RELAXED |
|--------------|--------|----------|---------|
| 50 lines | 12s | 8s | 5s |
| 100 lines | 28s | 18s | N/A (capped at 25) |
| 200 lines | 45s | 30s | N/A |
| 500 lines | 87s | 52s | N/A |

### Accuracy Metrics (Based on Feedback)

After 50+ sessions with consistent ratings:

| Mode | Precision | Recall | F1 Score |
|------|-----------|--------|----------|
| STRICT | 62% | 98% | 0.76 |
| BALANCED | 78% | 85% | 0.81 |
| RELAXED | 94% | 65% | 0.77 |

---

## 🔍 Key Features & Improvements

### Intelligent Diagnostics

**Auto-Detection of Available Data:**
- ✅ Shows data retention span at startup (e.g., "142 days of data available")
- ✅ Displays earliest and latest records
- ✅ Total record count across all tables
- ✅ Helps you query the right date ranges

**Query Diagnostics When No Data Found:**
```
🔍 Testing query components...
  [1] Table only: 5 records ✓ (table exists)
  [2] With time filter: 0 records ✗ (date issue!)
  [3] With all filters: 0 records ✗

Shows actual column names, sample timestamps, and identifies mismatches!
```

### Field Name Intelligence

**Automatic Field Mapping:**
- **Time Fields**: All Log Analytics tables use `TimeGenerated` (not `Timestamp`)
- **Account Fields**: Automatically maps to correct field per table:
  - DeviceLogonEvents → `AccountName`
  - DeviceFileEvents → `InitiatingProcessAccountName`
  - SigninLogs → `UserPrincipalName`
  - AzureActivity → `Caller`

**Labeled IOCs:**
All indicators include field names for clarity:
```
Before: slflare, DESKTOP-001, 10.0.5.22
After:  AccountName: slflare
        DeviceName: DESKTOP-001
        IP: 10.0.5.22
```

### Structured Query Input

**No More Natural Language Parsing:**
- Direct table selection from menu
- Optional DeviceName and AccountName filters
- Clear feedback on what will be queried
- Eliminates ambiguity and misinterpretation

### Enhanced Chat Mode

**Chat with actual data:**
- Includes IOCs, device names, and account names in context
- AI can answer "what device?" directly (not "see Finding X")
- Up to 10 findings with full details
- Actionable responses with real data

### Workflow Improvements

**New Flow Order:**
1. Select investigation mode
2. Select language model
3. Select severity level
4. **Set timeframe** (with data availability shown)
5. Specify hunt parameters
6. Execute and analyze
7. Review labeled results
8. Provide feedback

---

## 🚨 Troubleshooting

### Problem: Ollama Timeout

```
ReadTimeout: Read timed out (read timeout=120)
```

**Solution:**
- ✅ Fixed: Timeout increased to 300s
- ✅ Fixed: Smart chunking to 50 lines max
- ✅ Fixed: Fallback to rule-based if LLM fails

### Problem: Too Many Alerts in STRICT Mode

```
Raw findings: 245
Reported (STRICT): 245
```

**Solution:**
- Switch to BALANCED mode
- Review feedback history (patterns may need retraining)
- Increase `confidence_threshold` in STRICT config

### Problem: No Findings in RELAXED Mode

```
Raw findings: 23
Reported (RELAXED): 0
Suppressed: 23
```

**Solution:**
- Try BALANCED mode for broader coverage
- If still no findings, environment may be clean
- Check if patterns are over-trained (all low weights)

### Problem: Rate Limit Errors with OpenAI

**Solution:**
- Switch to a model with larger context
- Use local models (Ollama)
- Reduce `max_log_lines` in severity config

### Problem: No Data Returned from Log Analytics

```
No data returned from Log Analytics.
0 record(s) returned.
```

**Solution:**
The system now includes intelligent diagnostics that show:
1. ✅ Whether the table exists and has data
2. ✅ Available column names (identifies field mismatches)
3. ✅ Sample timestamps (shows actual date range)
4. ✅ Component-by-component testing (isolates the issue)

**Common Causes:**
- **Date Range Mismatch**: Querying Sept when data is in Oct
  - Fix: Check "Data Available" range shown at startup
  - Use hours ago (e.g., `48`) for recent data
- **Wrong Time Field**: Using `Timestamp` instead of `TimeGenerated`
  - Fix: System now auto-uses `TimeGenerated` for Log Analytics
- **Account Name Doesn't Exist**: Filter too specific
  - Fix: Leave filters blank or use partial matches
- **MDE vs Log Analytics**: Data in MDE Advanced Hunting but not Log Analytics
  - Fix: Enable MDE → Log Analytics connector in Azure
- **Wrong Workspace ID**: Querying different workspace than where data is
  - Fix: Verify workspace ID in `_keys.py`

---

## 🎓 Best Practices

### 1. Model Selection

| Task | Recommended Model | Why |
|------|------------------|-----|
| **Threat Hunting** | GPT-OSS:20B | Better reasoning, deep analysis, focused investigations |
| **Anomaly Detection** | Qwen3:8B | Fast, large context, multi-table scanning |
| **Critical Incident** | GPT-OSS:20B or GPT-5 | Quality and accuracy matter most |
| **Daily Operations** | Qwen3:8B | Speed for routine scans |
| **Large Log Volumes** | Qwen3:8B | 128K context handles more data |
| **Complex Attack Chains** | GPT-OSS:20B | Better at connecting patterns |

**Pro Strategy:**
- Use **Qwen** for initial broad scan (fast)
- Use **GPT-OSS** for deep dive on findings (quality)

### 2. Severity Selection

| Situation | Recommended Mode |
|-----------|------------------|
| Active incident | STRICT |
| Breach investigation | STRICT |
| Daily operations | BALANCED |
| Threat hunting | BALANCED |
| Weekly reports | RELAXED |
| Executive summary | RELAXED |
| Unknown environment | BALANCED → adjust |

### 3. Feedback Guidelines

**Be Consistent:**
```
Good: Always rate obvious FPs as 1-2
Bad: Sometimes 2, sometimes 4 for same pattern
```

**Add Comments for Low Ratings:**
```
Rating: 2/5
Comment: "Missed C2 beacon pattern - 30+ connections/min"
→ System learns to add this pattern
```

**Rate the Analysis, Not the Situation:**
```
Good: "Analysis correctly identified threat" → 5/5
Bad: "This breach is bad" → 1/5 (not about analysis quality)
```

### 4. Pattern Maintenance

**Weekly Review:**
```bash
# Check learned weights
python -c "
from LEARNING_ENGINE import get_learning_engine
engine = get_learning_engine()
engine.display_learning_status()
"

# Archive old feedback (keep last 100 sessions)
tail -n 100 _analysis_feedback.jsonl > temp.jsonl
mv temp.jsonl _analysis_feedback.jsonl
```

**Add Custom Patterns:**
```python
# In QWEN_ENHANCER.py
'my_custom_pattern': [
    r'specific.*regex.*here',
    r'another.*pattern'
]
```

### 5. Performance Optimization

**For Large Datasets:**
- Use RELAXED mode first (fast scan)
- If suspicious, rerun with BALANCED
- If confirmed, deep dive with STRICT

**For Production:**
- BALANCED mode as default
- Auto-escalate to STRICT on high-confidence alerts
- Schedule RELAXED mode for reports

---

## 🏆 CTF Mode - Interactive Flag Hunting

### Overview

CTF Mode is an interactive flag hunting pipeline designed for CTF competitions and multi-stage attack investigations. It features session memory, automatic correlation, LLM-assisted query generation, and comprehensive reporting.

### Key Features

- **Session Memory**: Accumulates flags and IOCs across multiple hunts
- **Auto-Correlation**: Suggests filters based on previous flags
- **LLM-Assisted Queries**: Generates KQL queries from objectives
- **Progressive Capture**: Tracks progress through attack chain
- **Final Report**: Auto-generates investigation report in markdown
- **Resume Capability**: Pause and resume hunts anytime
- **Multiple Sessions**: Work on multiple CTFs in parallel

### Quick Start

```bash
# 1. Run the agent
python3 start_button.py

# 2. Select CTF Mode
Select mode [1-4]: 3

# 3. Configure settings
Model: gpt-oss:20b (recommended for accuracy)
Severity: 1 (Critical - for maximum detection)

# 4. Start or resume hunt
[New] Create new investigation
[Continue] Resume existing hunt
```

### The 6-Stage Hunt Flow

#### **Stage 0: Session Context** (shows accumulated knowledge)
```
Session Memory Loaded:
  ✓ Flag 1: Attacker IP = 159.26.106.84
  ✓ Flag 2: Compromised Account = slflare
  
Progress: 2/10 Flags (20%)
```

#### **Stage 1: Intel Briefing** (flag objective)
```
🚩 FLAG 3: EXECUTED BINARY

Objective:
Identify the binary executed by the attacker

Guidance:
Look for binaries from unusual paths (Public, Temp, Downloads)
Focus on compromised account from Flag 2
```

#### **Stage 2: Query Building** (LLM suggests KQL)
```
SUGGESTED QUERY:
DeviceProcessEvents
| where AccountName == "slflare"  // From Flag 2
| where ProcessCommandLine contains "Public"
| project FileName, ProcessCommandLine

OPTIONS:
  [1] Execute this query
  [2] Write custom KQL
  [3] Cancel
```

#### **Stage 3: Execution** (query runs)
```
✓ Query completed
Records returned: 47

RESULTS (first 10 rows):
Timestamp            | FileName        | ProcessCommandLine
---------------------|-----------------|--------------------------------
2025-09-14 18:41:28  | msupdate.exe    | "msupdate.exe" -ExecutionPo...
```

#### **Stage 4: Analysis** (LLM interprets)
```
FINDING:
The binary executed is: msupdate.exe

EVIDENCE:
- Executed at 18:41:28 (earliest suspicious binary)
- By account "slflare" (Flag 2)
- From C:\Users\Public\ (staging directory)

REASONING:
Name mimics Microsoft Update utility. First malicious binary after RDP login.
```

#### **Stage 5: Capture** (save answer)
```
SUGGESTED ANSWER: msupdate.exe

Accept this answer? [Y/n]: y

Add notes (optional): Malicious binary from Public folder

✓ FLAG 3 CAPTURED: msupdate.exe
Progress: 3/10 Flags (30%)
```

#### **Stage 6: Continue** (next action)
```
NEXT STEPS:
  [1] Continue to Flag 4
  [2] Re-investigate Flag 3
  [3] View progress summary
  [4] Generate report and exit
```

### Recovery Options

If you reject an answer at Stage 5, you get recovery options:

```
⚠️  ANSWER REJECTED - RECOVERY OPTIONS

  [1] 🔨 Build new query (start from Stage 2)
  [2] 🧠 Re-analyze same results (new LLM analysis)
  [3] ✍️  Enter answer manually
  [4] 👁️  View raw results
  [5] ⏭️  Skip this flag
  [6] 🚪 Exit hunt
```

### Session Management

**Resume Capability:**
- Sessions are auto-saved after each flag capture
- Resume anytime by selecting CTF mode and choosing "Continue"
- Multiple sessions supported - switch between investigations

**File Structure:**
```
ctf_sessions/
├── {Project_Name}_{timestamp}.jsonl    # Event audit log
├── {Project_Name}_summary.json          # Current state
└── {Project_Name}_report.md             # Final report
```

### Data Source Selection

CTF Mode supports both Microsoft Defender for Endpoint (MDE) and Azure Log Analytics:

```
SELECT DATA SOURCE

[1] Microsoft Defender for Endpoint (MDE) ← Recommended
    • All tables available (DeviceRegistryEvents included!)
    • Real-time data (no ingestion delay)
    • Free (included in MDE license)
    • Best for CTF hunting

[2] Azure Sentinel / Log Analytics
    • Configured tables only
    • Multi-source correlation
    • Long-term storage
```

### Tips for Best Results

1. **Use GPT-OSS:20B or GPT-4o** - Better at KQL generation and analysis
2. **Set Severity to Critical (1)** - Maximum detection sensitivity
3. **Review LLM Queries** - Check suggested KQL before executing
4. **Add Notes** - Brief explanations help final report
5. **Use Correlation Hints** - System auto-suggests filters from previous flags

### Example Workflow

```bash
# Flag 1: Find attacker IP
→ Query: DeviceLogonEvents | where RemoteIPType == 'Public'
→ Result: 159.26.106.84
→ Captured ✓

# Flag 2: Find compromised account
→ LLM suggests: where RemoteIP == '159.26.106.84'  ← Auto-correlation!
→ Query: DeviceLogonEvents | where RemoteIP == '159.26.106.84'
→ Result: slflare
→ Captured ✓

# Flag 3: Find executed binary
→ LLM suggests: where AccountName == 'slflare'  ← Uses Flag 2!
→ Query: DeviceProcessEvents | where AccountName == 'slflare'
→ Result: msupdate.exe
→ Captured ✓
```

Each flag builds on previous discoveries automatically!

---

## 🤖 Enhanced Model Management

### Adding New Models

The system now **automatically detects** whether a model is local or cloud, and routes accordingly. **No code changes needed!** Just add the model to `GUARDRAILS.py`.

### How Model Routing Works

**Automatic Detection:**
```python
def is_local_model(model_name):
    """
    Determines if a model is local/Ollama or cloud/OpenAI
    Based on cost in GUARDRAILS.ALLOWED_MODELS
    """
    model_info = GUARDRAILS.ALLOWED_MODELS[model_name]
    # Local models have zero cost
    return (model_info["cost_per_million_input"] == 0.00 and 
            model_info["cost_per_million_output"] == 0.00)
```

**Routing Logic:**
- If `cost == 0.00` → Routes to Ollama (local)
- If `cost > 0.00` → Routes to OpenAI API (cloud)

### Adding a Cloud Model

**Step 1: Add to GUARDRAILS.py**
```python
ALLOWED_MODELS = {
    # ... existing models ...
    
    "gpt-6-ultra": {
        "max_input_tokens": 500_000,
        "max_output_tokens": 64_000,
        "cost_per_million_input": 5.00,    # ← Set actual cost
        "cost_per_million_output": 15.00,  # ← Set actual cost
        "tier": {
            "free": None,
            "1": 50_000,
            "2": 500_000,
            "3": 1_000_000,
            "4": 3_000_000,
            "5": 50_000_000
        }
    }
}
```

**Done!** System automatically detects as cloud model.

### Adding a Local Model

**Step 1: Add to GUARDRAILS.py**
```python
ALLOWED_MODELS = {
    # ... existing models ...
    
    "llama3:70b": {
        "max_input_tokens": 128_000,
        "max_output_tokens": 32_768,
        "cost_per_million_input": 0.00,   # ← Zero cost = local model
        "cost_per_million_output": 0.00,  # ← Zero cost = local model
        "tier": {
            "free": None,
            "1": None,
            "2": None,
            "3": None,
            "4": None,
            "5": None
        }
    }
}
```

**Step 2: (Optional) Add Ollama Mapping**
If your model name differs from Ollama's actual name, add to mapping in `CTF_HUNT_MODE.py`:
```python
def get_ollama_model_name(model_name):
    """Map friendly names to Ollama model names"""
    ollama_mapping = {
        "qwen": "qwen3:8b",
        "gpt-oss:20b": "gpt-oss:20b",
        "llama3": "llama3:70b",           # ← Add your mapping
    }
    return ollama_mapping.get(model_name, model_name)
```

**Step 3: Pull Model in Ollama**
```bash
ollama pull llama3:70b
ollama list  # Verify it's available
```

**Done!** Model is available in all modes.

### Local Mix Models (Intelligent Routing)

The **Local Mix** feature automatically selects the optimal local model (GPT-OSS or Qwen) for each task, or uses both in parallel for hybrid analysis.

**How It Works:**
- **Hybrid Mode (default)**: Uses both GPT-OSS 20B and Qwen 8B in parallel
  - **GPT-OSS 20B** → Used for reasoning-heavy tables (DeviceProcessEvents, DeviceRegistryEvents)
  - **Qwen 8B** → Used for high-volume tables (DeviceNetworkEvents, SigninLogs)
  - **Parallel Processing** → Both models analyze simultaneously, results are fused
- **Intelligent Routing**: Falls back to token count if table not categorized
- **Adaptive Configuration**: Adjusts based on investigation mode and severity level
- **Result Fusion**: Combines findings from both models with confidence weighting

**Usage:**
```
Select model [1-7]: 5  # or just press Enter (default)

✓ Selected: local-mix
Type: Smart Mix (GPT-OSS + Qwen) - Auto-selects best local model
Mode: Hybrid (parallel processing)
```

**Benefits:**
- ✅ FREE - No API costs
- ✅ Unlimited tokens
- ✅ Intelligent - Auto-selects optimal model per task
- ✅ Hybrid - Parallel processing for comprehensive analysis
- ✅ Transparent - Shows which model was selected
- ✅ Adaptive - Configures based on investigation context

### Model Comparison

| Model | Context | Params | Cost | Best For |
|-------|---------|--------|------|----------|
| **gpt-5-mini** | 272K | Cloud | $0.25/$2.00 | Default, balanced |
| **gpt-5** | 272K | Cloud | $1.25/$10.00 | Advanced reasoning |
| **qwen3:8b** | 128K | 8B | FREE | Anomaly Detection - Fast, large context |
| **gpt-oss:20b** | 32K | 20B | FREE | Threat Hunting - Better reasoning |
| **local-mix** | Both | Both | FREE | Auto-optimized per task |

---

## 🔧 Setup & Configuration Guides

### MDE Setup Guide

**Where to Paste Your Credentials:**

Open `_keys.py` and find lines 12-14:

```python
# ═══════════════════════════════════════════════════════════════════════════
# Microsoft Defender for Endpoint (MDE) - Advanced Hunting API
# ═══════════════════════════════════════════════════════════════════════════
# 👉 PASTE YOUR MDE CREDENTIALS HERE:

MDE_TENANT_ID = "YOUR_TENANT_ID_HERE"        # ← REPLACE THIS
MDE_CLIENT_ID = "YOUR_CLIENT_ID_HERE"        # ← REPLACE THIS
MDE_CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"  # ← REPLACE THIS
```

**Replace with your actual values:**
```python
MDE_TENANT_ID = "12345678-1234-1234-1234-123456789abc"
MDE_CLIENT_ID = "87654321-4321-4321-4321-cba987654321"
MDE_CLIENT_SECRET = "AbC~123XyZ456_VeryLongSecretStringHere789"
```

**Using MDE:**

When you start CTF Mode, you'll see:
```
SELECT DATA SOURCE
[1] Microsoft Defender for Endpoint (MDE) ← Recommended
[2] Azure Sentinel / Log Analytics

Select data source [1-2] (default: 1): [Press Enter]
```

**Benefits of MDE:**
- ✅ All tables available (DeviceRegistryEvents included!)
- ✅ Real-time data (no ingestion delay)
- ✅ Free (included in MDE license)
- ✅ Best for CTF hunting

### Azure Log Analytics Setup

**1. Authenticate with Azure:**
```bash
az login
```

**2. Set Log Analytics Workspace ID:**
```python
# _keys.py
LOG_ANALYTICS_WORKSPACE_ID = "Peterwpan1983"
OPENAI_API_KEY = "your-openai-api-key"
```

**3. Verify Connection:**
The system will test authentication at startup and show available data range.

### Local Model Setup (Ollama)

**1. Install Ollama:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**2. Pull Models:**
```bash
ollama pull qwen3:8b
ollama pull gpt-oss:20b
```

**3. Verify:**
```bash
ollama list
```

**4. Test:**
```bash
python start_button.py
# Select model [5] or [6] for local models
```

---

## 🚀 Advanced Features

### Enhanced Anomaly Detection

The Enhanced Anomaly Detection Pipeline transforms routine security scanning into production-grade SOC operations.

**4-Stage Analysis Pipeline:**

1. **Statistical Analysis** (Fast, Factual)
   - Time-based anomalies (off-hours, weekends)
   - Frequency anomalies (Z-score > 3σ)
   - Rare events (< 1% frequency)
   - Network diversity (unusual IPs)

2. **Baseline Comparison** (Behavioral)
   - Compare to learned normal patterns
   - Detect deviations from typical behavior
   - Updates baseline after each scan

3. **LLM Analysis** (Only on outliers)
   - Send filtered records to model
   - Confirm true anomalies vs false positives
   - Generate detailed findings
   - **90% token reduction** (only outliers analyzed)

4. **Cross-Table Correlation**
   - User-based: Multi-stage attacks
   - Device-based: Compromised hosts
   - IP-based: Lateral movement

**Results:**
- Professional SOC analyst summary
- Risk assessment
- Prioritized recommendations
- Attack narratives/timelines

### Custom KQL Expert Mode

For advanced users who want to write their own KQL queries:

**Usage:**
```
Query Method:
[1] Natural Language
[2] Structured  
[3] Custom KQL  ← Choose this!

Select: 3
```

**Enter Your KQL:**
```
Enter your KQL query (type 'END' when done):
  DeviceProcessEvents
  | where ProcessCommandLine contains "powershell"
  | where ProcessCommandLine contains "-enc"
  | project TimeGenerated, AccountName, ProcessCommandLine, SHA256
  END
```

**System will:**
- Auto-add time filter based on your timeframe
- Execute query
- Use LLM to filter results based on CTF hints/context
- Provide flag suggestions and next steps

### IOC Extraction Reference

The system extracts **12 different IOC types**:

| Type | Pattern/Source | Example | Boost |
|------|---------------|---------|-------|
| IP Address | IPv4 regex | `79.76.123.251` | 1x |
| IPv6 Address | IPv6 regex | `2607:fea8::1` | 1x |
| File Hash (MD5) | 32-char hex | `5d41402abc4b2a76b9719d911017c592` | 5x |
| File Hash (SHA256) | 64-char hex | `abc123def...` | 5x |
| Domain | FQDN regex | `malicious.com` | 1x |
| Email | Email regex | `attacker@bad.com` | 1x |
| URL | HTTP/HTTPS | `http://exfil.com/data` | 3x |
| Base64 | Base64 pattern | `UG93ZXJTaGVs...` | 2x |
| ProcessCommandLine | From logs | `powershell -enc [data]` | **4x** |
| Parent Command | InitiatingProcess | `cmd.exe /c whoami` | **4x** |
| Account Name | From CSV | `slflare` | 1x |
| Device Name | From CSV | `slflarewinsysmo` | 1x |

**Boost** = Relevance multiplier (higher = prioritized in results)

### Enhanced Session Menu

**Multi-level navigation:**
```
Level 1: Main Session Menu
  [C] Continue with existing hunts
  [N] Start new investigation

Level 2: Project Selection
  [1] RDP Password Spray (3 flags)
  [2] Operation Lurker (5 flags)
  [B] Back

Level 3: Project Actions
  [1] Continue hunt
  [2] Rename project
  [3] Delete project
  [B] Back
```

**Features:**
- ✅ Project renaming capability
- ✅ Back navigation at each level
- ✅ Auto-update all files on rename
- ✅ Multiple sessions supported

### Schema System

The system includes comprehensive Azure schema reference that teaches the LLM exact table structures:

**Features:**
- Complete table schemas with field types
- Field descriptions and allowed values
- KQL syntax rules and best practices
- Common query patterns per table
- Example values for each field

**Benefits:**
- ✅ Correct field names in generated queries
- ✅ Proper data types
- ✅ KQL syntax compliance
- ✅ Reduced query errors

### Compliance Framework Integration

The system supports multiple compliance frameworks with profile-aware detection:

**Supported Frameworks:**
- **OWASP**: Application and API security focus (SigninLogs, AppGatewayFirewallLog)
- **STIG**: System hardening and compliance (DeviceRegistryEvents, DeviceEvents, AzureActivity)
- **CIS**: Baseline configuration controls (AzureActivity, SigninLogs, DeviceEvents)
- **MITRE ATT&CK**: Technique-aligned detections (all tables)

**How It Works:**
1. Select framework profile during setup
2. System automatically filters tables per framework
3. Loads framework-specific rulepacks
4. Applies profile-aware detection patterns
5. Enriches findings with control mappings (via Insight Engine)

**Benefits:**
- ✅ Focused analysis per framework scope
- ✅ Reduced false positives through table filtering
- ✅ Compliance-aligned findings
- ✅ Framework-specific reporting

### Time Estimation System

The system provides accurate time estimates for all models before analysis:

**Features:**
- **Model-Specific Profiles**: Different estimation algorithms for OpenAI vs Ollama
- **Chunking Awareness**: Calculates time for chunked processing
- **Hybrid Models**: Parallel processing time estimates
- **Display Formatting**: Human-readable time display (e.g., "28s", "2m 15s", "45s (3 chunks)")

**Supported Models:**
```python
OpenAI Models:
  - gpt-4.1-nano: 50K tokens/sec
  - gpt-4.1: 40K tokens/sec
  - gpt-5-mini: 60K tokens/sec
  - gpt-5: 45K tokens/sec

Ollama Models:
  - qwen3:8b: 2K tokens/sec (128K context)
  - gpt-oss:20b: 1K tokens/sec (32K context)
  - local-mix: Parallel processing (max of both models)
```

**Example Display:**
```
Estimated time: 28s
Estimated time: 2m 15s (3 chunks)
Estimated time: 45s (2 chunks) (parallel)
```

### Pre-Analysis Confirmation

Before starting analysis, the system shows a comprehensive confirmation screen:

**Displayed Information:**
- Selected model and investigation mode
- Severity level and framework profile
- Estimated input size (tokens)
- Estimated processing time
- Cost information (FREE for local models)
- Processing details:
  - Chunked vs single-pass processing
  - Local/offline vs cloud API
  - Parallel processing for hybrid models

**Example Confirmation:**
```
════════════════════════════════════════════════════════════
📊 ANALYSIS CONFIRMATION
════════════════════════════════════════════════════════════
Model: gpt-oss:20b
Mode: Threat Hunt
Severity: Balanced
Input size: 45,230 tokens
Estimated time: 28s
Cost: FREE (Local/Offline model)

Processing Details:
  • Single-pass processing
  • Local/Offline model (no API calls)

Proceed with analysis? (y/n):
```

**Benefits:**
- ✅ Transparency before processing
- ✅ Cost awareness (especially for cloud models)
- ✅ Time planning
- ✅ Opportunity to adjust parameters

---

## 📚 Reference Materials

### IOC Extraction Patterns

**Command Line Extraction:**
Commands are extracted if they contain:
- Suspicious keywords (50+ patterns)
- Very long (>200 characters - often obfuscated)
- High special char density (>10 special chars)
- CTF keywords (`flag{`, `ctf`, `decode`, `hidden`)

**Common Patterns:**
- PowerShell obfuscation: `powershell.*-enc`, `iex\s*\(`
- Credential access: `mimikatz`, `procdump`, `reg save`
- Lateral movement: `psexec`, `wmic`, `net use`
- Exfiltration: `curl`, `certutil`, `Compress-Archive`

### CTF Flag Hunting Tips

**Quick Reference:**
```
Stage 1: Intel Capture
  → Paste flag info
  → Type: DONE
  → Press: Enter

Stage 2: Query Building  
  → Type: 1  (to execute LLM's query)
  → Press: Enter

Stage 3: Execution
  → Nothing to type (automatic)

Stage 4: Analysis
  → Press: Enter  (just once)

Stage 5: Flag Capture
  → Type: 1  (to accept answer)
  → Press: Enter

Stage 6: What's Next
  → Type: 2  (for next flag)
  → Press: Enter
```

**Recovery Options (if rejecting answer):**
- `[1]` New query → Back to Stage 2
- `[2]` Re-analyze → Back to Stage 4
- `[3]` Manual entry → Back to Stage 5
- `[4]` View raw → Stay in recovery
- `[5]` Skip flag → Exit
- `[6]` Exit → Exit

### Model Selection Guide

| Task | Recommended Model | Why |
|------|------------------|-----|
| **Threat Hunting** | GPT-OSS:20B | Better reasoning, deep analysis |
| **Anomaly Detection** | Qwen3:8B | Fast, large context, multi-table scanning |
| **CTF Mode** | GPT-OSS:20B or GPT-4o | Better KQL generation |
| **Critical Incident** | GPT-OSS:20B or GPT-5 | Quality and accuracy matter most |
| **Daily Operations** | Qwen3:8B or local-mix | Speed for routine scans |
| **Large Log Volumes** | Qwen3:8B | 128K context handles more data |

### KQL Field Reference

**Time Fields:**
- Azure Log Analytics: `TimeGenerated` (not `Timestamp`)
- MDE Advanced Hunting: `Timestamp`

**Account Fields (vary by table):**
- DeviceLogonEvents → `AccountName`
- DeviceFileEvents → `InitiatingProcessAccountName`
- SigninLogs → `UserPrincipalName`
- AzureActivity → `Caller`

**Device Fields:**
- Most tables → `DeviceName`
- Some tables → `Computer`

**IP Fields:**
- DeviceLogonEvents → `RemoteIP`
- DeviceNetworkEvents → `RemoteIP`, `LocalIP`

### Troubleshooting Quick Reference

| Problem | Solution |
|---------|----------|
| Ollama timeout | Timeout increased to 300s, check chunking |
| Too many alerts | Switch to BALANCED mode, review feedback |
| No findings | Try BALANCED mode, check patterns |
| Rate limit errors | Switch to local models, reduce `max_log_lines` |
| No data returned | Check date range, verify workspace ID |
| Query errors | Check field names, use schema reference |

---

## 📁 Project Structure

```
openAI_Agentic_SOC_Analyst/
│
├── start_button.py                      # Main entry point
├── _keys.py                      # Configuration & secrets
│
├── EXECUTOR.py                   # Query execution & hunting
├── THREAT_HUNT_PIPELINE.py       # Targeted investigation
├── ANOMALY_DETECTION_PIPELINE.py # Automated scanning
│
├── CORRELATION_ENGINE.py         # Attack chain correlation
├── LEARNING_ENGINE.py            # Self-learning system
├── FEEDBACK_MANAGER.py           # User feedback collection
│
├── MODEL_SELECTOR.py             # Model selection UI
├── OLLAMA_CLIENT.py              # Local model interface
├── QWEN_ENHANCER.py              # Qwen model enhancement
├── GPT_OSS_ENHANCER.py           # GPT-OSS enhancement
│
├── GUARDRAILS.py                 # Security controls
├── SEVERITY_LEVELS.py            # Severity filtering
├── PROMPT_MANAGEMENT.py          # Prompt templates
├── LOCAL_QUERY_PARSER.py         # Offline query planning
├── UTILITIES.py                  # Helper functions
├── CHAT_MODE.py                  # Interactive chat
│
├── COMPLIANCE_PROFILES.py        # Framework profile selection
├── CONFIRMATION_MANAGER.py       # Pre-analysis confirmation
├── TIME_ESTIMATOR.py             # Time estimation system
├── HYBRID_ENGINE.py              # Hybrid model engine
├── RETRIEVAL_MEMORY.py           # Killchain exemplar retrieval
├── SCHEMAS.py                     # Schema validation
│
├── _threats.jsonl                # Detected threats (output)
├── _analysis_feedback.jsonl      # User feedback (learning)
├── pattern_weights.json          # Learned weights
│
└── README.md                     # This file
```

---

## 📊 Output Files

### `_threats.jsonl`
Detected threats in JSON Lines format:
```json
{
  "title": "Suspicious PowerShell Execution",
  "confidence": "High",
  "mitre": {"tactic": "Execution", "technique": "T1059.001"},
  "indicators_of_compromise": ["DESKTOP-001", "powershell.exe -enc"],
  "log_lines": ["2025-10-08T10:15:23Z,admin,DESKTOP-001,powershell.exe..."],
  "tags": ["powershell", "encoded-command"]
}
```

### `_analysis_feedback.jsonl`
User feedback for learning:
```json
{
  "timestamp": "2025-10-08T14:30:00",
  "findings": [...],
  "user_rating": 4,
  "user_comments": "Good detection, one false positive"
}
```

### `pattern_weights.json`
Learned pattern adjustments:
```json
{
  "lateral_movement": 1.3,
  "powershell_obfuscation": 0.7,
  "credential_dumping": 1.3
}
```

---

## 🎯 Summary

### What You Built

An intelligent, self-learning SOC analyst that:

1. **Adapts to Context**: 3-tier severity system (Relaxed/Balanced/Strict)
2. **Learns from You**: Active learning from 1-5 ratings
3. **Hybrid Detection**: 165+ rule patterns + LLM analysis
4. **Finds Attack Chains**: Correlates events across tables
5. **Detects Anomalies**: Behavioral baseline + outlier detection
6. **Works Offline**: Local models for privacy
7. **Maps to MITRE**: 610+ ATT&CK technique mappings
8. **Improves Over Time**: Pattern weights adjust based on feedback
9. **Compliance Frameworks**: OWASP, STIG, CIS, MITRE profile support
10. **Time Estimation**: Accurate processing time estimates for all models
11. **Pre-Analysis Confirmation**: Transparent cost and time information
12. **Result View Modes**: Strict, Critical-only, or both for comprehensive analysis

### Key Innovation

**Dynamic Confidence = (Pattern Weight × Severity Multiplier) + User Feedback**

Example:
```
lateral_movement pattern
├─ Base: Medium (5/10)
├─ User feedback: 1.3x (you rated high)
├─ Severity: STRICT 1.5x
└─ Result: 5 × 1.3 × 1.5 = 9.75/10 → High confidence
```

**Your SOC analyst adapts to:**
1. **Context** (severity mode)
2. **Your preferences** (feedback learning)
3. **Environment** (pattern performance)

**Result: Personalized threat detection that improves every run.** 🎯☕

---

## 🔐 Security Notes

- Keep `_keys.py` secure (contains API keys)
- Use Azure RBAC for Log Analytics access control
- Review `GUARDRAILS.py` for allowed tables/fields
- Local models recommended for sensitive data
- Threat data stored locally in `_threats.jsonl`
- All learning happens offline (no data leaves your machine)
- IOCs displayed with field name labels for clarity

## ⚠️ Important: MDE vs Log Analytics

**This agent queries Azure Log Analytics, NOT MDE Advanced Hunting directly!**

| Data Source | Field Names | Access Method |
|-------------|-------------|---------------|
| **MDE Advanced Hunting** | Uses `Timestamp` | security.microsoft.com portal |
| **Log Analytics** | Uses `TimeGenerated` | This agent queries here |

**Why does this matter?**
- MDE may have 30 days of data
- Log Analytics may have different retention
- Data must be exported from MDE → Log Analytics
- Configure: MDE Settings → Advanced Features → Microsoft Sentinel integration

**Data Availability:**
- Agent shows available data range at startup
- Displays: "Earliest: [date] to Latest: [date]"
- Query within this range for results
- Outside this range = 0 results (no data)

---

## 📞 Support

**Issues?**
1. Check troubleshooting section above
2. Review error messages (system provides hints)
3. Try BALANCED mode if others fail
4. Check `_analysis_feedback.jsonl` for learning issues

**Questions?**
- Severity selection: Use BALANCED when unsure
- Too many alerts: Lower severity or review feedback
- Too few alerts: Raise severity or check patterns
- Performance slow: Use RELAXED mode

**Remember:** The system learns from you. Rate consistently, and it becomes YOUR personal SOC analyst. 🚀

---

## 🔮 Future Enhancements

**Planned:**
- [ ] Auto-recommend severity based on environment
- [ ] Time-based severity (strict during business hours)
- [ ] Per-table severity overrides
- [ ] Weekly self-tuning reports
- [ ] C2 burst detection (30/min threshold)
- [ ] Timestamp burst analysis
- [ ] UDP flood detection

**Possible:**
- [ ] API mode with severity parameter
- [ ] Severity presets per threat type
- [ ] Machine learning for optimal threshold
- [ ] SIEM integration
- [ ] Slack/Teams notifications
- [ ] PDF report generation

---

## 🤝 Contributing

Improvements welcome! Key areas:
- Additional log source integrations
- New threat detection patterns
- Enhanced correlation algorithms
- Model optimization
- Additional behavioral baselines

---

## 📝 License

MIT License - See LICENSE file for details

---

---

## 🆕 Recent Improvements

### Response Parsing System
- ✅ **Added**: Unified RESPONSE_PARSER module for different output formats
- ✅ Threat Hunt format parsing (`{"findings": [...]}`)
- ✅ CTF format parsing (`{"suggested_answer": "...", "confidence": "..."}`)
- ✅ Fallback parsing for partial/invalid JSON responses
- ✅ Pattern extraction from text when JSON parsing fails

### Enhanced Hybrid Engine
- ✅ **Enhanced**: Dynamic configuration based on investigation mode
- ✅ **Enhanced**: Adaptive model selection per severity level
- ✅ **Enhanced**: Query method awareness (llm, structured, custom_kql)
- ✅ **Enhanced**: Parallel processing with intelligent result fusion
- ✅ **Enhanced**: Chunked processing for large datasets
- ✅ **Enhanced**: Context-aware model routing (volume vs reasoning tables)

### Investigation Context & Guidance
- ✅ **Added**: Investigation context input (IOCs, hints, techniques)
- ✅ **Added**: Guidance mode with killchain exemplar retrieval
- ✅ **Added**: Known killchain pattern matching
- ✅ **Added**: Evidence requirements enforcement

### Query Method Selection
- ✅ **Added**: Natural Language (LLM-Assisted) query building
- ✅ **Added**: Custom KQL (Expert Mode) for advanced users
- ✅ **Removed**: Structured manual input (simplified to LLM or Custom KQL)
- ✅ LLM picks table & filters automatically from natural language

### Offline Model Security
- ✅ **Added**: Offline Guardrails for local models (defense-in-depth)
- ✅ **Added**: Violation logging for audit trail
- ✅ **Added**: Strict mode enforcement for security controls
- ✅ **Added**: Runtime validation for offline model operations

### Model Selection Enhancements
- ✅ **Updated**: Default model changed to `local-mix` (hybrid local models)
- ✅ **Enhanced**: Runtime token validation and limit checking
- ✅ **Enhanced**: Cost estimation with model switching recommendations
- ✅ **Enhanced**: Offline model detection and routing

### Structured Query Input
- ❌ **Removed**: Natural language prompt parsing (ambiguous)
- ✅ **Added**: Direct table/filter selection (precise)
- ✅ Clear menu-based parameter input
- ✅ Shows what will be queried before execution

### Intelligent Diagnostics
- ✅ Auto-detects available data range (142 days, 27M+ records)
- ✅ Component-by-component query testing
- ✅ Shows actual column names in your tables
- ✅ Identifies time field mismatches automatically
- ✅ Sample timestamps to verify date ranges

### Field Name Intelligence
- ✅ Correct time field: `TimeGenerated` for all Log Analytics tables
- ✅ Proper account field mapping per table
- ✅ Labeled IOCs: `AccountName:`, `DeviceName:`, `IP:`
- ✅ No more hash/IP clutter - focus on actionable IOCs

### Enhanced Chat Mode
- ✅ Includes actual IOC data (not just references)
- ✅ Direct answers ("Device: DESKTOP-001" not "see Finding X")
- ✅ Up to 10 findings with full context

### Improved Workflow
- ✅ Timeframe auto-set to 365 days (configurable)
- ✅ Shows available data before asking for dates
- ✅ Explicit KQL queries with visible timestamps
- ✅ Authentication test at startup

### Compliance Framework Integration
- ✅ **Added**: Framework profile selection (OWASP, STIG, CIS, MITRE)
- ✅ Profile-aware table filtering
- ✅ Rulepack integration per framework
- ✅ Framework-specific detection patterns
- ✅ Compliance-aligned findings with control mappings

### Time Estimation & Confirmation
- ✅ **Added**: Universal time estimation for all models
- ✅ Model-specific performance profiles
- ✅ Chunking-aware time calculations
- ✅ Pre-analysis confirmation screen
- ✅ Cost transparency (FREE for local models)
- ✅ Processing details preview (chunking, parallel processing)

### Result View Modes
- ✅ **Added**: Flexible result filtering options
- ✅ Strict mode (all findings per severity)
- ✅ Critical-only mode (high-confidence subset)
- ✅ Critical + Strict mode (two separate sets)

### Enhanced Schema & Validation
- ✅ **Added**: Pydantic schema validation (SCHEMAS.py)
- ✅ Evidence-bound finding extensions
- ✅ MITRE mapping schema structure
- ✅ Finding structure validation

### Killchain & Pattern Recognition
- ✅ **Added**: Retrieval Memory system for killchain exemplars
- ✅ Known pattern recognition (e.g., RDP password spray)
- ✅ Sigma adapter for rule hints
- ✅ Evidence-focused guidance

---

**Built with ❤️ for SOC analysts who need AI-powered, self-learning threat hunting**
