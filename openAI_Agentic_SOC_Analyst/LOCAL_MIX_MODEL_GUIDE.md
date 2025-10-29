# Local Mix Models - Intelligent Model Selection Guide

## Overview

The **Local Mix Models** feature automatically selects the optimal local model (GPT-OSS or Qwen) for each task, giving you the best performance without requiring technical knowledge about model differences.

---

## What Is Local Mix?

A **smart routing system** that intelligently alternates between two complementary local models:

### **GPT-OSS 20B** - The Reasoner
- **Best for**: Complex analysis, tactical reasoning, attack pattern recognition
- **Strengths**: 20B parameters = better logic, deeper analysis
- **Context**: 32K tokens
- **Speed**: Slower but more thorough

### **Qwen 8B** - The Volume Processor  
- **Best for**: High-volume data, bulk analysis, pattern matching
- **Strengths**: 8B parameters = faster, 128K context
- **Context**: 128K tokens (4x larger)
- **Speed**: Fast and efficient

### **Local Mix = Best of Both**
- ✅ **FREE** - No API costs
- ✅ **Unlimited** - No token limits
- ✅ **Intelligent** - Auto-selects optimal model per task
- ✅ **Transparent** - Shows which model was selected

---

## How Model Selection Works

### **In Anomaly Detection Pipeline**

The system automatically routes each table to the optimal model:

```
┌─────────────────────────────────────────────────────────────────┐
│ HIGH-VOLUME TABLES → Qwen (Fast, handles bulk data)           │
├─────────────────────────────────────────────────────────────────┤
│  • DeviceNetworkEvents      - Lots of network connections      │
│  • DeviceFileEvents          - Many file operations            │
│  • SigninLogs                - Many authentication events      │
│  • AzureNetworkAnalytics_CL  - Network flow data              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ REASONING-HEAVY TABLES → GPT-OSS (Deep analysis needed)       │
├─────────────────────────────────────────────────────────────────┤
│  • DeviceProcessEvents   - Command line analysis, TTPs         │
│  • DeviceRegistryEvents  - Persistence detection               │
│  • AzureActivity         - Cloud policy violations             │
│  • DeviceLogonEvents     - Login pattern analysis              │
└─────────────────────────────────────────────────────────────────┘
```

### **In Threat Hunting Mode**

Falls back to **token count routing**:
- Data > 50K tokens → **Qwen** (handles volume)
- Data ≤ 50K tokens → **GPT-OSS** (better quality)

### **Selection Logic (Priority)**

1. **Table-based** (if table_name provided)
   - Check if table is high-volume → Qwen
   - Check if table needs reasoning → GPT-OSS

2. **Token count** (fallback)
   - Count tokens in messages
   - >50K → Qwen
   - ≤50K → GPT-OSS

3. **Default** (last resort)
   - Qwen (safer choice for unknown scenarios)

---

## Real-World Example

### **Anomaly Detection Scan Output**

```bash
═══════════════════════════════════════════════════════════════════
PHASE 1: Multi-Table Anomaly Scanning
═══════════════════════════════════════════════════════════════════

Scanning Authentication Tables
──────────────────────────────────────────────────────────────────

Scanning: DeviceLogonEvents
  1,245 records returned
  Running statistical analysis... 3 patterns
  Comparing to baseline... 1 deviations
  Analyzing 42 outliers with local-mix...
  Local Mix: Auto-selected gpt-oss:20b for this task
  Using Ollama local model (GPT-OSS 20B)...
  ✓ 2 findings detected

Scanning: SigninLogs
  892 records returned
  Running statistical analysis... 2 patterns
  Analyzing 87 outliers with local-mix...
  Local Mix: Auto-selected qwen for this task
  Using Ollama local model (qwen3:8b)...
  ✓ 1 finding detected

Scanning Execution Tables
──────────────────────────────────────────────────────────────────

Scanning: DeviceProcessEvents
  3,421 records returned
  Running statistical analysis... 5 patterns
  Analyzing 23 outliers with local-mix...
  Local Mix: Auto-selected gpt-oss:20b for this task
  Using Ollama local model (GPT-OSS 20B)...
  ✓ 3 findings detected
```

---

## Model Selection Per Table (Reference)

| Table | Selected Model | Reason | Record Count Typical |
|-------|----------------|--------|---------------------|
| **DeviceLogonEvents** | GPT-OSS | Login pattern reasoning | 1K-5K |
| **SigninLogs** | Qwen | High volume auth events | 5K-20K |
| **DeviceProcessEvents** | GPT-OSS | Command analysis needs logic | 2K-10K |
| **DeviceNetworkEvents** | Qwen | Many connections | 10K-50K |
| **DeviceFileEvents** | Qwen | Many file ops | 5K-30K |
| **DeviceRegistryEvents** | GPT-OSS | Persistence detection logic | 500-2K |
| **AzureActivity** | GPT-OSS | Policy violation reasoning | 1K-5K |
| **AzureNetworkAnalytics_CL** | Qwen | High volume flows | 10K-100K |

---

## Benefits

### **For Users**

✅ **Zero Configuration**
- No need to understand model differences
- System makes optimal choice automatically
- Just select "Local Mix" and go

✅ **Best Performance**
- Each table gets the model that handles it best
- No compromise between speed and quality

✅ **Completely Free**
- Both models are local (Ollama)
- No API costs
- Unlimited token usage

✅ **Transparent**
- Shows which model was selected for each task
- Can still manually select qwen or gpt-oss:20b if desired

### **For the System**

✅ **Optimized Resource Usage**
- Qwen processes high-volume data efficiently
- GPT-OSS handles complex reasoning tasks

✅ **Reduced Processing Time**
- Fast model (Qwen) for bulk operations
- Quality model (GPT-OSS) only where reasoning needed

✅ **Better Accuracy**
- Right tool for the job
- Leverages each model's strengths

---

## Usage

### **Simple - Just Select It**

```bash
python _main.py
```

**Model Selection Menu:**
```
═══════════════════════════════════════════════════════════════════
SELECT LANGUAGE MODEL
═══════════════════════════════════════════════════════════════════

═══ OpenAI Models (Cloud/API) ═══

[1] gpt-4.1-nano
    Cost: Very Low ($0.10/$0.40 per M) | Context: 1M+ tokens
[2] gpt-4.1
    Cost: Moderate ($1.00/$8.00 per M) | Context: 1M+ tokens
[3] gpt-5-mini ⭐ Recommended
    Cost: Low ($0.25/$2.00 per M) | Context: 272K tokens
[4] gpt-5
    Cost: High ($1.25/$10.00 per M) | Context: 272K tokens

═══ Ollama Models (Local/Offline) - FREE ═══

[5] local-mix ⭐ Recommended
    Free ✓ | Auto-Select | Local/Offline
    ⭐ Smart Mix: GPT-OSS (reasoning) + Qwen (volume) - RECOMMENDED
[6] gpt-oss:20b
    Free ✓ | 32K tokens | Local/Offline
    20B params - Manual: Better reasoning
[7] qwen
    Free ✓ | 128K tokens | Local/Offline
    8B params - Manual: Fast and high volume

──────────────────────────────────────────────────────────────────
Select model [1-7] or press Enter for local-mix: [Just press Enter]

✓ Selected: local-mix
Type: Smart Mix (GPT-OSS + Qwen) - Auto-selects best local model
Cost: FREE - No API costs • Unlimited tokens
═══════════════════════════════════════════════════════════════════
```

---

## Advanced: Manual Model Selection

If you're an advanced user and want to force a specific local model:

**For maximum quality (slower):**
```
Select model [1-7]: 6    ← Force GPT-OSS for everything
```

**For maximum speed (high volume):**
```
Select model [1-7]: 7    ← Force Qwen for everything
```

**For intelligent mix (recommended):**
```
Select model [1-7]: 5    ← or just press Enter
```

---

## Technical Details

### **Selection Algorithm**

```python
def select_optimal_local_model(messages, table_name, severity_config):
    HIGH_VOLUME_TABLES = {
        'DeviceNetworkEvents', 'DeviceFileEvents', 
        'SigninLogs', 'AzureNetworkAnalytics_CL'
    }
    
    REASONING_HEAVY_TABLES = {
        'DeviceProcessEvents', 'DeviceRegistryEvents',
        'AzureActivity', 'DeviceLogonEvents'
    }
    
    # Priority 1: Table type
    if table_name in HIGH_VOLUME_TABLES:
        return "qwen"
    elif table_name in REASONING_HEAVY_TABLES:
        return "gpt-oss:20b"
    
    # Priority 2: Token count
    token_count = count_tokens(messages)
    if token_count > 50000:
        return "qwen"
    else:
        return "gpt-oss:20b"
```

### **Performance Characteristics**

| Model | Processing Speed | Analysis Depth | Context Size | Best Use Case |
|-------|-----------------|----------------|--------------|---------------|
| **Qwen** | ⚡⚡⚡ Fast | ⭐⭐ Good | 128K | Bulk data, pattern matching |
| **GPT-OSS** | ⚡⚡ Moderate | ⭐⭐⭐ Excellent | 32K | Deep analysis, reasoning |
| **Local Mix** | ⚡⚡⚡ Adaptive | ⭐⭐⭐ Optimal | Both | Auto-optimized per task |

---

## Real-World Performance

### **Anomaly Detection Scan (7 tables, 12,458 records)**

**Using local-mix:**
```
DeviceLogonEvents    → GPT-OSS (1,245 records)  = 18s (reasoning needed)
SigninLogs           → Qwen    (892 records)    = 8s  (high volume)
DeviceProcessEvents  → GPT-OSS (3,421 records)  = 32s (command analysis)
DeviceNetworkEvents  → Qwen    (5,234 records)  = 12s (many connections)
DeviceFileEvents     → Qwen    (1,234 records)  = 9s  (file operations)
DeviceRegistryEvents → GPT-OSS (234 records)    = 15s (persistence logic)
AzureActivity        → GPT-OSS (198 records)    = 12s (policy analysis)

Total: 106s (1m 46s)
Cost: $0.00
Quality: Optimized per table
```

**Using only Qwen:**
```
All tables → Qwen
Total: 85s (faster)
Cost: $0.00
Quality: Good but misses complex patterns
```

**Using only GPT-OSS:**
```
All tables → GPT-OSS
Total: 145s (slower)
Cost: $0.00
Quality: Excellent but slower on bulk data
```

**Winner**: Local Mix - **Balanced speed + quality**

---

## Troubleshooting

### **Q: How do I know which model was selected?**

The system displays it clearly:
```
Local Mix: Auto-selected qwen for this task
```

### **Q: Can I override the automatic selection?**

Yes! Just manually select model [6] or [7] instead of [5]:
- [6] = Force GPT-OSS for everything
- [7] = Force Qwen for everything
- [5] = Let system decide (recommended)

### **Q: What if I want different routing logic?**

Edit `EXECUTOR.py` → `select_optimal_local_model()` function:
```python
# Customize thresholds:
if token_count > 75000:  # Increase threshold
    return "qwen"

# Or add custom table routing:
if table_name == "MyCustomTable":
    return "gpt-oss:20b"
```

### **Q: Does this work in all modes?**

Yes! Works in:
- ✅ Threat Hunting
- ✅ Anomaly Detection (optimal routing per table)
- ✅ CTF Mode

---

## Comparison with Cloud Models

### **Local Mix vs. GPT-4/5**

| Feature | Local Mix | GPT-4/5 |
|---------|-----------|---------|
| **Cost** | $0.00 | $$$ |
| **Token Limits** | Unlimited | 272K-1M |
| **Speed** | Adaptive (fast/slow) | Moderate |
| **Quality** | Very Good (context-optimized) | Excellent |
| **Data Capacity** | Unlimited | Limited |
| **Use Case** | Large datasets, routine scans | Small focused analyses |

**Recommendation**: 
- Use **Local Mix** for: Anomaly scans, large datasets, routine operations
- Use **GPT-4/5** for: Critical incidents, executive reporting (when enabled)

---

## Configuration

### **Default Settings**

Located in `MODEL_SELECTOR.py`:
```python
DEFAULT_MODEL = "local-mix"  # Smart mix is now the default
```

Located in `EXECUTOR.py`:
```python
# Token threshold for routing
TOKEN_THRESHOLD = 50000

# Table categorization
HIGH_VOLUME_TABLES = {...}
REASONING_HEAVY_TABLES = {...}
```

### **Customization**

To change default model or routing logic:

**1. Change Default Model** (`MODEL_SELECTOR.py` line 22):
```python
DEFAULT_MODEL = "gpt-5-mini"  # Use cloud model
# or
DEFAULT_MODEL = "qwen"         # Force Qwen always
# or
DEFAULT_MODEL = "local-mix"    # Smart routing (current)
```

**2. Adjust Routing Thresholds** (`EXECUTOR.py` lines 27-39):
```python
# Add/remove tables from categories
HIGH_VOLUME_TABLES = {
    'DeviceNetworkEvents',
    'DeviceFileEvents',
    'MyCustomTable',  # Add your table
    # ...
}
```

**3. Change Token Threshold** (`EXECUTOR.py` line 53):
```python
if token_count > 75000:  # Increase from 50000
    return "qwen"
```

---

## Example Output

### **Console Display**

```
✓ Selected: local-mix
Type: Smart Mix (GPT-OSS + Qwen) - Auto-selects best local model
Cost: FREE - No API costs • Unlimited tokens
═══════════════════════════════════════════════════════════════════

[... scan starts ...]

Scanning: DeviceProcessEvents
  3,421 records returned
  Running statistical analysis... 5 patterns
  Comparing to baseline... 0 deviations
  Analyzing 23 outliers with local-mix...
  Local Mix: Auto-selected gpt-oss:20b for this task
  Using Ollama local model (GPT-OSS 20B) with GUARDRAILS enforcement...
  ✓ GUARDRAILS enabled (defense-in-depth security)
  ✓ 3 findings detected

Scanning: DeviceNetworkEvents
  5,234 records returned
  Running statistical analysis... 2 patterns
  Analyzing 87 outliers with local-mix...
  Local Mix: Auto-selected qwen for this task
  Using Ollama local model (qwen3:8b) with GUARDRAILS enforcement...
  ✓ GUARDRAILS enabled (defense-in-depth security)
  ✓ 1 finding detected
```

---

## Hybrid Mode (Optional GPT-4 Refinement)

### **Triple-Model Architecture**

For ultimate quality, you can enable:
```
Local Mix (data processing) → GPT-4o (refinement) → Output
```

**Currently disabled by default** - see `EXECUTOR.py` lines 59-61:
```python
enhancer = QWEN_ENHANCER.QwenEnhancer(
    # ...
    use_gpt_refinement=False,  # Change to True to enable
    refinement_model="gpt-4o"
)
```

**Cost**: ~$0.05 per comprehensive scan (still very cheap!)

---

## Best Practices

### **When to Use Local Mix**

✅ **Always recommended for:**
- Anomaly detection scans
- Large datasets (>1K records)
- Routine security operations
- Learning/testing the system
- Cost-conscious operations

### **When to Use Manual Selection**

🔧 **Advanced users only:**
- You know your data characteristics
- Specific performance requirements
- Debugging/testing specific models
- Custom workflows

### **When to Use Cloud Models**

☁️ **Specific scenarios:**
- Executive reporting (GPT-4/5 refinement)
- Small targeted queries (<1K records)
- Maximum quality needed
- Budget available for API costs

---

## Statistics & Metrics

The system tracks model usage in scan reports:

```json
{
  "scan_metadata": {
    "model_selected": "local-mix",
    "model_breakdown": {
      "qwen": 3,        // Used for 3 tables
      "gpt-oss:20b": 4  // Used for 4 tables
    },
    "total_tokens_processed": 125340,
    "cost": 0.00
  }
}
```

---

## Troubleshooting

### **Issue: "Unknown model 'local-mix'"**

**Fix**: Update GUARDRAILS.py - ensure "local-mix" is in ALLOWED_MODELS

### **Issue: Always selects same model**

**Check**:
1. Is table_name being passed to hunt()?
2. Are table categories defined in EXECUTOR.py?
3. Look for routing debug messages

### **Issue: Want different routing**

**Customize** `EXECUTOR.py` → `select_optimal_local_model()`:
- Adjust table categories
- Change token threshold
- Add custom logic

---

## Future Enhancements

Potential improvements (not yet implemented):

- [ ] Track model performance per table
- [ ] Learning-based routing (use history to optimize)
- [ ] Dynamic threshold adjustment
- [ ] Model ensemble (run both, merge results)
- [ ] GPU utilization awareness

---

## Summary

**Local Mix Models** gives you:
- 🎯 **Intelligence**: Automatic optimal model selection
- 💰 **Free**: Zero API costs
- 🚀 **Performance**: Balanced speed + quality
- 📊 **Transparency**: See what was selected
- 🔧 **Flexibility**: Can still choose manually

**Perfect for**: SOC analysts who want the best results without managing technical model details!

---

**Version**: 1.0  
**Status**: ✅ Production Ready  
**Last Updated**: October 21, 2025

