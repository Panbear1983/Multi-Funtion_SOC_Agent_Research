# 🤖 Adding New Models - Complete Guide

## ✅ **System Now Supports ALL Models Automatically!**

The CTF Hunt Mode (and all other modules) now **automatically detect** whether a model is local or cloud, and route accordingly.

**No code changes needed!** Just add the model to `GUARDRAILS.py`

---

## 📋 **How Model Routing Works**

### **Automatic Detection:**

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

### **Routing Logic:**

```python
if is_local_model(model):
    # Routes to OLLAMA_CLIENT → http://localhost:11434
    response = OLLAMA_CLIENT.chat(...)
else:
    # Routes to OpenAI API → https://api.openai.com
    response = openai_client.chat.completions.create(...)
```

---

## 🎯 **How to Add a New Model**

### **Step 1: Add to GUARDRAILS.py**

Open `/Users/peter/Desktop/Old_Projects/GitHub/Multi-Funtion_SOC_Agent_Research/openAI_Agentic_SOC_Analyst/GUARDRAILS.py`

#### **For Cloud Models (OpenAI, etc.):**

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

**System will auto-detect as CLOUD model** (cost > 0)

#### **For Local Models (Ollama, etc.):**

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

**System will auto-detect as LOCAL model** (cost == 0)

---

### **Step 2: (Local Models Only) Add Ollama Mapping**

If your local model name differs from Ollama's actual name, add to mapping in `CTF_HUNT_MODE.py`:

```python
def get_ollama_model_name(model_name):
    """Map friendly names to Ollama model names"""
    ollama_mapping = {
        "qwen": "qwen3:8b",
        "gpt-oss:20b": "gpt-oss:20b",
        "llama3": "llama3:70b",           # ← Add your mapping
        "mistral": "mistral:latest"       # ← Add your mapping
    }
    return ollama_mapping.get(model_name, model_name)
```

**If names match exactly, skip this step!**

---

### **Step 3: (Local Models Only) Pull Model in Ollama**

```bash
# Pull the model to your local Ollama instance
ollama pull llama3:70b

# Verify it's available
ollama list
```

---

### **Step 4: Done! Use the Model**

```bash
python3 _main.py
```

**Select your new model from the menu:**
```
SELECT LANGUAGE MODEL

[1] gpt-4.1-nano
[2] gpt-4.1
[3] gpt-5-mini (Default)
[4] gpt-5
[5] qwen
[6] gpt-oss:20b
[7] llama3:70b  ← Your new model!

Select model [1-7]: 7
```

**System automatically:**
- ✅ Detects if it's local or cloud
- ✅ Routes to correct client (Ollama or OpenAI)
- ✅ Works in ALL modules (Threat Hunt, Anomaly Detection, CTF Mode)

---

## 📊 **Current Models**

### **Cloud Models (OpenAI API):**

| Model | Input Tokens | Output Tokens | Cost (per M) |
|-------|-------------|---------------|--------------|
| gpt-4.1-nano | 1,047,576 | 32,768 | $0.10 / $0.40 |
| gpt-4.1 | 1,047,576 | 32,768 | $1.00 / $8.00 |
| gpt-5-mini | 272,000 | 128,000 | $0.25 / $2.00 |
| gpt-5 | 272,000 | 128,000 | $1.25 / $10.00 |

### **Local Models (Ollama):**

| Model | Input Tokens | Output Tokens | Cost |
|-------|-------------|---------------|------|
| qwen (qwen3:8b) | 128,000 | 32,768 | FREE |
| gpt-oss:20b | 32,000 | 4,096 | FREE |

---

## 🔧 **Examples**

### **Example 1: Add Claude 3.5 Sonnet (Cloud)**

```python
# GUARDRAILS.py
ALLOWED_MODELS = {
    # ... existing ...
    
    "claude-3.5-sonnet": {
        "max_input_tokens": 200_000,
        "max_output_tokens": 4_096,
        "cost_per_million_input": 3.00,
        "cost_per_million_output": 15.00,
        "tier": {
            "free": None,
            "1": 40_000,
            "2": 400_000,
            "3": 1_000_000,
            "4": 3_000_000,
            "5": 50_000_000
        }
    }
}
```

**System detects:** Cost > 0 → Cloud model → Routes to OpenAI client

---

### **Example 2: Add Mistral (Local Ollama)**

**Step 1 - GUARDRAILS.py:**
```python
ALLOWED_MODELS = {
    # ... existing ...
    
    "mistral": {
        "max_input_tokens": 32_000,
        "max_output_tokens": 8_192,
        "cost_per_million_input": 0.00,  # ← Free = Local
        "cost_per_million_output": 0.00,
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

**Step 2 - CTF_HUNT_MODE.py (if needed):**
```python
def get_ollama_model_name(model_name):
    ollama_mapping = {
        "qwen": "qwen3:8b",
        "gpt-oss:20b": "gpt-oss:20b",
        "mistral": "mistral:latest"  # ← Add mapping
    }
    return ollama_mapping.get(model_name, model_name)
```

**Step 3 - Terminal:**
```bash
ollama pull mistral:latest
```

**Done!** Model is available in all modes.

---

### **Example 3: Add DeepSeek (Local Ollama)**

```bash
# Pull model
ollama pull deepseek-coder:33b

# Add to GUARDRAILS.py
ALLOWED_MODELS = {
    "deepseek-coder": {
        "max_input_tokens": 16_000,
        "max_output_tokens": 4_096,
        "cost_per_million_input": 0.00,
        "cost_per_million_output": 0.00,
        "tier": {"free": None, "1": None, "2": None, "3": None, "4": None, "5": None}
    }
}

# Add mapping if name differs
def get_ollama_model_name(model_name):
    ollama_mapping = {
        "deepseek-coder": "deepseek-coder:33b"
    }
    ...
```

---

## ✅ **Benefits of This System**

### **1. Future-Proof**
- ✅ Add any model without changing core code
- ✅ Just update `GUARDRAILS.py`

### **2. Automatic Detection**
- ✅ No need to specify "local" or "cloud"
- ✅ System detects based on cost
- ✅ Routes to correct API automatically

### **3. Works Everywhere**
- ✅ Threat Hunt Pipeline
- ✅ Anomaly Detection
- ✅ CTF Hunt Mode
- ✅ All future modules

### **4. Easy to Maintain**
- ✅ Single source of truth (`GUARDRAILS.py`)
- ✅ One place to add models
- ✅ No scattered configuration

---

## 🎯 **Quick Reference**

### **To Add Cloud Model:**
1. Add to `GUARDRAILS.py` with actual costs
2. Done!

### **To Add Local Model:**
1. Add to `GUARDRAILS.py` with 0.00 costs
2. (Optional) Add name mapping in `CTF_HUNT_MODE.py`
3. Pull model: `ollama pull <model>`
4. Done!

---

## 🚀 **All Current & Future Models Supported!**

**The system is now fully dynamic and extensible!**

Any model you add to `GUARDRAILS.py` will automatically:
- ✅ Appear in model selection menu
- ✅ Be routed to correct API (local/cloud)
- ✅ Work in all modules
- ✅ Have cost tracking (if cloud)
- ✅ Have rate limit monitoring

**No code changes needed beyond configuration!** 🎯✅

