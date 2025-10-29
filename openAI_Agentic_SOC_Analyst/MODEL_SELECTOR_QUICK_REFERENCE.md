# MODEL_SELECTOR.py - Quick Reference Guide

## Module Overview

**MODEL_SELECTOR.py** is now the unified module for all model selection and management operations. It combines user-friendly selection menus with runtime validation and cost management.

---

## Available Functions

### 1. **Initial Model Selection**

```python
import MODEL_SELECTOR

# Show numbered menu and get user's model choice
model = MODEL_SELECTOR.prompt_model_selection()
```

**What it does:**
- Displays cloud vs offline models in separate sections
- Shows costs, context limits, and use-case recommendations
- Emphasizes FREE offline options
- Returns selected model name (str)

---

### 2. **Token Counting**

```python
# Count tokens in messages
messages = [system_msg, user_msg]
token_count = MODEL_SELECTOR.count_tokens(messages, model)
```

**What it does:**
- Uses tiktoken to count tokens accurately
- Works for both OpenAI and Ollama models
- Returns token count (int)

---

### 3. **Runtime Model Validation**

```python
# Validate model can handle token count, optionally switch
model = MODEL_SELECTOR.choose_model(
    model_name=model,
    input_tokens=token_count,
    tier="4",  # Your OpenAI API tier
    assumed_output_tokens=500,
    interactive=True  # Allow user to switch models
)
```

**What it does:**
- Shows comparison table (cloud vs offline)
- Checks input token limits
- Checks TPM rate limits (cloud models only)
- Displays warnings if approaching/exceeding limits
- Allows interactive model switching
- Suggests offline models as solution
- Returns final model name (str)

---

### 4. **Model Validation**

```python
# Quick validation that model exists
MODEL_SELECTOR.validate_model(model)
```

**What it does:**
- Validates model is in GUARDRAILS.ALLOWED_MODELS
- Shows model type (Cloud/API or Offline/FREE)
- Exits if invalid model

---

### 5. **Helper Functions**

```python
# Check if model is offline/free
is_free = MODEL_SELECTOR.is_offline_model("qwen")  # Returns True

# Format currency
cost_str = MODEL_SELECTOR.money(0.0523)  # Returns "$0.052300"

# Calculate estimated cost
info = GUARDRAILS.ALLOWED_MODELS["gpt-5-mini"]
cost = MODEL_SELECTOR.estimate_cost(
    input_tokens=1000,
    output_tokens=500,
    model_info=info
)  # Returns float cost in USD
```

---

## Usage Patterns

### Pattern 1: Simple Selection (in _main.py)
```python
import MODEL_SELECTOR

# Just get model choice from user
model = MODEL_SELECTOR.prompt_model_selection()
```

### Pattern 2: Full Validation (in THREAT_HUNT_PIPELINE.py)
```python
import MODEL_SELECTOR

# Build messages
messages = [system_message, user_message]

# Count tokens
token_count = MODEL_SELECTOR.count_tokens(messages, model)

# Validate and optionally switch
model = MODEL_SELECTOR.choose_model(model, token_count)

# Final validation
MODEL_SELECTOR.validate_model(model)

# Now safe to use model
response = openai_client.chat.completions.create(
    model=model,
    messages=messages
)
```

---

## Key Benefits

### 🎯 Offline Model Promotion
- **At Startup:** Clearly separated "FREE" section
- **At Runtime:** Shows [FREE] badge with no rate limits
- **When Limits Hit:** Suggests switching to offline

### 💰 Cost Transparency
- Shows exact costs: `$0.25/$2.00 per M tokens`
- Displays "FREE - No API costs" for offline
- Calculates estimated costs for current query

### 🚀 Smart Validation
- Checks input token limits
- Checks TPM rate limits (cloud only)
- Color-coded warnings (🔴 red, 🟡 yellow, 🟢 green)
- Suggests optimizations when over limit

### 🏷️ Clear Model Types
- Labels every model as (Cloud/API) or (Offline/FREE)
- Consistent messaging throughout flow
- Reminds user of choice implications

---

## Configuration

Edit these constants at the top of MODEL_SELECTOR.py:

```python
CURRENT_TIER = "4"              # Your OpenAI API tier
DEFAULT_MODEL = "gpt-5-mini"    # Fallback model
WARNING_RATIO = 0.80            # Warning threshold (80%)
```

---

## Migration from MODEL_MANAGEMENT

If you have old code using MODEL_MANAGEMENT:

**Before:**
```python
import MODEL_MANAGEMENT
tokens = MODEL_MANAGEMENT.count_tokens(msgs, model)
model = MODEL_MANAGEMENT.choose_model(model, tokens)
```

**After:**
```python
import MODEL_SELECTOR
tokens = MODEL_SELECTOR.count_tokens(msgs, model)
model = MODEL_SELECTOR.choose_model(model, tokens)
```

Just replace `MODEL_MANAGEMENT` with `MODEL_SELECTOR` - all function signatures are identical!

---

## Examples

### Example 1: Basic Startup
```python
# In _main.py
model = MODEL_SELECTOR.prompt_model_selection()
# User selects from menu, sees: "✓ Selected: qwen"
# "Type: Ollama (Local/Offline)"
# "Cost: FREE - No API costs"
```

### Example 2: Runtime Validation with Warnings
```python
# Large query scenario
messages = [system, user_with_1000_log_lines]
tokens = MODEL_SELECTOR.count_tokens(messages, "gpt-4.1-nano")
# tokens = 150000

model = MODEL_SELECTOR.choose_model("gpt-4.1-nano", tokens)

# Output shows:
# ═══ Cloud Models (OpenAI API) ═══
#   gpt-4.1-nano | input: 150000/1047576 | TPM: 150000/10000000 | cost: $0.23 ← current
#
# ═══ Offline Models (Ollama/Local) ═══  
#   qwen         | input: 150000/128000  | [FREE] | cost: $0.00
#
# ⚠️ WARNING: input: 150000/128000 exceeds input limit for qwen.
# 💡 Suggestions:
#    • Or switch to offline models (no limits!)
#
# Continue with 'gpt-4.1-nano'? (Enter=yes / type model name / 'list'):
```

### Example 3: Switching Models at Runtime
```python
# User hits 'list' when prompted
# Shows:
# Available models:
#   1. gpt-4.1-nano   (Cloud/API)
#   2. gpt-4.1        (Cloud/API)
#   3. gpt-5-mini     (Cloud/API)
#   4. gpt-5          (Cloud/API)
#   5. gpt-oss:20b    (Offline/FREE)
#   6. qwen           (Offline/FREE)

# User types: qwen
# ✓ Switched to: qwen
# (Offline model - FREE, no API costs)
```

---

## Troubleshooting

### "Model not in allowed list"
**Solution:** Check GUARDRAILS.ALLOWED_MODELS contains the model

### "Token count too high"
**Solution:** 
1. Reduce log lines (shorter time range)
2. Filter to specific device/user
3. Switch to offline model (often unlimited or higher limits)

### "TPM rate limit exceeded"
**Solution:**
1. Wait a few seconds (rate limit resets)
2. Switch to offline model (no rate limits)
3. Upgrade OpenAI API tier

---

## Model Recommendations

| Use Case | Recommended Model | Why |
|----------|-------------------|-----|
| **Quick testing** | gpt-5-mini | Fast, cheap, good context |
| **Production SOC** | gpt-5 | Best accuracy, large context |
| **Offline/Private** | qwen | FREE, 128K context, fast |
| **Threat Hunting CTF** | gpt-oss:20b | FREE, better reasoning |
| **Cost-conscious** | qwen or gpt-oss:20b | No API costs! |
| **Large log volumes** | gpt-4.1-nano | 1M+ context, very cheap |

---

**Pro Tip:** For CTF competitions or sensitive investigations, use offline models (qwen/gpt-oss:20b) to keep data local and avoid API costs! 🔒💰

