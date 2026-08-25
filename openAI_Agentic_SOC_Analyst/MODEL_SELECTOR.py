"""
MODEL_SELECTOR.py - Unified Model Selection & Runtime Validation
Combines user-friendly selection with token validation and cost management

Key Features:
- Clean numbered menu for initial selection (promotes offline models)
- Runtime token validation and limit checking
- Cost estimation and model switching
- Distinguishes cloud (OpenAI) vs local (Ollama) models
"""

from color_support import Fore, Style
import tiktoken
import GUARDRAILS
import TIME_ESTIMATOR

# Canonical Ollama tag → GUARDRAILS.ALLOWED_MODELS key mapping (single source of truth)
OLLAMA_TAG_TO_MODEL_KEY = {
    "qwen3:8b":    "qwen",
    "gemma4:26b":  "gemma4:26b",
    "gemma4:e4b":  "gemma4:e4b",
}
MODEL_KEY_TO_OLLAMA_TAG = {v: k for k, v in OLLAMA_TAG_TO_MODEL_KEY.items()}

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

# OpenAI API Tier - https://platform.openai.com/settings/organization/limits
CURRENT_TIER = "4"  # Options: "free", "1", "2", "3", "4", "5"
DEFAULT_MODEL = "local-mix"  # Smart mix of local models (FREE, unlimited)
WARNING_RATIO = 0.80  # 80% threshold for warnings

# GUARDRAILS Configuration for Offline Models (Defense-in-Depth)
OFFLINE_GUARDRAILS_CONFIG = {
    "enabled": True,  # Master switch for offline model GUARDRAILS
    "strict_mode": True,  # If True, reject violations; if False, warn only
    "log_violations": True,  # Log GUARDRAILS violations to file
    "violation_log_file": "_guardrails_violations.jsonl"
}

# Authority Enhancement Configuration
AUTHORITY_ENHANCEMENT_ENABLED = True  # Can disable if issues
CONFIDENCE_BOOSTING_ENABLED = True     # Can disable if issues

# ═══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS (from MODEL_MANAGEMENT)
# ═══════════════════════════════════════════════════════════════════════

def money(usd):
    """Format USD with appropriate precision"""
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"

def is_offline_model(model_name):
    """Check if model is offline/local (Ollama)"""
    if model_name is None:
        return False
    
    # Check direct match first
    info = GUARDRAILS.ALLOWED_MODELS.get(model_name, {})
    if info and info.get('cost_per_million_input', 0) == 0.00:
        return True
    
    # Check if it's an Ollama tag that maps to an allowed model key
    ollama_to_allowed_mapping = OLLAMA_TAG_TO_MODEL_KEY

    if model_name in ollama_to_allowed_mapping:
        mapped_name = ollama_to_allowed_mapping[model_name]
        info = GUARDRAILS.ALLOWED_MODELS.get(mapped_name, {})
        return info.get('cost_per_million_input', 0) == 0.00

    return False

def color_for_usage(used, limit):
    """Return color based on usage relative to limit"""
    if limit is None:
        return Fore.LIGHTGREEN_EX
    if used > limit:
        return Fore.LIGHTRED_EX
    if used >= WARNING_RATIO * limit:
        return Fore.LIGHTYELLOW_EX
    return Fore.LIGHTGREEN_EX

def colorize(label, used, limit):
    """Format usage with color coding"""
    col = color_for_usage(used, limit)
    lim = "∞" if limit is None else str(limit)
    return f"{label}: {col}{used}/{lim}{Style.RESET_ALL}"

def estimate_cost(input_tokens, output_tokens, model_info):
    """Calculate estimated cost for given token counts"""
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout

# ═══════════════════════════════════════════════════════════════════════
# GUARDRAILS MANAGEMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def get_offline_guardrails_config():
    """Get GUARDRAILS configuration for offline models"""
    return OFFLINE_GUARDRAILS_CONFIG

def log_guardrails_violation(model_name, table_name, reason):
    """Log GUARDRAILS violation for audit trail"""
    if not OFFLINE_GUARDRAILS_CONFIG["log_violations"]:
        return
    
    import json
    from datetime import datetime
    
    violation = {
        "timestamp": datetime.now().isoformat(),
        "model": model_name,
        "table_attempted": table_name,
        "reason": reason,
        "action": "BLOCKED" if OFFLINE_GUARDRAILS_CONFIG["strict_mode"] else "WARNED"
    }
    
    try:
        with open(OFFLINE_GUARDRAILS_CONFIG["violation_log_file"], "a") as f:
            f.write(json.dumps(violation) + "\n")
        print(f"{Fore.LIGHTRED_EX}[GUARDRAILS] Violation logged to {OFFLINE_GUARDRAILS_CONFIG['violation_log_file']}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.YELLOW}[GUARDRAILS] Could not log violation: {e}{Fore.RESET}")

# ═══════════════════════════════════════════════════════════════════════
# INITIAL MODEL SELECTION (Original MODEL_SELECTOR functionality)
# ═══════════════════════════════════════════════════════════════════════

def prompt_model_selection(input_tokens=None):
    """
    Interactive numbered menu for model selection with time estimates
    Emphasizes offline/free models for cost-conscious users
    
    Args:
        input_tokens (int): Estimated input tokens for time calculation
    """
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}SELECT LANGUAGE MODEL")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    
    if input_tokens:
        print(f"{Fore.WHITE}Input size: {input_tokens:,} tokens{Fore.RESET}\n")
    else:
        print()
    
    model_list = []
    
    # ═══ CLOUD MODELS (OpenAI API) ═══
    print(f"{Fore.LIGHTGREEN_EX}═══ OpenAI Models (Cloud/API) ═══{Fore.RESET}\n")
    
    openai_models = [
        ('gpt-4.1-nano', 'Very Low ($0.10/$0.40 per M)', '1M+ tokens'),
        ('gpt-4.1', 'Moderate ($1.00/$8.00 per M)', '1M+ tokens'),
        ('gpt-5-mini', 'Low ($0.25/$2.00 per M)', '272K tokens'),
        ('gpt-5', 'High ($1.25/$10.00 per M)', '272K tokens')
    ]
    
    for idx, (model_name, cost, tokens) in enumerate(openai_models, 1):
        model_list.append(model_name)
        default_marker = " ⭐ Recommended" if model_name == "gpt-5-mini" else ""
        print(f"{Fore.LIGHTGREEN_EX}[{idx}] {model_name}{default_marker}{Fore.RESET}")
        print(f"{Fore.WHITE}    Cost: {cost} | Context: {tokens}")
        
        # Add time estimate if input_tokens provided
        if input_tokens:
            estimated_time = TIME_ESTIMATOR.estimate_time(model_name, input_tokens)
            time_display = TIME_ESTIMATOR.format_time_display(estimated_time, input_tokens, model_name)
            print(f"{Fore.LIGHTBLUE_EX}    Est. time: {time_display}{Fore.RESET}")
    
    # ═══ OFFLINE MODELS (Ollama/Local) ═══
    print(f"\n{Fore.LIGHTYELLOW_EX}═══ Ollama Models (Local/Offline) - FREE ═══{Fore.RESET}\n")
    
    ollama_models = [
        ('local-mix',   'Free', 'Auto-Select', '⭐ Smart Mix: Gemma4:26b (reasoning) + Qwen (volume) + Gemma4:e4b (CTF/validator) - RECOMMENDED'),
        ('qwen',        'Free', '128K tokens', '8B params - Manual: Fast and high volume'),
        ('gemma4:26b',  'Free', '128K tokens', '26B params - Manual: Best reasoning (threat hunt / anomaly)'),
        ('gemma4:e4b',  'Free', '32K tokens',  '4B params - Manual: Fast (CTF / quick triage)'),
    ]
    
    start_idx = len(openai_models) + 1
    for idx, model_info in enumerate(ollama_models, start_idx):
        model_name = model_info[0]
        cost = model_info[1]
        tokens = model_info[2]
        description = model_info[3] if len(model_info) > 3 else ""
        
        model_list.append(model_name)
        print(f"{Fore.LIGHTYELLOW_EX}[{idx}] {model_name}{Fore.RESET}")
        print(f"{Fore.LIGHTGREEN_EX}    {cost} ✓{Fore.RESET} | {tokens} | Local/Offline")
        
        # Add time estimate if input_tokens provided
        if input_tokens:
            estimated_time = TIME_ESTIMATOR.estimate_time(model_name, input_tokens)
            time_display = TIME_ESTIMATOR.format_time_display(estimated_time, input_tokens, model_name)
            print(f"{Fore.LIGHTBLUE_EX}    Est. time: {time_display}{Fore.RESET}")
        
        if description:
            print(f"{Fore.LIGHTBLACK_EX}    {description}{Fore.RESET}")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}")
    
    # Get user selection
    while True:
        try:
            choice = input(f"{Fore.LIGHTGREEN_EX}Select model [1-{len(model_list)}] or press Enter for local-mix: {Fore.RESET}").strip()
            
            if not choice:
                selected_model = 'local-mix'
                break
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(model_list):
                selected_model = model_list[choice_num - 1]
                break
            else:
                print(f"{Fore.RED}Please enter a number between 1 and {len(model_list)}.{Fore.RESET}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Enter a number 1-{len(model_list)}.{Fore.RESET}")
    
    # Display selection with model type
    if is_offline_model(selected_model):
        color = Fore.LIGHTYELLOW_EX
        if selected_model == "local-mix":
            model_type = "Smart Mix (Gemma4:26b reasoning + Qwen volume + Gemma4:e4b CTF/validator) - Mode-aware routing"
            cost_msg = f"{Fore.LIGHTGREEN_EX}FREE - No API costs • Unlimited tokens{Fore.RESET}"
        else:
            model_type = "Ollama (Local/Offline)"
            cost_msg = f"{Fore.LIGHTGREEN_EX}FREE - No API costs{Fore.RESET}"
    else:
        color = Fore.LIGHTGREEN_EX
        model_type = "OpenAI (Cloud/API)"
        # Map Ollama model names to ALLOWED_MODELS keys if needed
        ollama_to_allowed_mapping = OLLAMA_TAG_TO_MODEL_KEY
        lookup_name = ollama_to_allowed_mapping.get(selected_model, selected_model)
        info = GUARDRAILS.ALLOWED_MODELS.get(lookup_name, {})
        if info:
            cost_msg = f"${info['cost_per_million_input']:.2f}/${info['cost_per_million_output']:.2f} per M tokens"
        else:
            cost_msg = "Cost information unavailable"
    
    print(f"\n{color}✓ Selected: {selected_model}{Fore.RESET}")
    print(f"{Fore.WHITE}Type: {model_type}")
    print(f"{Fore.WHITE}Cost: {cost_msg}")
    
    # Add time estimate if input_tokens provided
    if input_tokens:
        estimated_time = TIME_ESTIMATOR.estimate_time(selected_model, input_tokens)
        time_display = TIME_ESTIMATOR.format_time_display(estimated_time, input_tokens, selected_model)
        print(f"{Fore.WHITE}Est. time: {time_display}")
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
    
    return selected_model

# ═══════════════════════════════════════════════════════════════════════
# RUNTIME VALIDATION (from MODEL_MANAGEMENT)
# ═══════════════════════════════════════════════════════════════════════

def count_tokens(messages, model):
    """
    Count tokens in message list using tiktoken
    Works for both OpenAI and Ollama models (approximation for Ollama)
    """
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        # Fallback for non-OpenAI models (Ollama)
        enc = tiktoken.get_encoding("cl100k_base")

    text = ""
    for m in messages:
        text += m.get("role", "") + " " + m.get("content", "") + "\n"
    return len(enc.encode(text))

def print_model_comparison_table(input_tokens, current_model, tier, assumed_output_tokens=500):
    """
    Display all models with token limits and costs
    Enhanced to separate cloud vs offline models
    """
    print(f"Model limits and estimated cost:{Fore.WHITE}\n")
    
    # Separate models by type
    offline_models = {}
    cloud_models = {}
    
    for name, info in GUARDRAILS.ALLOWED_MODELS.items():
        if is_offline_model(name):
            offline_models[name] = info
        else:
            cloud_models[name] = info
    
    # Display cloud models
    if cloud_models:
        print(f"{Fore.LIGHTGREEN_EX}═══ Cloud Models (OpenAI API) ═══{Fore.RESET}")
        for name, info in cloud_models.items():
            tpm_limit = info["tier"].get(tier)
            usage_text = colorize("input", input_tokens, info["max_input_tokens"])
            tpm_text = colorize("TPM", input_tokens, tpm_limit)
            est = estimate_cost(input_tokens, assumed_output_tokens, info)
            current_marker = f"{Fore.CYAN} ← current{Fore.WHITE}" if name == current_model else ""
            print(f"  {name:<14} | {usage_text:<35} | {tpm_text:<32} | cost: {money(est)}{current_marker}")
    
    # Display offline models
    if offline_models:
        print(f"\n{Fore.LIGHTYELLOW_EX}═══ Offline Models (Ollama/Local) ═══{Fore.RESET}")
        for name, info in offline_models.items():
            usage_text = colorize("input", input_tokens, info["max_input_tokens"])
            current_marker = f"{Fore.CYAN} ← current{Fore.WHITE}" if name == current_model else ""
            free_badge = f"{Fore.LIGHTGREEN_EX}[FREE]{Fore.WHITE}"
            print(f"  {name:<14} | {usage_text:<35} | {free_badge:<20} | cost: $0.00{current_marker}")
    
    print("")

def assess_limits(model_name, input_tokens, tier):
    """
    Check if model can handle the input size
    Validates both input token limit and TPM rate limits
    """
    # Map Ollama model names to ALLOWED_MODELS keys if needed
    ollama_to_allowed_mapping = {
        "qwen3:8b": "qwen",
        "gpt-oss:20b": "gpt-oss:20b"
    }
    
    # Get the correct model name for ALLOWED_MODELS lookup
    lookup_name = ollama_to_allowed_mapping.get(model_name, model_name)
    
    if lookup_name not in GUARDRAILS.ALLOWED_MODELS:
        # Fallback: try direct lookup
        lookup_name = model_name
    
    info = GUARDRAILS.ALLOWED_MODELS.get(lookup_name, {})
    if not info:
        # Model not found - return early with warning
        print(f"{Fore.YELLOW}⚠️  Model '{model_name}' not found in ALLOWED_MODELS{Fore.RESET}")
        return
    msgs = []

    # Input token limit check
    usage_txt = colorize("input limit", input_tokens, info["max_input_tokens"])
    if input_tokens > info["max_input_tokens"]:
        msgs.append(f"🚨 ERROR: {usage_txt} exceeds input limit for {model_name}.")
    elif input_tokens >= WARNING_RATIO * info["max_input_tokens"]:
        msgs.append(f"⚠️  WARNING: {usage_txt} is at {int(WARNING_RATIO*100)}% of input limit for {model_name}.")
    else:
        msgs.append(f"✅ Safe: {usage_txt} is within input limit for {model_name}.")

    # TPM rate limit check (only for cloud models)
    if not is_offline_model(model_name):
        tpm_limit = info["tier"].get(tier)
        tpm_txt = colorize("rate_limit", input_tokens, tpm_limit)
        if tpm_limit is not None:
            if input_tokens > tpm_limit:
                msgs.append(f"⚠️  WARNING: {tpm_txt} exceeds TPM rate limit for {model_name} — may be throttled.")
            elif input_tokens >= WARNING_RATIO * tpm_limit:
                msgs.append(f"⚠️  WARNING: {tpm_txt} is at {int(WARNING_RATIO*100)}% of TPM rate limit for {model_name}.")
            else:
                msgs.append(f"✅ Safe: {tpm_txt} is within TPM rate limit for {model_name}.")
        else:
            msgs.append(f"ℹ️  No TPM tier limit data for {model_name} at tier '{tier}'.")
    else:
        msgs.append(f"ℹ️  {Fore.LIGHTGREEN_EX}Offline model - no rate limits!{Fore.WHITE}")

    # Suggest optimizations if over limit
    if input_tokens > info["max_input_tokens"] or (not is_offline_model(model_name) and info["tier"].get(tier) is not None and input_tokens > info["tier"].get(tier)):
        msgs += [
            "",
            "💡 Suggestions to reduce input size:",
            "   • Focus on one user or device",
            "   • Use a shorter time range",
            "   • Remove extra context"
        ]
        if not is_offline_model(model_name):
            msgs.append("   • Or switch to offline models (no limits!)")

    print("\n".join(msgs))
    print("")

def choose_model(model_name, input_tokens, tier=CURRENT_TIER, assumed_output_tokens=500, interactive=True):
    """
    Runtime model validation and optional switching
    Shows token usage, limits, and allows model change if needed
    
    This is called AFTER data is loaded to validate the model can handle it
    """
    # Validate model exists (check both direct and Ollama mappings)
    ollama_to_allowed_mapping = {
        "qwen3:8b": "qwen",
        "gpt-oss:20b": "gpt-oss:20b"
    }
    lookup_name = ollama_to_allowed_mapping.get(model_name, model_name)
    
    if lookup_name not in GUARDRAILS.ALLOWED_MODELS and model_name not in GUARDRAILS.ALLOWED_MODELS:
        print(Fore.LIGHTRED_EX + f"Unknown model '{model_name}'. Defaulting to {DEFAULT_MODEL}." + Style.RESET_ALL)
        model_name = DEFAULT_MODEL

    # Show comparison table
    print_model_comparison_table(input_tokens, model_name, tier, assumed_output_tokens)
    
    # Assess current model
    assess_limits(model_name, input_tokens, tier)

    # Non-interactive mode: just return
    if not interactive:
        return model_name

    # Interactive prompt for model switching
    while True:
        prompt = f"{Fore.WHITE}Continue with '{model_name}'? (Enter=yes / type model name / 'list'):{Fore.WHITE} "
        choice = input(prompt).strip()

        # Continue with current model
        if choice == "" or choice.lower() in {"y", "yes", "continue", "c"}:
            # Map Ollama model names to ALLOWED_MODELS keys if needed
            ollama_to_allowed_mapping = {
                "qwen3:8b": "qwen",
                "gpt-oss:20b": "gpt-oss:20b"
            }
            lookup_name = ollama_to_allowed_mapping.get(model_name, model_name)
            info = GUARDRAILS.ALLOWED_MODELS.get(lookup_name, {})
            if not info:
                # Fallback: try direct lookup
                info = GUARDRAILS.ALLOWED_MODELS.get(model_name, {})
            if not info:
                print(f"{Fore.YELLOW}⚠️  Model '{model_name}' not found in ALLOWED_MODELS{Fore.RESET}")
                return model_name
            
            tpm_limit = info.get("tier", {}).get(tier) if info else None
            over_input = input_tokens > info.get("max_input_tokens", 0) if info else False
            over_tpm = (not is_offline_model(model_name)) and (tpm_limit is not None) and (input_tokens > tpm_limit)

            if over_input or over_tpm:
                limit_type = "input limit" if over_input else "TPM rate limit"
                print(f"{Fore.YELLOW}⚠️  WARNING: Input may exceed {model_name}'s {limit_type}.{Fore.WHITE}\n")
            return model_name

        # Show model list
        if choice.lower() in {"list", "models"}:
            print(f"\n{Fore.LIGHTGREEN_EX}Available models:{Fore.WHITE}")
            for idx, name in enumerate(GUARDRAILS.ALLOWED_MODELS.keys(), 1):
                model_type = "Offline/FREE" if is_offline_model(name) else "Cloud/API"
                print(f"  {idx}. {name:<14} ({model_type})")
            print("")
            continue

        # Switch to different model
        if choice in GUARDRAILS.ALLOWED_MODELS:
            model_name = choice
            # Map Ollama model names to ALLOWED_MODELS keys if needed
            ollama_to_allowed_mapping = {
                "qwen3:8b": "qwen",
                "gpt-oss:20b": "gpt-oss:20b"
            }
            lookup_name = ollama_to_allowed_mapping.get(model_name, model_name)
            info = GUARDRAILS.ALLOWED_MODELS.get(lookup_name, {})
            if not info:
                info = GUARDRAILS.ALLOWED_MODELS.get(model_name, {})
            print(f"\n{Fore.LIGHTGREEN_EX}Switched to: {model_name}{Fore.RESET}")
            
            if is_offline_model(model_name):
                print(f"{Fore.LIGHTYELLOW_EX}(Offline model - FREE, no API costs){Fore.RESET}\n")
            else:
                print("")
            
            # Re-assess with new model
            assess_limits(model_name, input_tokens, tier)
            est = estimate_cost(input_tokens, assumed_output_tokens, info)
            if not is_offline_model(model_name):
                print(f"Estimated cost: {money(est)}\n")
            continue

        print(f"{Fore.RED}Invalid input. Press Enter to continue, type a model name, or 'list'.{Fore.RESET}")

# ═══════════════════════════════════════════════════════════════════════
# VALIDATION (from GUARDRAILS)
# ═══════════════════════════════════════════════════════════════════════

def validate_model(model):
    """Quick validation that model is in allowed list"""
    if model not in GUARDRAILS.ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR:{Style.RESET_ALL} Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}exiting.{Style.RESET_ALL}")
        raise SystemExit(1)
    else:
        model_type = "Offline/FREE" if is_offline_model(model) else "Cloud/API"
        print(f"{Fore.LIGHTGREEN_EX}✓ Valid model: {Fore.CYAN}{model} {Fore.LIGHTBLACK_EX}({model_type}){Style.RESET_ALL}\n")
