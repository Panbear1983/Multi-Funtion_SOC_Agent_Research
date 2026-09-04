"""
MODEL_SELECTOR.py - Model menu, runtime limit checks and cost display.

The menu and every limit come from LLM_ROUTER.MODELS (single source of truth).
Policy since 2026-09-03: ONE local model (qwen3:8b - the only one that fits this
Mac's memory at usable speed) plus cloud options from OpenAI and Claude.
"""

from color_support import Fore, Style
import CLAUDE_CLIENT
import GUARDRAILS
import LLM_ROUTER
import TIME_ESTIMATOR

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

CURRENT_TIER = "4"  # kept for old call signatures (rate tiers were an OpenAI concept)
DEFAULT_MODEL = LLM_ROUTER.DEFAULT_MODEL   # qwen3:8b - free, offline
WARNING_RATIO = 0.80  # 80% threshold for warnings

# GUARDRAILS Configuration for Offline Models (Defense-in-Depth)
OFFLINE_GUARDRAILS_CONFIG = {
    "enabled": True,          # Master switch for offline model GUARDRAILS
    "strict_mode": True,      # If True, reject violations; if False, warn only
    "log_violations": True,   # Log GUARDRAILS violations to file
    "violation_log_file": "_guardrails_violations.jsonl"
}

# Authority Enhancement Configuration
AUTHORITY_ENHANCEMENT_ENABLED = True
CONFIDENCE_BOOSTING_ENABLED = True

# Kept for older imports: canonical Ollama tag <-> registry key (now identical)
OLLAMA_TAG_TO_MODEL_KEY = {LLM_ROUTER.LOCAL_MODEL: LLM_ROUTER.LOCAL_MODEL}
MODEL_KEY_TO_OLLAMA_TAG = dict(OLLAMA_TAG_TO_MODEL_KEY)

# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def money(usd):
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"


def is_offline_model(model_name):
    """True for the local Ollama model (any alias)."""
    return LLM_ROUTER.is_local(model_name) if model_name else False


def color_for_usage(used, limit):
    if limit is None:
        return Fore.LIGHTGREEN_EX
    if used > limit:
        return Fore.LIGHTRED_EX
    if used >= WARNING_RATIO * limit:
        return Fore.LIGHTYELLOW_EX
    return Fore.LIGHTGREEN_EX


def colorize(label, used, limit):
    col = color_for_usage(used, limit)
    lim = "∞" if limit is None else str(limit)
    return f"{label}: {col}{used}/{lim}{Style.RESET_ALL}"


def estimate_cost(input_tokens, output_tokens, model_info):
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout


def _info(model_name):
    return GUARDRAILS.ALLOWED_MODELS.get(LLM_ROUTER.resolve(model_name), {})


# ═══════════════════════════════════════════════════════════════════════
# GUARDRAILS MANAGEMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def get_offline_guardrails_config():
    return OFFLINE_GUARDRAILS_CONFIG


def log_guardrails_violation(model_name, table_name, reason):
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
# INITIAL MODEL SELECTION
# ═══════════════════════════════════════════════════════════════════════

def model_status(name):
    """Live readiness check for the dashboard: (ready?, short status text)."""
    import OLLAMA_CLIENT
    if LLM_ROUTER.is_local(name):
        installed = OLLAMA_CLIENT.installed_models()
        if not installed:
            return False, "Ollama not running - start it with: ollama serve"
        if name not in installed:
            return False, f"not pulled - run: ollama pull {name}"
        return True, "ready (Ollama running, fits 100% on the GPU)"
    if LLM_ROUTER.is_claude(name):
        backend = LLM_ROUTER.claude_backend()
        if backend == "cli":
            return True, "ready (your Claude Code login)"
        if backend == "api":
            return True, "ready (Anthropic API key)"
        return False, "not signed in - run `claude` once in a terminal"
    return False, "unknown provider"


def _dashboard_row(idx, kind, name, ready, status, input_tokens):
    m = LLM_ROUTER.info(name)
    color = Fore.LIGHTGREEN_EX if ready else Fore.LIGHTBLACK_EX
    dot = f"{Fore.LIGHTGREEN_EX}●" if ready else f"{Fore.RED}●"
    eta = ""
    if input_tokens and ready:
        est = TIME_ESTIMATOR.estimate_time(name, input_tokens)
        eta = f"   ~{TIME_ESTIMATOR.format_time_display(est, input_tokens, name)}"
    print(f"  {color}[{idx}] {kind:<6} {name:<16}{Fore.RESET} {dot} {Fore.WHITE}{status}{Fore.RESET}")
    print(f"      {Fore.LIGHTBLACK_EX}{m['label']} · {LLM_ROUTER.cost_label(name)} · {m['max_input_tokens']:,}-token window{eta}{Fore.RESET}")


def prompt_model_selection(input_tokens=None):
    """
    The model dashboard: one local model, one cloud model, each with a live readiness
    check. Enter = the local model. (OpenAI models were decommissioned 2026-09-04.)
    """
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🧠 MODELS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
    if input_tokens:
        print(f"{Fore.LIGHTBLACK_EX}Input size: {input_tokens:,} tokens{Fore.RESET}")
    print()

    rows = []
    for name in LLM_ROUTER.LOCAL_MENU:
        rows.append(("Local", name) + model_status(name))
    for name in LLM_ROUTER.CLOUD_MENU:
        rows.append(("Cloud", name) + model_status(name))
    for idx, (kind, name, ready, status) in enumerate(rows, 1):
        _dashboard_row(idx, kind, name, ready, status, input_tokens)
    model_list = [r[1] for r in rows]
    ready_map = {r[1]: r[2] for r in rows}
    print(f"\n{Fore.LIGHTBLACK_EX}Enter = {DEFAULT_MODEL}. You can also type a model name (e.g. claude-sonnet-5).{Fore.RESET}")

    try:  # drop anything pasted while the previous stage was still running
        import sys, termios
        if sys.stdin.isatty():
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass
    while True:
        try:
            choice = input(f"{Fore.LIGHTGREEN_EX}Model [1-{len(model_list)}]: {Fore.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            choice = ""
        if not choice:
            selected_model = DEFAULT_MODEL
        elif choice.isdigit() and 1 <= int(choice) <= len(model_list):
            selected_model = model_list[int(choice) - 1]
        elif LLM_ROUTER.is_known(choice):
            selected_model = LLM_ROUTER.resolve(choice)
        else:
            print(f"{Fore.RED}Enter 1-{len(model_list)} or a model name.{Fore.RESET}")
            continue
        ready = ready_map.get(selected_model)
        if ready is None:
            ready, _ = model_status(selected_model)
        if not ready:
            print(f"{Fore.RED}{selected_model} is not ready on this machine - pick another.{Fore.RESET}")
            continue
        break

    color = Fore.LIGHTYELLOW_EX if LLM_ROUTER.is_local(selected_model) else Fore.LIGHTMAGENTA_EX
    print(f"\n{color}✓ Selected: {selected_model}{Fore.RESET}  {Fore.LIGHTBLACK_EX}{LLM_ROUTER.describe(selected_model)}{Fore.RESET}")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
    return selected_model


# ═══════════════════════════════════════════════════════════════════════
# RUNTIME VALIDATION
# ═══════════════════════════════════════════════════════════════════════

def count_tokens(messages, model):
    """CSV-aware token estimate (LLM_ROUTER). `model` kept for older callers."""
    return LLM_ROUTER.estimate_tokens(messages, model)


def print_model_comparison_table(input_tokens, current_model, tier, assumed_output_tokens=500):
    print(f"Model limits and estimated cost:{Fore.WHITE}\n")
    current = LLM_ROUTER.resolve(current_model)
    for name, info in GUARDRAILS.ALLOWED_MODELS.items():
        usage_text = colorize("input", input_tokens, info["max_input_tokens"])
        marker = f"{Fore.CYAN} ← current{Fore.WHITE}" if name == current else ""
        if LLM_ROUTER.is_local(name):
            print(f"  {name:<17} | {usage_text:<35} | {Fore.LIGHTGREEN_EX}[FREE]{Fore.WHITE:<14} | cost: $0.00{marker}")
        else:
            tpm_limit = info["tier"].get(tier)
            tpm_text = colorize("TPM", input_tokens, tpm_limit) if tpm_limit else "TPM: n/a".ljust(20)
            est = estimate_cost(input_tokens, assumed_output_tokens, info)
            cost = "subscription" if LLM_ROUTER.is_claude(name) and LLM_ROUTER.claude_backend() == "cli" else money(est)
            print(f"  {name:<17} | {usage_text:<35} | {tpm_text:<32} | cost: {cost}{marker}")
    print("")


def assess_limits(model_name, input_tokens, tier):
    info = _info(model_name)
    if not info:
        print(f"{Fore.YELLOW}⚠️  Model '{model_name}' not found in ALLOWED_MODELS{Fore.RESET}")
        return
    msgs = []
    usage_txt = colorize("input limit", input_tokens, info["max_input_tokens"])
    if input_tokens > info["max_input_tokens"]:
        msgs.append(f"🚨 ERROR: {usage_txt} exceeds input limit for {model_name}.")
    elif input_tokens >= WARNING_RATIO * info["max_input_tokens"]:
        msgs.append(f"⚠️  WARNING: {usage_txt} is at {int(WARNING_RATIO*100)}% of input limit for {model_name}.")
    else:
        msgs.append(f"✅ Safe: {usage_txt} is within input limit for {model_name}.")

    over_tpm = False
    if is_offline_model(model_name):
        msgs.append(f"ℹ️  {Fore.LIGHTGREEN_EX}Offline model - no rate limits (but a big prompt is slow: ~60 tokens/s){Fore.WHITE}")
    else:
        tpm_limit = info["tier"].get(tier)
        if tpm_limit is not None:
            tpm_txt = colorize("rate_limit", input_tokens, tpm_limit)
            if input_tokens > tpm_limit:
                msgs.append(f"⚠️  WARNING: {tpm_txt} exceeds TPM rate limit for {model_name} — may be throttled.")
                over_tpm = True
            elif input_tokens >= WARNING_RATIO * tpm_limit:
                msgs.append(f"⚠️  WARNING: {tpm_txt} is at {int(WARNING_RATIO*100)}% of TPM rate limit for {model_name}.")
            else:
                msgs.append(f"✅ Safe: {tpm_txt} is within TPM rate limit for {model_name}.")
        else:
            msgs.append(f"ℹ️  No TPM tier limit data for {model_name} at tier '{tier}'.")

    if input_tokens > info["max_input_tokens"] or over_tpm:
        msgs += ["", "💡 Suggestions to reduce input size:",
                 "   • Focus on one user or device", "   • Use a shorter time range", "   • Remove extra context"]
    print("\n".join(msgs))
    print("")


def choose_model(model_name, input_tokens, tier=CURRENT_TIER, assumed_output_tokens=500, interactive=True):
    """
    Runtime validation and optional switching, called AFTER data is loaded.
    """
    model_name = LLM_ROUTER.resolve(model_name)
    if model_name not in GUARDRAILS.ALLOWED_MODELS:
        print(Fore.LIGHTRED_EX + f"Unknown model '{model_name}'. Defaulting to {DEFAULT_MODEL}." + Style.RESET_ALL)
        model_name = DEFAULT_MODEL

    print_model_comparison_table(input_tokens, model_name, tier, assumed_output_tokens)
    assess_limits(model_name, input_tokens, tier)

    if not interactive:
        return model_name

    while True:
        choice = input(f"{Fore.WHITE}Continue with '{model_name}'? (Enter=yes / type model name / 'list'):{Fore.WHITE} ").strip()
        if choice == "" or choice.lower() in {"y", "yes", "continue", "c"}:
            info = _info(model_name)
            if info and input_tokens > info.get("max_input_tokens", 0):
                print(f"{Fore.YELLOW}⚠️  WARNING: Input exceeds {model_name}'s input limit - it will be split or sampled.{Fore.WHITE}\n")
            return model_name
        if choice.lower() in {"list", "models"}:
            print(f"\n{Fore.LIGHTGREEN_EX}Available models:{Fore.WHITE}")
            for idx, name in enumerate(GUARDRAILS.ALLOWED_MODELS.keys(), 1):
                print(f"  {idx}. {LLM_ROUTER.describe(name)}")
            print("")
            continue
        resolved = LLM_ROUTER.resolve(choice)
        if resolved in GUARDRAILS.ALLOWED_MODELS:
            if LLM_ROUTER.is_claude(resolved) and not LLM_ROUTER.claude_backend():
                print(f"{Fore.RED}Claude is not available on this machine.{Fore.RESET}")
                continue
            model_name = resolved
            print(f"\n{Fore.LIGHTGREEN_EX}Switched to: {model_name}{Fore.RESET}")
            assess_limits(model_name, input_tokens, tier)
            if not is_offline_model(model_name):
                print(f"Estimated cost: {money(estimate_cost(input_tokens, assumed_output_tokens, _info(model_name)))}\n")
            continue
        print(f"{Fore.RED}Invalid input. Press Enter to continue, type a model name, or 'list'.{Fore.RESET}")


# ═══════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════

def validate_model(model):
    resolved = LLM_ROUTER.resolve(model)
    if resolved not in GUARDRAILS.ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR:{Style.RESET_ALL} Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}exiting.{Style.RESET_ALL}")
        raise SystemExit(1)
    model_type = "Offline/FREE" if is_offline_model(resolved) else "Cloud/API"
    print(f"{Fore.LIGHTGREEN_EX}✓ Valid model: {Fore.CYAN}{resolved} {Fore.LIGHTBLACK_EX}({model_type}){Style.RESET_ALL}\n")
