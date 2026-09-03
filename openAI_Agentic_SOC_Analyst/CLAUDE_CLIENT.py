"""
CLAUDE_CLIENT.py - Anthropic Claude as a cloud model option for the SOC analyst.

Two backends, chosen automatically by available():

  api  - the official `anthropic` SDK. Used when ANTHROPIC_API_KEY is set in the
         environment or in _keys.py (or an `ant auth login` profile exists). Pay-per-token.
  cli  - the Claude Code CLI in headless mode (`claude -p`). Uses Peter's existing
         Claude subscription login - no key anywhere in this repo. This is what runs
         on this Mac today (verified 2026-09-03: ~3 s round trip, structured output works).

Both return (reply_text, meta). meta carries token usage, stop reason, cost and which
backend answered, so LLM_ROUTER can log it like every other provider.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

DEFAULT_MODEL = "claude-opus-5"
# Models whose API rejects sampling params and use adaptive thinking (Claude 5 family).
ADAPTIVE_THINKING_MODELS = ("claude-opus-5", "claude-sonnet-5", "claude-fable-5", "claude-opus-4-8", "claude-opus-4-7")

_backend_cache: str | None | bool = False   # False = not probed yet


class ClaudeUnavailableError(RuntimeError):
    pass


# ═══════════════════════════════════════════════════════════════════════
# BACKEND DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

def _api_key() -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    try:
        import _keys
        return getattr(_keys, "ANTHROPIC_API_KEY", None) or None
    except Exception:
        return None


def available(force: bool = False) -> str | None:
    """'api', 'cli' or None. Cached; pass force=True to re-probe."""
    global _backend_cache
    if _backend_cache is not False and not force:
        return _backend_cache
    if _api_key() or os.path.isdir(os.path.expanduser("~/.config/anthropic")):
        try:
            import anthropic  # noqa: F401
            _backend_cache = "api"
            return _backend_cache
        except ImportError:
            pass
    _backend_cache = "cli" if shutil.which("claude") else None
    return _backend_cache


def describe_backend() -> str:
    b = available()
    return {"api": "Anthropic API (key)", "cli": "Claude Code login (subscription)", None: "not available"}[b]


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC CALL
# ═══════════════════════════════════════════════════════════════════════

def chat(messages, model=DEFAULT_MODEL, *, system="", json_schema=None, json_mode=False,
         max_tokens=16_000, think=None, timeout=900, temperature=None):
    """
    messages: chat turns WITHOUT system entries (LLM_ROUTER splits them out).
    Returns (text, meta). With json_schema the text is the JSON document itself.
    """
    backend = available()
    if backend == "api":
        return _chat_api(messages, model, system, json_schema, json_mode, max_tokens, think, timeout, temperature)
    if backend == "cli":
        return _chat_cli(messages, model, system, json_schema, json_mode, max_tokens, think, timeout)
    raise ClaudeUnavailableError(
        "Claude is not available: no ANTHROPIC_API_KEY and no `claude` CLI on PATH.\n"
        "Fix: install Claude Code and run `claude` once to log in, or add ANTHROPIC_API_KEY to _keys.py."
    )


# ═══════════════════════════════════════════════════════════════════════
# API BACKEND (official SDK)
# ═══════════════════════════════════════════════════════════════════════

def _chat_api(messages, model, system, json_schema, json_mode, max_tokens, think, timeout, temperature):
    import anthropic

    key = _api_key()
    client = anthropic.Anthropic(api_key=key, timeout=timeout) if key else anthropic.Anthropic(timeout=timeout)

    kwargs = {"model": model, "max_tokens": max_tokens, "messages": _normalize_turns(messages)}
    if system:
        kwargs["system"] = system
    if json_schema:
        kwargs["output_config"] = {"format": {"type": "json_schema", "schema": json_schema}}
    elif json_mode:
        kwargs["system"] = (system + "\n\n" if system else "") + "Reply with a single JSON object and nothing else."

    if model.startswith(ADAPTIVE_THINKING_MODELS):
        # Claude 5 family: adaptive thinking; sampling params are rejected. Lower effort = less thinking.
        if think is False:
            kwargs["output_config"] = {**kwargs.get("output_config", {}), "effort": "low"}
        else:
            kwargs["thinking"] = {"type": "adaptive"}
    else:
        # Haiku 4.5 and older: no adaptive thinking; temperature allowed.
        if temperature is not None:
            kwargs["temperature"] = temperature

    with client.messages.stream(**kwargs) as stream:
        msg = stream.get_final_message()

    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    meta = {
        "backend": "api",
        "input_tokens": getattr(msg.usage, "input_tokens", None),
        "output_tokens": getattr(msg.usage, "output_tokens", None),
        "cache_read": getattr(msg.usage, "cache_read_input_tokens", None),
        "stop": msg.stop_reason,
    }
    if msg.stop_reason == "refusal" and getattr(msg, "stop_details", None):
        meta["refusal"] = getattr(msg.stop_details, "category", None)
        text = text or f"[Claude declined this request: {meta['refusal']}]"
    if msg.stop_reason == "max_tokens":
        meta["truncated_output"] = True
    return text, meta


def _normalize_turns(messages):
    """Drop empty turns and guarantee the first turn is a user turn."""
    turns = [{"role": m["role"], "content": m.get("content", "")} for m in messages
             if m.get("role") in ("user", "assistant") and m.get("content")]
    if not turns or turns[0]["role"] != "user":
        turns.insert(0, {"role": "user", "content": "(continue)"})
    return turns


# ═══════════════════════════════════════════════════════════════════════
# CLI BACKEND (Claude Code headless, subscription login)
# ═══════════════════════════════════════════════════════════════════════

def _render_prompt(messages) -> str:
    """The CLI takes one prompt: fold earlier turns into a transcript, last user turn is the ask."""
    turns = _normalize_turns(messages)
    if len(turns) == 1:
        return turns[0]["content"]
    *history, last = turns
    lines = ["Conversation so far (for context):", ""]
    for t in history:
        who = "Analyst" if t["role"] == "user" else "Assistant"
        lines.append(f"{who}: {t['content']}")
        lines.append("")
    lines.append("Now respond to the analyst's latest message:")
    lines.append(last["content"])
    return "\n".join(lines)


def _chat_cli(messages, model, system, json_schema, json_mode, max_tokens, think, timeout):
    exe = shutil.which("claude")
    if not exe:
        raise ClaudeUnavailableError("`claude` CLI not found on PATH")

    cmd = [exe, "-p", "--output-format", "json", "--no-session-persistence", "--tools", "", "--model", model]
    sys_prompt = system or ""
    if json_schema:
        cmd += ["--json-schema", json.dumps(json_schema)]
    elif json_mode:
        sys_prompt = (sys_prompt + "\n\n" if sys_prompt else "") + "Reply with a single JSON object and nothing else."
    if sys_prompt:
        cmd += ["--system-prompt", sys_prompt]
    if think is False:
        cmd += ["--effort", "low"]

    # Running inside a Claude Code session sets these; a nested headless call must not inherit them.
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")}

    try:
        proc = subprocess.run(cmd, input=_render_prompt(messages), capture_output=True, text=True,
                              timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Claude CLI did not answer within {timeout}s")

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip()[:400]
        if "log in" in err.lower() or "auth" in err.lower():
            raise ClaudeUnavailableError(f"Claude CLI is not logged in. Run `claude` once in a terminal to sign in. ({err})")
        raise RuntimeError(f"Claude CLI failed (exit {proc.returncode}): {err}")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        # Some CLI versions print extra lines; take the last JSON object
        data = {}
        for line in reversed(proc.stdout.strip().splitlines()):
            try:
                data = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        if not data:
            raise RuntimeError(f"Claude CLI returned no JSON: {proc.stdout[:300]}")

    if data.get("is_error"):
        raise RuntimeError(f"Claude CLI error: {str(data.get('result'))[:300]}")

    structured = data.get("structured_output")
    if json_schema and isinstance(structured, dict):
        text = json.dumps(structured)
    else:
        text = data.get("result") or ""

    usage = data.get("usage") or {}
    meta = {
        "backend": "cli",
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "cache_read": usage.get("cache_read_input_tokens"),
        "stop": data.get("stop_reason"),
        "cost_usd_equiv": data.get("total_cost_usd"),   # informational: subscription, not billed per call
        "cli_session": data.get("session_id"),
    }
    return text, meta
