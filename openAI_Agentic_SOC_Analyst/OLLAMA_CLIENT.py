"""
OLLAMA_CLIENT.py - the one place the SOC analyst talks to Ollama.

Why this file matters (audit 2026-09-03): it used to hard-code num_ctx=8192 for every
call. Ollama does not error when a prompt is longer than num_ctx - it keeps 4 tokens
plus the tail and silently drops the rest (server.log: "truncating input prompt
limit=4098 prompt=73920"). The system prompt, the flag question and most log rows
were being thrown away before the model ever saw them. Now:

  * num_ctx is sized to the prompt (from LLM_ROUTER's CSV-aware estimate) and capped
    at what this Mac can actually process (MAX_CTX).
  * a prompt that cannot fit raises PromptTooLargeError - never truncates.
  * qwen3 is a thinking model: thinking tokens count against num_predict, and a 2K
    budget came back EMPTY on hard questions. Thinking is now explicit (think=...)
    and the output budget is large enough for it.
  * every reply is checked for done_reason == "length" (cut off) and for the
    prompt_eval_count Ollama reports, so truncation can never hide again.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path

import requests

DEFAULT_HOST = "http://localhost:11434"
LOCAL_MODEL = "qwen3:8b"

# Practical ceilings on this 24 GB Mac (measured 2026-09-03, ~55-80 prompt tok/s).
MAX_CTX = {LOCAL_MODEL: 32_768}
DEFAULT_MAX_CTX = 16_384
MIN_CTX = 4_096
DEFAULT_NUM_PREDICT = 4_096
THINKING_NUM_PREDICT = 8_192
THINKING_MODELS = ("qwen3", "gemma4", "deepseek-r1")


class PromptTooLargeError(ValueError):
    pass


def _host(host=None):
    return host or os.environ.get("OLLAMA_HOST", DEFAULT_HOST)


# ═══════════════════════════════════════════════════════════════════════
# PRE-FLIGHT
# ═══════════════════════════════════════════════════════════════════════

def verify_artemis_and_ollama(host=None, required=(LOCAL_MODEL,)):
    """
    Startup pre-flight: Artemis volume mounted, Ollama reachable, required model pulled.
    Raises RuntimeError with the exact fix if anything is missing.
    """
    host = _host(host)
    artemis_path = Path("/Volumes/Artemis/Local_LMs/.ollama/models")
    if not artemis_path.exists():
        raise RuntimeError(
            "Artemis volume not found at /Volumes/Artemis/Local_LMs/.ollama/models\n"
            "Fix: Connect and mount the Artemis NVMe drive, then re-run."
        )
    try:
        tags_resp = requests.get(f"{host}/api/tags", timeout=5)
        tags_resp.raise_for_status()
        available = {m["name"] for m in tags_resp.json().get("models", [])}
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Ollama not reachable at {host}\nFix: Run 'ollama serve' in a terminal, then re-run the agent.")
    except Exception as e:
        raise RuntimeError(f"Ollama health check failed: {e}")
    missing = set(required) - available
    if missing:
        pull_cmds = "\n".join(f"  ollama pull {m}" for m in sorted(missing))
        raise RuntimeError(f"Missing Ollama models: {sorted(missing)}\nFix — run:\n{pull_cmds}")
    return f"[OLLAMA] Local model verified: {sorted(required)}"


def installed_models(host=None) -> set[str]:
    try:
        r = requests.get(f"{_host(host)}/api/tags", timeout=5)
        r.raise_for_status()
        return {m["name"] for m in r.json().get("models", [])}
    except Exception:
        return set()


# ═══════════════════════════════════════════════════════════════════════
# WINDOW SIZING
# ═══════════════════════════════════════════════════════════════════════

def is_thinking_model(model_name: str) -> bool:
    return any(model_name.startswith(p) for p in THINKING_MODELS)


def _estimate(messages) -> int:
    import LLM_ROUTER
    return LLM_ROUTER.estimate_tokens(messages)


def choose_num_ctx(est_tokens: int, num_predict: int, model_name: str) -> int:
    """
    Window = prompt estimate (+10%) + output budget + margin, rounded up to 1K,
    clamped to [MIN_CTX, MAX_CTX]. Raises PromptTooLargeError if it cannot fit.
    """
    cap = MAX_CTX.get(model_name, DEFAULT_MAX_CTX)
    needed = int(est_tokens * 1.10) + num_predict + 256
    if needed > cap:
        raise PromptTooLargeError(
            f"Prompt ~{est_tokens:,} tokens + {num_predict:,} output needs a {needed:,}-token window, "
            f"but {model_name} is capped at {cap:,} on this machine. Shrink the log data first."
        )
    return max(MIN_CTX, min(cap, int(math.ceil(needed / 1024.0) * 1024)))


def _options(est_tokens, num_predict, model_name, temperature):
    return {
        "temperature": temperature,
        "num_ctx": choose_num_ctx(est_tokens, num_predict, model_name),
        "num_predict": num_predict,
    }


def _resolve_think(think, json_mode, model_name):
    """Explicit wins; otherwise: JSON extraction → no thinking (fast, compact), free text → think."""
    if not is_thinking_model(model_name):
        return None
    if think is not None:
        return bool(think)
    return not json_mode


# ═══════════════════════════════════════════════════════════════════════
# CALLS
# ═══════════════════════════════════════════════════════════════════════

def chat_ex(messages, model_name, host=None, *, json_mode=False, json_schema=None, temperature=0.1,
            num_predict=None, think=None, timeout=600, est_tokens=None):
    """
    Full-featured call. Returns (reply_text, meta) where meta has the numbers Ollama
    reported: prompt tokens actually evaluated, output tokens, done_reason, num_ctx used.
    """
    host = _host(host)
    est_tokens = est_tokens if est_tokens is not None else _estimate(messages)
    use_think = _resolve_think(think, json_mode or bool(json_schema), model_name)
    if num_predict is None:
        num_predict = THINKING_NUM_PREDICT if use_think else DEFAULT_NUM_PREDICT

    payload = {
        "model": model_name,
        "messages": messages,
        "stream": False,
        "options": _options(est_tokens, num_predict, model_name, temperature),
    }
    if json_schema:
        payload["format"] = json_schema          # Ollama enforces the schema (>= 0.5)
    elif json_mode:
        payload["format"] = "json"
    if use_think is not None:
        payload["think"] = use_think

    try:
        resp = requests.post(f"{host}/api/chat", json=payload, timeout=timeout)
    except requests.exceptions.ReadTimeout:
        print(f"\n⚠ Ollama timeout after {timeout}s (window {payload['options']['num_ctx']:,} tokens). "
              f"Reduce the log data or raise the timeout.")
        raise
    resp.raise_for_status()
    data = resp.json()
    message = data.get("message", {}) or {}
    text = message.get("content", "") or ""

    meta = {
        "num_ctx": payload["options"]["num_ctx"],
        "think": use_think,
        "input_tokens": data.get("prompt_eval_count"),
        "output_tokens": data.get("eval_count"),
        "stop": data.get("done_reason"),
        "thinking_chars": len(message.get("thinking") or ""),
    }
    # Loud checks - these two conditions are exactly what hid the bug for months.
    if data.get("done_reason") == "length":
        print(f"⚠ Ollama cut the reply off at {num_predict:,} tokens (thinking used "
              f"{meta['thinking_chars']} chars). Consider think=False or a larger budget.")
        meta["truncated_output"] = True
    pe = data.get("prompt_eval_count")
    if pe is not None and est_tokens > 0 and pe < est_tokens * 0.5 and pe < payload["options"]["num_ctx"] * 0.9:
        # Far fewer prompt tokens than we sent: usually cache reuse (fine), but flag it.
        meta["prompt_eval_low"] = True
    return text, meta


def chat(messages, model_name, host=None, json_mode=True, temperature=0, timeout=600, **kw):
    """Backward-compatible wrapper: returns just the reply text."""
    text, _ = chat_ex(messages, model_name, host, json_mode=json_mode, temperature=temperature,
                      timeout=timeout, **kw)
    return text


def stream_text(messages, model_name, host=None, *, temperature=0.3, num_predict=None, think=None,
                est_tokens=None):
    """Yield reply text pieces only (thinking is skipped; a leaked <think> block is filtered)."""
    host = _host(host)
    est_tokens = est_tokens if est_tokens is not None else _estimate(messages)
    use_think = _resolve_think(think, False, model_name)
    if num_predict is None:
        num_predict = THINKING_NUM_PREDICT if use_think else DEFAULT_NUM_PREDICT
    payload = {
        "model": model_name,
        "messages": messages,
        "stream": True,
        "options": _options(est_tokens, num_predict, model_name, temperature),
    }
    if use_think is not None:
        payload["think"] = use_think

    in_think = False
    with requests.post(f"{host}/api/chat", json=payload, stream=True, timeout=None) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                obj = json.loads(line.decode("utf-8"))
            except Exception:
                continue
            piece = (obj.get("message") or {}).get("content", "") or obj.get("response", "")
            if not piece:
                if obj.get("done") and obj.get("done_reason") == "length":
                    yield "\n⚠ [reply cut off - output budget reached]"
                continue
            # Some builds leak <think> tags into content; keep them out of the user's view.
            if "<think>" in piece:
                in_think = True
                piece = piece.split("<think>")[0]
            if in_think:
                if "</think>" in piece:
                    in_think = False
                    piece = piece.split("</think>", 1)[1]
                else:
                    continue
            if piece:
                yield piece


def chat_stream(messages, model_name, host=None, json_mode=False, temperature=0, **kw):
    """
    Legacy raw-line streamer kept for older callers: yields Ollama's JSON lines as
    strings. New code should use stream_text() (or LLM_ROUTER.chat_stream).
    """
    host = _host(host)
    est_tokens = _estimate(messages)
    use_think = _resolve_think(kw.get("think"), json_mode, model_name)
    num_predict = kw.get("num_predict") or (THINKING_NUM_PREDICT if use_think else DEFAULT_NUM_PREDICT)
    payload = {
        "model": model_name, "messages": messages, "stream": True,
        "options": _options(est_tokens, num_predict, model_name, temperature),
    }
    if json_mode:
        payload["format"] = "json"
    if use_think is not None:
        payload["think"] = use_think
    with requests.post(f"{host}/api/chat", json=payload, stream=True, timeout=None) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                yield line.decode("utf-8")
            except Exception:
                yield line
