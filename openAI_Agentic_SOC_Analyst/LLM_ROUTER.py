"""
LLM_ROUTER.py - Single front door for every language-model call in the SOC analyst.

One registry (MODELS) is the source of truth for which models exist, which provider
serves them, their real context windows and prices. Every module that needs a model
reply calls LLM_ROUTER.chat()/chat_json()/chat_stream() and never touches a provider
SDK directly, so provider quirks (Ollama's num_ctx, Claude's thinking) live in
exactly one place.

Providers (OpenAI decommissioned 2026-09-04 at Peter's request - "way too many language models"):
  ollama  - local qwen3:8b (the only local model on this Mac that fits in memory)
  claude  - Anthropic: official SDK when ANTHROPIC_API_KEY is present, otherwise the
            Claude Code CLI bridge that runs on Peter's subscription login

Every call is appended to _llm_calls.jsonl (model, purpose, tokens, seconds, stop reason)
so "what did the AI actually see?" is always answerable after the fact.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Iterator

from color_support import Fore

# ═══════════════════════════════════════════════════════════════════════
# REGISTRY - the only place a model is described
# ═══════════════════════════════════════════════════════════════════════

LOCAL_MODEL = "qwen3:8b"

MODELS = {
    # ── Local (Ollama) ──────────────────────────────────────────────────
    # qwen3:8b advertises 128K, but prompt processing on this Mac is ~55-80 tok/s,
    # so 32K is the practical ceiling (a 32K prompt already takes ~7 minutes).
    "qwen3:8b": {
        "provider": "ollama", "label": "Qwen3 8B (local, free, offline)",
        "max_input_tokens": 32_768, "max_output_tokens": 8_192,
        "cost_per_million_input": 0.0, "cost_per_million_output": 0.0,
        "thinking": True, "tier": {},
    },
    # ── Anthropic / Claude ──────────────────────────────────────────────
    # Prices are Anthropic first-party API rates. On the CLI bridge (subscription) the
    # per-call charge is $0 - the cost column is shown as "subscription" instead.
    "claude-opus-5":   {"provider": "claude", "label": "Claude Opus 5 (best reasoning)", "max_input_tokens": 1_000_000, "max_output_tokens": 128_000,
                        "cost_per_million_input": 5.00, "cost_per_million_output": 25.00, "thinking": True, "tier": {}},
    # Sonnet/Haiku stay reachable by name (type it at a model prompt) but are off the dashboard.
    "claude-sonnet-5": {"provider": "claude", "label": "Claude Sonnet 5 (fast, strong)", "max_input_tokens": 1_000_000, "max_output_tokens": 128_000,
                        "cost_per_million_input": 2.00, "cost_per_million_output": 10.00, "thinking": True, "tier": {}, "hidden": True},
    "claude-haiku-4-5": {"provider": "claude", "label": "Claude Haiku 4.5 (cheapest)", "max_input_tokens": 200_000, "max_output_tokens": 64_000,
                         "cost_per_million_input": 1.00, "cost_per_million_output": 5.00, "thinking": False, "tier": {}, "hidden": True},
}

# Old names that still appear in saved sessions / older code paths.
ALIASES = {
    "qwen": LOCAL_MODEL,
    "local": LOCAL_MODEL,
    "local-mix": LOCAL_MODEL,   # the retired two-model hybrid → the one local model
    "gpt-oss:20b": LOCAL_MODEL,  # retired (removed from disk 2026-05-11)
    # OpenAI models decommissioned 2026-09-04 → old sessions that name them get Claude
    "gpt-4.1-nano": "claude-opus-5", "gpt-4.1": "claude-opus-5", "gpt-5-mini": "claude-opus-5",
    "gpt-5": "claude-opus-5", "gpt-4o-mini": "claude-opus-5", "gpt-4o": "claude-opus-5",
    "gemma4:26b": LOCAL_MODEL,   # does not fit in 24 GB - retired 2026-09-03
    "gemma4:e4b": LOCAL_MODEL,   # retired 2026-09-03 (one local model policy)
    "mixtral": LOCAL_MODEL,
    "claude": "claude-opus-5",
    "opus": "claude-opus-5",
    "sonnet": "claude-sonnet-5",
    "haiku": "claude-haiku-4-5",
}

# The dashboard: one local model, one cloud model. Local is the default.
CLOUD_MENU = ["claude-opus-5"]
LOCAL_MENU = [LOCAL_MODEL]
DEFAULT_MODEL = LOCAL_MODEL

CALL_LOG = "_llm_calls.jsonl"



# One exception class for "the prompt cannot fit" - defined in OLLAMA_CLIENT (no heavy
# imports there) and re-exported here so callers can catch LLM_ROUTER.PromptTooLargeError.
from OLLAMA_CLIENT import PromptTooLargeError  # noqa: E402


def _too_large(model, estimated_tokens, limit) -> PromptTooLargeError:
    err = PromptTooLargeError(
        f"Prompt is ~{estimated_tokens:,} tokens but {model} can take at most {limit:,}. "
        f"Reduce the log data (sample, filter, or split) before calling the model."
    )
    err.model, err.estimated_tokens, err.limit = model, estimated_tokens, limit
    return err


# ═══════════════════════════════════════════════════════════════════════
# REGISTRY HELPERS
# ═══════════════════════════════════════════════════════════════════════

def resolve(model: str | None) -> str | None:
    """Map any alias/old name to a canonical registry key (returns input if unknown)."""
    if model is None:
        return None
    return ALIASES.get(model, model)


def info(model: str) -> dict:
    return MODELS.get(resolve(model), {})


def is_known(model: str) -> bool:
    return resolve(model) in MODELS


def provider_of(model: str) -> str | None:
    return info(model).get("provider")


def is_local(model: str) -> bool:
    return provider_of(model) == "ollama"


def is_claude(model: str) -> bool:
    return provider_of(model) == "claude"


def context_limit(model: str) -> int:
    return info(model).get("max_input_tokens", 32_000)


def output_limit(model: str) -> int:
    return info(model).get("max_output_tokens", 4_096)


def set_openai_client(client) -> None:
    """Kept for old call sites; OpenAI is decommissioned, so this is a no-op."""
    return None


def claude_backend() -> str | None:
    """'api' (SDK + key), 'cli' (Claude Code login) or None. Cached after first probe."""
    import CLAUDE_CLIENT
    return CLAUDE_CLIENT.available()


def cost_label(model: str) -> str:
    """Human-readable cost for menus."""
    m = info(model)
    if not m:
        return "unknown"
    if m["provider"] == "ollama":
        return "Free (local)"
    if claude_backend() == "cli":
        return "Subscription (Claude Code login)"
    return f"${m['cost_per_million_input']:.2f} / ${m['cost_per_million_output']:.2f} per M tokens (API key)"


# ═══════════════════════════════════════════════════════════════════════
# TOKEN ESTIMATION - CSV-aware
# ═══════════════════════════════════════════════════════════════════════
# Measured 2026-09-03: qwen3 tokenizes log/CSV text at ~1.9 chars per token
# (IPs, timestamps, punctuation), prose at ~4. tiktoken's gpt-4 encoding
# under-counted a CSV prompt by 2x, which is how 74K tokens got sent into an
# 8K window. So log data is counted at chars/2, everything else at chars/4.

LOG_MARKERS = ("Log Data:", "Analyze these logs:", "LOG DATA:", "# CSV DATA SUMMARY")


def _split_prose_and_logs(text: str) -> tuple[int, int]:
    """Return (prose_chars, log_chars) for one block of text."""
    for marker in LOG_MARKERS:
        idx = text.find(marker)
        if idx != -1:
            return idx, len(text) - idx
    # No marker: guess from shape - many commas/digits per line means CSV
    sample = text[:4000]
    if sample.count(",") > sample.count(" ") // 2 and sum(c.isdigit() for c in sample) > len(sample) * 0.15:
        return 0, len(text)
    return len(text), 0


def estimate_tokens(messages_or_text, model: str | None = None) -> int:
    """Conservative token estimate. Over-estimating only costs KV memory; under-estimating loses data."""
    if isinstance(messages_or_text, str):
        blocks = [messages_or_text]
    else:
        blocks = []
        for m in messages_or_text:
            if isinstance(m, dict):
                c = m.get("content", "")
                if isinstance(c, list):  # multimodal blocks - count text parts
                    c = " ".join(p.get("text", "") for p in c if isinstance(p, dict))
                blocks.append(str(c))
            else:
                blocks.append(str(m))
    total = 0
    for b in blocks:
        prose, logs = _split_prose_and_logs(b)
        total += prose / 4.0 + logs / 2.0 + 8  # +8 per message for role/formatting tokens
    return int(total) + 1


def fits(messages, model: str, reserve_output: int | None = None) -> tuple[bool, int, int]:
    """(fits?, estimated_input_tokens, usable_input_limit)."""
    m = resolve(model)
    limit = context_limit(m) - (reserve_output or min(output_limit(m), 4096))
    est = estimate_tokens(messages, m)
    return est <= limit, est, limit


# ═══════════════════════════════════════════════════════════════════════
# CALL LOG
# ═══════════════════════════════════════════════════════════════════════

def _log(record: dict) -> None:
    try:
        record["ts"] = datetime.now().isoformat(timespec="seconds")
        with open(CALL_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
# UNIFIED CALLS
# ═══════════════════════════════════════════════════════════════════════

def _system_and_rest(messages):
    """Split chat-style messages into (system_text, non_system_messages)."""
    system_parts, rest = [], []
    for m in messages:
        if m.get("role") == "system":
            system_parts.append(m.get("content", ""))
        else:
            rest.append(m)
    return "\n\n".join(p for p in system_parts if p), rest


def chat(messages, model, *, json_mode=False, json_schema=None, temperature=0.1,
         max_tokens=None, think=None, timeout=None, purpose="") -> str:
    """
    Send chat messages, get the reply text. Raises PromptTooLargeError instead of
    letting any provider drop input. json_schema (dict) forces that exact shape
    where the provider supports it; json_mode=True asks for any valid JSON object.
    """
    m = resolve(model)
    if m not in MODELS:
        raise ValueError(f"Unknown model '{model}'. Known: {', '.join(MODELS)}")
    provider = MODELS[m]["provider"]
    max_tokens = max_tokens or min(output_limit(m), 8_192 if provider == "ollama" else 16_000)

    ok, est, limit = fits(messages, m, reserve_output=max_tokens)
    if not ok:
        raise _too_large(m, est, limit)

    t0 = time.time()
    record = {"model": m, "provider": provider, "purpose": purpose, "est_input_tokens": est,
              "json": bool(json_mode or json_schema)}
    try:
        if provider == "ollama":
            import OLLAMA_CLIENT
            text, meta = OLLAMA_CLIENT.chat_ex(
                messages, m, json_mode=json_mode, json_schema=json_schema, temperature=temperature,
                num_predict=max_tokens, think=think, timeout=timeout or 600, est_tokens=est)
            record.update(meta)
        elif provider == "claude":
            import CLAUDE_CLIENT
            system, rest = _system_and_rest(messages)
            text, meta = CLAUDE_CLIENT.chat(rest, m, system=system, json_schema=json_schema,
                                            json_mode=json_mode, max_tokens=max_tokens,
                                            think=think, timeout=timeout or 900)
            record.update(meta)
        else:
            raise ValueError(f"No provider for model '{m}' - only the local model and Claude are wired.")
        record["seconds"] = round(time.time() - t0, 1)
        record["ok"] = True
        _log(record)
        return text
    except Exception as e:
        record.update({"seconds": round(time.time() - t0, 1), "ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
        _log(record)
        raise


def chat_json(messages, model, schema=None, **kw) -> dict:
    """chat() + robust JSON extraction. Always returns a dict (empty on failure)."""
    text = chat(messages, model, json_mode=True, json_schema=schema, **kw)
    return extract_json(text)


def chat_stream(messages, model, *, temperature=0.3, max_tokens=None, think=None,
                purpose="") -> Iterator[str]:
    """Yield reply TEXT chunks (never thinking, never raw JSON lines)."""
    m = resolve(model)
    if m not in MODELS:
        raise ValueError(f"Unknown model '{model}'")
    provider = MODELS[m]["provider"]
    max_tokens = max_tokens or min(output_limit(m), 8_192 if provider == "ollama" else 16_000)
    ok, est, limit = fits(messages, m, reserve_output=max_tokens)
    if not ok:
        raise _too_large(m, est, limit)

    t0 = time.time()
    n_chars = 0
    try:
        if provider == "ollama":
            import OLLAMA_CLIENT
            for piece in OLLAMA_CLIENT.stream_text(messages, m, temperature=temperature,
                                                   num_predict=max_tokens, think=think, est_tokens=est):
                n_chars += len(piece)
                yield piece
        elif provider == "claude":
            # Claude bridge: non-streaming call, delivered as one chunk (CLI has no token stream)
            import CLAUDE_CLIENT
            system, rest = _system_and_rest(messages)
            text, _ = CLAUDE_CLIENT.chat(rest, m, system=system, max_tokens=max_tokens, think=think)
            n_chars = len(text)
            yield text
        else:
            raise ValueError(f"No provider for model '{m}' - only the local model and Claude are wired.")
        _log({"model": m, "provider": provider, "purpose": purpose or "stream", "est_input_tokens": est,
              "output_chars": n_chars, "seconds": round(time.time() - t0, 1), "ok": True, "stream": True})
    except Exception as e:
        _log({"model": m, "provider": provider, "purpose": purpose or "stream", "est_input_tokens": est,
              "seconds": round(time.time() - t0, 1), "ok": False, "stream": True,
              "error": f"{type(e).__name__}: {e}"[:300]})
        raise


# ═══════════════════════════════════════════════════════════════════════
# JSON EXTRACTION - tolerant of fences, prose, and thinking leftovers
# ═══════════════════════════════════════════════════════════════════════

def extract_json(text) -> dict:
    """Pull the first JSON object out of a model reply. Returns {} if none."""
    if isinstance(text, dict):
        return text
    if not text:
        return {}
    s = str(text).strip()
    # Strip <think>...</think> if a model leaked it into content
    if "<think>" in s and "</think>" in s:
        s = s.split("</think>", 1)[1].strip()
    # Fenced block?
    if "```" in s:
        for part in s.split("```"):
            p = part.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                try:
                    return json.loads(p)
                except json.JSONDecodeError:
                    pass
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    # First balanced {...}
    start = s.find("{")
    depth = 0
    for i in range(start, len(s)) if start != -1 else []:
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except json.JSONDecodeError:
                    break
    return {}


def describe(model: str) -> str:
    """One-line description for menus and logs."""
    m = resolve(model)
    d = info(m)
    if not d:
        return f"{model} (unknown)"
    where = {"ollama": "Local/Offline", "claude": "Claude cloud"}.get(d["provider"], d["provider"])
    return f"{m} - {d['label']} | {where} | {cost_label(m)} | {d['max_input_tokens']:,} token window"
