"""
TIME_ESTIMATOR.py - How long will this model call take, and does the prompt fit?

Speeds are MEASURED on this Mac (2026-09-03), not guessed: qwen3:8b processes a
prompt at ~55-80 tokens/s and generates at ~11 tokens/s. The old table claimed 2,000
tokens/s, so every estimate was 25-40x optimistic. Cloud numbers are typical API
throughput incl. network overhead.

Token counting is delegated to LLM_ROUTER.estimate_tokens, which counts log/CSV text
at ~2 chars/token (what qwen actually does) instead of tiktoken's prose-tuned guess.
"""

import LLM_ROUTER
from color_support import Fore


class TimeEstimator:
    """Universal time estimation for all models"""

    def __init__(self):
        # seconds of fixed overhead, prompt tokens/s, output tokens/s, typical output tokens
        self.profiles = {
            # local - measured
            'qwen3:8b':        {'base_time': 3,  'prompt_tps': 60,     'gen_tps': 11,  'typical_output': 600, 'load_time': 40},
            # OpenAI - typical API throughput
            'gpt-4.1-nano':    {'base_time': 2,  'prompt_tps': 50000,  'gen_tps': 150, 'typical_output': 500},
            'gpt-4.1':         {'base_time': 3,  'prompt_tps': 40000,  'gen_tps': 80,  'typical_output': 500},
            'gpt-5-mini':      {'base_time': 4,  'prompt_tps': 60000,  'gen_tps': 90,  'typical_output': 800},
            'gpt-5':           {'base_time': 6,  'prompt_tps': 45000,  'gen_tps': 60,  'typical_output': 800},
            'gpt-4o-mini':     {'base_time': 2,  'prompt_tps': 70000,  'gen_tps': 120, 'typical_output': 300},
            # Claude - typical API throughput (CLI bridge adds ~3 s)
            'claude-opus-5':   {'base_time': 5,  'prompt_tps': 40000,  'gen_tps': 50,  'typical_output': 800},
            'claude-sonnet-5': {'base_time': 4,  'prompt_tps': 60000,  'gen_tps': 80,  'typical_output': 800},
            'claude-haiku-4-5': {'base_time': 3, 'prompt_tps': 80000,  'gen_tps': 120, 'typical_output': 500},
        }

    def _profile(self, model_name):
        return self.profiles.get(LLM_ROUTER.resolve(model_name))

    def estimate_time(self, model_name, input_tokens, model_type=None):
        """Estimated seconds for one call (model already loaded)."""
        p = self._profile(model_name)
        if not p:
            return int(input_tokens / 1000) + 5
        limit = self.get_model_context_limit(model_name)
        chunks = self._calculate_chunks(input_tokens, limit)
        per_chunk_prompt = (input_tokens / chunks) / p['prompt_tps']
        per_chunk_gen = p['typical_output'] / p['gen_tps']
        total = p['base_time'] + chunks * (per_chunk_prompt + per_chunk_gen)
        return int(total)

    def _calculate_chunks(self, input_tokens, max_tokens_per_chunk):
        if input_tokens <= max_tokens_per_chunk:
            return 1
        safe_tokens = max(1, int(max_tokens_per_chunk * 0.8))
        return (input_tokens + safe_tokens - 1) // safe_tokens

    def format_time_display(self, estimated_time, input_tokens, model_name):
        if estimated_time < 60:
            time_str = f"{estimated_time}s"
        else:
            minutes, seconds = divmod(estimated_time, 60)
            time_str = f"{minutes}m" if seconds == 0 else f"{minutes}m {seconds}s"
        limit = self.get_model_context_limit(model_name)
        if input_tokens > limit:
            time_str += f" ({self._calculate_chunks(input_tokens, limit)} chunks)"
        p = self._profile(model_name)
        if p and p.get('load_time') and LLM_ROUTER.is_local(model_name):
            time_str += f" (+{p['load_time']}s if the model must load first)"
        return time_str

    def get_model_context_limit(self, model_name):
        """Practical input limit (LLM_ROUTER is the source of truth)."""
        return LLM_ROUTER.context_limit(model_name)

    def estimate_tokens(self, messages, model_name="gpt-4"):
        """CSV-aware estimate (see LLM_ROUTER.estimate_tokens). model_name kept for old callers."""
        return LLM_ROUTER.estimate_tokens(messages, model_name)


# Global instance
time_estimator = TimeEstimator()


def estimate_inference_time(model_name, input_tokens, model_type=None):
    return time_estimator.estimate_time(model_name, input_tokens, model_type)


def estimate_time(model_name, input_tokens, model_type=None):
    return time_estimator.estimate_time(model_name, input_tokens, model_type)


def format_time_display(estimated_time, input_tokens, model_name):
    return time_estimator.format_time_display(estimated_time, input_tokens, model_name)


def get_model_context_limit(model_name):
    return time_estimator.get_model_context_limit(model_name)


def estimate_tokens(messages, model_name="gpt-4"):
    return time_estimator.estimate_tokens(messages, model_name)
