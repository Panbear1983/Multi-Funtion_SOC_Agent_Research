import os
import requests
from pathlib import Path


def verify_artemis_and_ollama(host=None):
    """
    Startup pre-flight: verify Artemis NVMe volume and all required Ollama models.
    Raises RuntimeError with actionable message if any check fails.
    Call once at process startup before any inference.
    """
    if host is None:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    # 1. Check Artemis volume is mounted
    artemis_path = Path("/Volumes/Artemis/Local_LMs/.ollama/models")
    if not artemis_path.exists():
        raise RuntimeError(
            "Artemis volume not found at /Volumes/Artemis/Local_LMs/.ollama/models\n"
            "Fix: Connect and mount the Artemis NVMe drive, then re-run."
        )

    # 2. Check Ollama daemon is reachable
    try:
        tags_resp = requests.get(f"{host}/api/tags", timeout=5)
        tags_resp.raise_for_status()
        available = {m["name"] for m in tags_resp.json().get("models", [])}
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Ollama not reachable at {host}\n"
            "Fix: Run 'ollama serve' in a terminal, then re-run the agent."
        )
    except Exception as e:
        raise RuntimeError(f"Ollama health check failed: {e}")

    # 3. Check all required models are pulled
    required = {"qwen3:8b", "gemma4:26b", "gemma4:e4b"}
    missing = required - available
    if missing:
        pull_cmds = "\n".join(f"  ollama pull {m}" for m in sorted(missing))
        raise RuntimeError(
            f"Missing Ollama models: {sorted(missing)}\n"
            f"Fix — run:\n{pull_cmds}"
        )

    return f"[OLLAMA] All models verified: {sorted(required)}"


def chat(messages, model_name, host=None, json_mode=True, temperature=0, timeout=300):

	if host is None:
		host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

	url = f"{host}/api/chat"

	payload = {
		"model": model_name,
		"messages": messages,
		"stream": False,
		"options": {
			"temperature": temperature,
			"num_ctx": 8192,  # Context window
			"num_predict": 2048  # Max tokens to generate
		}
	}

	# Request JSON-formatted output if supported by the model/runtime
	if json_mode:
		payload["format"] = "json"

	try:
		resp = requests.post(url, json=payload, timeout=timeout)
	except requests.exceptions.ReadTimeout:
		print(f"\n⚠ Ollama timeout after {timeout}s. Try:\n  1. Reduce log size\n  2. Use faster model\n  3. Increase timeout")
		raise
	if resp.status_code == 404:
		# Fallback to /api/generate for older Ollama
		gen_url = f"{host}/api/generate"
		# Convert chat-style messages to a single prompt
		prompt_parts = []
		for m in messages:
			role = m.get("role", "user")
			content = m.get("content", "")
			prompt_parts.append(f"{role}: {content}")
		prompt = "\n".join(prompt_parts) + "\nassistant:"

		gen_payload = {
			"model": model_name,
			"prompt": prompt,
			"stream": False,
			"options": {
				"temperature": temperature
			}
		}
		if json_mode:
			gen_payload["format"] = "json"

		gen_resp = requests.post(gen_url, json=gen_payload, timeout=120)
		gen_resp.raise_for_status()
		gen_data = gen_resp.json()
		return gen_data.get("response", "")

	resp.raise_for_status()
	data = resp.json()

	# Ollama chat API returns { message: { role, content }, ... }
	message = data.get("message", {})
	return message.get("content", "")


def chat_stream(messages, model_name, host=None, json_mode=True, temperature=0):
	"""Stream responses from Ollama, yielding raw JSON lines or text chunks.

	Callers are responsible for buffering and parsing. This function intentionally
	avoids imposing a schema because Ollama may stream different shapes depending
	on model/runtime (chat vs generate endpoints).
	"""

	if host is None:
		host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

	url = f"{host}/api/chat"

	payload = {
		"model": model_name,
		"messages": messages,
		"stream": True,
		"options": {
			"temperature": temperature,
			"num_ctx": 8192,
			"num_predict": 2048
		}
	}

	if json_mode:
		payload["format"] = "json"

	with requests.post(url, json=payload, stream=True, timeout=None) as resp:
		resp.raise_for_status()
		for line in resp.iter_lines():
			if not line:
				continue
			try:
				yield line.decode("utf-8")
			except Exception:
				# Fallback to raw bytes if decoding fails
				yield line


