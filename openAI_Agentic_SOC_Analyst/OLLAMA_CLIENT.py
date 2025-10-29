import os
import requests


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


