"""LLM providers: Ollama (local) and any OpenAI-compatible API.
API keys come from the environment (AI_API_KEY) only, are never logged,
and are never stored in files. Untrusted application content is wrapped
in delimiters and labelled as DATA, never as instructions.
"""
from __future__ import annotations
import json, logging, os
import requests

log = logging.getLogger("spyder.ai")


class BaseProvider:
    name = "base"

    def complete(self, system: str, user: str, model: str, temperature: float,
                 max_tokens: int, timeout: int) -> str:
        raise NotImplementedError


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, base_url="http://localhost:11434"):
        self.base_url = base_url.rstrip("/")

    def complete(self, system, user, model, temperature, max_tokens, timeout):
        resp = requests.post(f"{self.base_url}/api/chat", json={
            "model": model or "llama3.1", "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": temperature, "num_predict": max_tokens}},
            timeout=timeout)
        resp.raise_for_status()
        return resp.json()["message"]["content"]


class OpenAICompatibleProvider(BaseProvider):
    name = "openai"

    def __init__(self, base_url="https://api.openai.com/v1", api_key=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("AI_API_KEY", "")
        if not self.api_key:
            raise ValueError("OpenAI-compatible provider needs AI_API_KEY in the environment")

    def complete(self, system, user, model, temperature, max_tokens, timeout):
        # The API key is sent only in the Authorization header, never in the body or logs.
        resp = requests.post(f"{self.base_url}/chat/completions", json={
            "model": model or "gpt-4o-mini", "temperature": temperature, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            headers={"Authorization": f"Bearer {self.api_key}"}, timeout=timeout)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def get_provider(name, base_url="", api_key=None):
    if name == "ollama":
        return OllamaProvider(base_url or "http://localhost:11434")
    if name == "openai":
        return OpenAICompatibleProvider(base_url or "https://api.openai.com/v1", api_key)
    raise ValueError(f"Unknown AI provider: {name}")
