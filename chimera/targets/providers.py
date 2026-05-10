"""API provider targets.

All providers that use an OpenAI-compatible chat completions API
share a single implementation. Providers with different APIs
(Anthropic, Cohere, Replicate) have minimal dedicated implementations.
"""

import os
import time
import requests
from typing import Union, List, Dict, Any, Optional

from chimera.targets.base import BaseTarget
from chimera.core.target_manager import TargetManager


def _to_text(prompt: Union[str, List[Dict]]) -> str:
    if isinstance(prompt, str):
        return prompt
    return " ".join(m.get("content", "") for m in prompt if isinstance(m, dict))


def _max_tokens(instance: Any, kwargs: dict) -> int:
    return kwargs.get("max_tokens", getattr(instance, "_default_max_tokens", 512))


class OpenAICompatibleTarget(BaseTarget):
    """Base for any OpenAI-compatible chat completions endpoint.

    Covers: OpenAI, Groq, Together AI, Mistral, vLLM, LiteLLM, LM Studio,
    and any other provider that implements /v1/chat/completions.
    """

    _base_url: str = "https://api.openai.com"
    _env_key: str = "OPENAI_API_KEY"

    def __init__(self, model_id: str, base_url: str = None, api_key: str = None, **kwargs):
        self._url = (base_url or self._base_url).rstrip("/")
        self._key = api_key or os.environ.get(self._env_key, "")
        super().__init__(model_id=model_id)

    def _load_model(self, **kwargs) -> None:
        if self._env_key and not self._key:
            raise ValueError(f"{self._env_key} is not set")

    def generate(self, prompt: Union[str, List[Dict]], **kwargs) -> str:
        text = _to_text(prompt)
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"

        r = requests.post(
            f"{self._url}/v1/chat/completions",
            headers=headers,
            json={
                "model": self.model_id,
                "messages": [{"role": "user", "content": text}],
                "max_tokens": _max_tokens(self, kwargs),
                "temperature": kwargs.get("temperature", 0.7),
            },
            timeout=kwargs.get("timeout", 60),
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class GroqTarget(OpenAICompatibleTarget):
    _base_url = "https://api.groq.com/openai"
    _env_key = "GROQ_API_KEY"


class TogetherTarget(OpenAICompatibleTarget):
    _base_url = "https://api.together.xyz"
    _env_key = "TOGETHER_API_KEY"


class MistralTarget(OpenAICompatibleTarget):
    _base_url = "https://api.mistral.ai"
    _env_key = "MISTRAL_API_KEY"


class VLLMTarget(OpenAICompatibleTarget):
    _env_key = ""  # no key needed for local vLLM

    def __init__(self, model_id: str, base_url: str = "http://localhost:8000", **kwargs):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)


class LiteLLMTarget(OpenAICompatibleTarget):
    _env_key = ""

    def __init__(self, model_id: str, base_url: str = "http://localhost:4000", **kwargs):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)


class LMStudioTarget(OpenAICompatibleTarget):
    _env_key = ""

    def __init__(self, model_id: str = "local", base_url: str = "http://localhost:1234", **kwargs):
        super().__init__(model_id=model_id, base_url=base_url, **kwargs)


class AzureOpenAITarget(BaseTarget):
    """Azure OpenAI Service."""

    def __init__(self, model_id: str, **kwargs):
        self._key = os.environ.get("AZURE_OPENAI_KEY", "")
        self._endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
        self._api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")
        super().__init__(model_id=model_id)

    def _load_model(self, **kwargs) -> None:
        if not self._key or not self._endpoint:
            raise ValueError("AZURE_OPENAI_KEY and AZURE_OPENAI_ENDPOINT must be set")

    def generate(self, prompt: Union[str, List[Dict]], **kwargs) -> str:
        text = _to_text(prompt)
        url = f"{self._endpoint}/openai/deployments/{self.model_id}/chat/completions?api-version={self._api_version}"
        r = requests.post(
            url,
            headers={"api-key": self._key},
            json={
                "messages": [{"role": "user", "content": text}],
                "max_tokens": _max_tokens(self, kwargs),
            },
            timeout=60,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class AnthropicTarget(BaseTarget):
    """Anthropic Claude."""

    def __init__(self, model_id: str, **kwargs):
        self._key = os.environ.get("ANTHROPIC_API_KEY", "")
        super().__init__(model_id=model_id)

    def _load_model(self, **kwargs) -> None:
        if not self._key:
            raise ValueError("ANTHROPIC_API_KEY is not set")

    def generate(self, prompt: Union[str, List[Dict]], **kwargs) -> str:
        text = _to_text(prompt)
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.model_id,
                "max_tokens": _max_tokens(self, kwargs),
                "messages": [{"role": "user", "content": text}],
            },
            timeout=60,
        )
        r.raise_for_status()
        return r.json()["content"][0]["text"]


class CohereTarget(BaseTarget):
    """Cohere."""

    def __init__(self, model_id: str, **kwargs):
        self._key = os.environ.get("COHERE_API_KEY", "")
        super().__init__(model_id=model_id)

    def _load_model(self, **kwargs) -> None:
        if not self._key:
            raise ValueError("COHERE_API_KEY is not set")

    def generate(self, prompt: Union[str, List[Dict]], **kwargs) -> str:
        text = _to_text(prompt)
        r = requests.post(
            "https://api.cohere.com/v2/chat",
            headers={"Authorization": f"Bearer {self._key}"},
            json={
                "model": self.model_id,
                "messages": [{"role": "user", "content": text}],
                "max_tokens": _max_tokens(self, kwargs),
            },
            timeout=60,
        )
        r.raise_for_status()
        d = r.json()
        return d.get("message", {}).get("content", [{}])[0].get("text", "")


class ReplicateTarget(BaseTarget):
    """Replicate — any open source model."""

    def __init__(self, model_id: str, **kwargs):
        self._key = os.environ.get("REPLICATE_API_TOKEN", "")
        super().__init__(model_id=model_id)

    def _load_model(self, **kwargs) -> None:
        if not self._key:
            raise ValueError("REPLICATE_API_TOKEN is not set")

    def generate(self, prompt: Union[str, List[Dict]], **kwargs) -> str:
        text = _to_text(prompt)
        headers = {"Authorization": f"Token {self._key}"}

        r = requests.post(
            f"https://api.replicate.com/v1/models/{self.model_id}/predictions",
            headers=headers,
            json={"input": {"prompt": text, "max_new_tokens": _max_tokens(self, kwargs)}},
            timeout=30,
        )
        r.raise_for_status()
        pid = r.json()["id"]

        for _ in range(60):
            time.sleep(2)
            poll = requests.get(
                f"https://api.replicate.com/v1/predictions/{pid}",
                headers=headers, timeout=10,
            )
            poll.raise_for_status()
            data = poll.json()
            if data["status"] == "succeeded":
                out = data.get("output", "")
                return "".join(out) if isinstance(out, list) else str(out)
            if data["status"] in ("failed", "canceled"):
                raise RuntimeError(f"Replicate: {data['status']}")

        raise TimeoutError("Replicate prediction timed out")


# Register all providers
_PROVIDERS = {
    "groq":      GroqTarget,
    "together":  TogetherTarget,
    "mistral":   MistralTarget,
    "azure":     AzureOpenAITarget,
    "anthropic": AnthropicTarget,
    "cohere":    CohereTarget,
    "replicate": ReplicateTarget,
    "vllm":      VLLMTarget,
    "litellm":   LiteLLMTarget,
    "lmstudio":  LMStudioTarget,
}

for _scheme, _cls in _PROVIDERS.items():
    TargetManager.register_target(_scheme, _cls)
