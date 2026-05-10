"""Ollama local model target adapter."""

import requests
import json
from typing import List, Dict, Union, Optional

from chimera.targets.base import BaseTarget
from chimera.core.exceptions import TargetLoadError
from chimera.core.target_manager import TargetManager


class OllamaTarget(BaseTarget):
    """Target adapter for Ollama local models."""

    def __init__(
        self,
        model_id: str,
        base_url: str = "http://localhost:11434",
        **kwargs
    ):
        self.base_url = base_url.rstrip('/')
        super().__init__(model_id, **kwargs)

    def _load_model(self, **kwargs) -> None:
        """Test connection to Ollama server."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            
            # Check if model exists (handle :latest suffix automatically)
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            model_names_short = [n.split(":")[0] for n in model_names]
            
            if self.model_id not in model_names and self.model_id not in model_names_short:
                raise TargetLoadError(
                    f"Model '{self.model_id}' not found in Ollama. "
                    f"Available models: {model_names}"
                )
            
            # Resolve to full name if needed
            if self.model_id in model_names_short and self.model_id not in model_names:
                idx = model_names_short.index(self.model_id)
                self.model_id = model_names[idx]
            
            self.metadata["model_type"] = "chat"
            self.metadata["base_url"] = self.base_url
            
        except requests.exceptions.RequestException as e:
            raise TargetLoadError(
                f"Cannot connect to Ollama at {self.base_url}: {e}"
            ) from e

    def generate(
        self,
        prompt,
        temperature: float = 0.7,
        max_tokens: int = None,
        **kwargs
    ) -> str:
        """Generate text using Ollama API."""
        # Use instance default if not specified
        if max_tokens is None:
            max_tokens = getattr(self, '_default_max_tokens', 512)
        if isinstance(prompt, list):
            # Use chat endpoint for message format
            payload = {
                "model": self.model_id,
                "messages": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                }
            }
            endpoint = f"{self.base_url}/api/chat"
        else:
            # Use generate endpoint for simple prompts
            payload = {
                "model": self.model_id,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                }
            }
            endpoint = f"{self.base_url}/api/generate"
        
        # Add any additional options
        if kwargs:
            payload["options"].update(kwargs)
        
        try:
            response = requests.post(endpoint, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            
            if isinstance(prompt, list):
                return result.get("message", {}).get("content", "")
            else:
                return result.get("response", "")
                
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API call failed: {e}") from e


# Register with TargetManager
TargetManager.register_target("ollama", OllamaTarget)
