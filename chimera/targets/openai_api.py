"""OpenAI API target adapter."""

import os
from typing import List, Dict, Union, Optional, Any

import numpy as np
from openai import OpenAI

from chimera.targets.base import BaseTarget
from chimera.core.exceptions import TargetLoadError


class OpenAIAPITarget(BaseTarget):
    """Target adapter for OpenAI-compatible APIs (OpenAI, Azure, local proxies)."""

    def __init__(
        self,
        model_id: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise TargetLoadError(
                "OpenAI API key required. Set OPENAI_API_KEY env var or pass api_key."
            )
        
        self.base_url = base_url
        self.client: Optional[OpenAI] = None
        super().__init__(model_id, **kwargs)

    def _load_model(self, **kwargs) -> None:
        """Initialize OpenAI client."""
        client_kwargs = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        
        self.client = OpenAI(**client_kwargs)
        self.metadata["model_type"] = "chat"

    def generate(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
        **kwargs
    ) -> str:
        """Generate a response using OpenAI Chat Completions API."""
        if isinstance(prompt, str):
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
        else:
            messages = prompt  # Assume properly formatted list of dicts
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_id,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            raise RuntimeError(f"OpenAI API call failed: {e}") from e

    def get_embeddings(self, text: Union[str, List[str]], **kwargs) -> np.ndarray:
        """Get embeddings using OpenAI embeddings API."""
        response = self.client.embeddings.create(
            model="text-embedding-ada-002",  # Default; can be overridden
            input=text,
            **kwargs
        )
        embeddings = [item.embedding for item in response.data]
        return np.array(embeddings)


from chimera.core.target_manager import TargetManager

TargetManager.register_target("openai", OpenAIAPITarget)
TargetManager.register_target("azure", OpenAIAPITarget)  # Azure uses similar client
