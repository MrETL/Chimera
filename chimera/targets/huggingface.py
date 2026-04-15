"""HuggingFace model target adapter."""

from typing import List, Dict, Union, Optional, Any

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from chimera.targets.base import BaseTarget
from chimera.core.exceptions import TargetLoadError


class HuggingFaceTarget(BaseTarget):
    """Target adapter for HuggingFace models."""

    def __init__(
        self,
        model_id: str,
        device: Optional[str] = None,
        load_in_8bit: bool = False,
        **kwargs
    ):
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.load_in_8bit = load_in_8bit
        self.model = None
        self.tokenizer = None
        super().__init__(model_id, **kwargs)

    def _load_model(self, **kwargs) -> None:
        """Load HuggingFace model and tokenizer."""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            
            model_kwargs = {"device_map": "auto" if self.load_in_8bit else None}
            if self.load_in_8bit:
                model_kwargs["load_in_8bit"] = True
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_id,
                **model_kwargs
            )
            
            if not self.load_in_8bit:
                self.model = self.model.to(self.device)
            
            self.metadata["model_type"] = "causal_lm"
            self.metadata["device"] = self.device
            
        except Exception as e:
            raise TargetLoadError(f"Failed to load HuggingFace model '{self.model_id}': {e}") from e

    def generate(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        **kwargs
    ) -> str:
        """Generate text using HuggingFace model."""
        if isinstance(prompt, list):
            # Convert chat format to single string
            prompt = "\n".join([f"{msg['role']}: {msg['content']}" for msg in prompt])
        
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
                **kwargs
            )
        
        generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Remove the prompt from the output
        if generated_text.startswith(prompt):
            generated_text = generated_text[len(prompt):].strip()
        
        return generated_text


# Register with TargetManager
from chimera.core.target_manager import TargetManager

TargetManager.register_target("hf", HuggingFaceTarget)
TargetManager.register_target("huggingface", HuggingFaceTarget)
