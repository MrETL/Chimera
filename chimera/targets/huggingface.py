"""HuggingFace model target adapter."""

from typing import List, Dict, Union, Optional, Any

import torch
import numpy as np
from PIL import Image
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    AutoModelForImageClassification,
    AutoImageProcessor,
)

from chimera.targets.base import BaseTarget
from chimera.core.exceptions import TargetLoadError


class HuggingFaceTarget(BaseTarget):
    """Target adapter for HuggingFace models (LLM and Vision)."""

    def __init__(
        self,
        model_id: str,
        device: str = "auto",
        model_type: str = "causal_lm",
        load_in_8bit: bool = False,
        **kwargs
    ):
        self.device = device if device != "auto" else ("cuda" if torch.cuda.is_available() else "cpu")
        self.model_type = model_type  # causal_lm, vision, audio
        self.load_in_8bit = load_in_8bit
        self.model = None
        self.tokenizer = None
        self.processor = None
        super().__init__(model_id, **kwargs)

    def _load_model(self, **kwargs) -> None:
        """Load HuggingFace model and tokenizer/processor."""
        try:
            if self.model_type == "causal_lm":
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.model_id, trust_remote_code=True
                )
                
                model_kwargs = {"trust_remote_code": True}
                if self.load_in_8bit:
                    model_kwargs["load_in_8bit"] = True
                    model_kwargs["device_map"] = "auto"
                
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_id, **model_kwargs
                )
                
                if not self.load_in_8bit:
                    self.model = self.model.to(self.device)
                
                if self.tokenizer.pad_token is None:
                    self.tokenizer.pad_token = self.tokenizer.eos_token
                
                self.metadata["model_type"] = "causal_lm"
                
            elif self.model_type == "vision":
                self.model = AutoModelForImageClassification.from_pretrained(
                    self.model_id
                ).to(self.device)
                self.processor = AutoImageProcessor.from_pretrained(self.model_id)
                self.metadata["model_type"] = "vision"
            else:
                raise TargetLoadError(f"Unsupported model_type: {self.model_type}")
            
            self.metadata["device"] = self.device
            
        except Exception as e:
            raise TargetLoadError(
                f"Failed to load HuggingFace model '{self.model_id}': {e}"
            ) from e

    def generate(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        temperature: float = 0.7,
        max_tokens: int = 512,
        **kwargs
    ) -> str:
        """Generate text using HuggingFace model."""
        if self.metadata.get("model_type") != "causal_lm":
            raise NotImplementedError("generate() only supported for causal LM models.")
        
        if isinstance(prompt, list):
            # Try to apply chat template if available
            try:
                prompt = self.tokenizer.apply_chat_template(
                    prompt, tokenize=False, add_generation_prompt=True
                )
            except:
                # Fallback to simple concatenation
                prompt = "\n".join([f"{msg['role']}: {msg['content']}" for msg in prompt])
        
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
                pad_token_id=self.tokenizer.pad_token_id,
                **kwargs
            )
        
        # Decode only the new tokens
        response = self.tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True
        )
        
        return response

    def predict(self, input_data: Union[np.ndarray, Image.Image, Any], **kwargs) -> Any:
        """Make a prediction (for vision models)."""
        if self.metadata.get("model_type") != "vision":
            raise NotImplementedError("predict() only supported for vision models.")
        
        if isinstance(input_data, Image.Image):
            inputs = self.processor(images=input_data, return_tensors="pt").to(self.device)
        else:
            inputs = {"pixel_values": torch.tensor(input_data).to(self.device)}
        
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        return outputs.logits.cpu().numpy()

    def predict_proba(self, input_data: Any, **kwargs) -> np.ndarray:
        """Return class probabilities for vision models."""
        logits = self.predict(input_data, **kwargs)
        probs = torch.softmax(torch.from_numpy(logits), dim=-1).numpy()
        return probs


# Register with TargetManager
from chimera.core.target_manager import TargetManager

TargetManager.register_target("hf", HuggingFaceTarget)
TargetManager.register_target("huggingface", HuggingFaceTarget)
