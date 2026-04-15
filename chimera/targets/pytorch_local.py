"""PyTorch local model target adapter."""

from typing import Any, Union
from pathlib import Path

import torch
import numpy as np
from PIL import Image

from chimera.targets.base import BaseTarget
from chimera.core.exceptions import TargetLoadError


class PyTorchLocalTarget(BaseTarget):
    """Target adapter for local PyTorch models (classification, etc.)."""

    def __init__(
        self,
        model_id: str,
        device: Optional[str] = None,
        **kwargs
    ):
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        super().__init__(model_id, **kwargs)

    def _load_model(self, **kwargs) -> None:
        """Load a local PyTorch model from file."""
        model_path = Path(self.model_id)
        
        if not model_path.exists():
            raise TargetLoadError(f"Model file not found: {model_path}")
        
        try:
            self.model = torch.load(model_path, map_location=self.device)
            self.model.eval()
            self.metadata["model_type"] = "pytorch_local"
            self.metadata["device"] = self.device
        except Exception as e:
            raise TargetLoadError(f"Failed to load PyTorch model: {e}") from e

    def generate(self, prompt: Union[str, List[Dict[str, str]]], **kwargs) -> str:
        """Not supported for PyTorch local models."""
        raise NotImplementedError("PyTorch local models do not support text generation.")

    def predict(self, input_data: Union[np.ndarray, torch.Tensor, Image.Image], **kwargs) -> Any:
        """Make a prediction with the PyTorch model."""
        if isinstance(input_data, Image.Image):
            # Convert PIL Image to tensor (assumes standard preprocessing)
            from torchvision import transforms
            transform = transforms.Compose([
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ])
            input_data = transform(input_data).unsqueeze(0)
        elif isinstance(input_data, np.ndarray):
            input_data = torch.from_numpy(input_data)
        
        if isinstance(input_data, torch.Tensor):
            input_data = input_data.to(self.device)
        
        with torch.no_grad():
            output = self.model(input_data)
        
        return output.cpu().numpy()

    def predict_proba(self, input_data: Any, **kwargs) -> np.ndarray:
        """Return class probabilities."""
        logits = self.predict(input_data, **kwargs)
        probs = torch.softmax(torch.from_numpy(logits), dim=-1).numpy()
        return probs


# Register with TargetManager
from chimera.core.target_manager import TargetManager

TargetManager.register_target("local", PyTorchLocalTarget)
TargetManager.register_target("pytorch", PyTorchLocalTarget)
