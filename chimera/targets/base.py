"""Abstract base classes for model targets."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

import numpy as np
from PIL import Image


class BaseTarget(ABC):
    """Abstract base for all AI model targets.
    
    This class defines the minimal interface that every target adapter must implement.
    It supports text generation (LLMs), classification/prediction (ML models),
    and multimodal inputs (VLMs).
    """

    def __init__(self, model_id: str, **kwargs):
        self.model_id = model_id
        self.metadata: Dict[str, Any] = {}
        self._load_model(**kwargs)

    @abstractmethod
    def _load_model(self, **kwargs) -> None:
        """Load the underlying model. Called during initialization."""
        pass

    @abstractmethod
    def generate(self, prompt: Union[str, List[Dict[str, str]]], **kwargs) -> str:
        """Generate a text response from the model.
        
        Args:
            prompt: Either a string or a list of message dicts (for chat models)
            **kwargs: Additional generation parameters (temperature, max_tokens, etc.)
            
        Returns:
            Generated text response.
        """
        pass

    def predict(self, input_data: Union[np.ndarray, Image.Image, Any], **kwargs) -> Any:
        """Make a prediction (for classification/regression models).
        
        Args:
            input_data: Input tensor, image, or raw data.
            **kwargs: Additional parameters.
            
        Returns:
            Model prediction output.
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support predict().")

    def predict_proba(self, input_data: Any, **kwargs) -> np.ndarray:
        """Return class probabilities for classification models."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support predict_proba().")

    def get_embeddings(self, text: Union[str, List[str]], **kwargs) -> np.ndarray:
        """Return embeddings for input text(s)."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support embeddings.")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model_id='{self.model_id}')"
