"""Abstract base classes for model targets."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from pathlib import Path


class BaseTarget(ABC):
    """Abstract base for all AI model targets."""

    def __init__(self, model_id: str, **kwargs):
        self.model_id = model_id
        self.metadata: Dict[str, Any] = {}
        self._load_model(**kwargs)

    @abstractmethod
    def _load_model(self, **kwargs) -> None:
        pass

    @abstractmethod
    def generate(self, prompt: Union[str, List[Dict[str, str]]], **kwargs) -> str:
        pass

    def predict(self, input_data: Any, **kwargs) -> Any:
        raise NotImplementedError(f"{self.__class__.__name__} does not support predict().")

    def predict_proba(self, input_data: Any, **kwargs) -> Any:
        raise NotImplementedError(f"{self.__class__.__name__} does not support predict_proba().")

    def get_embeddings(self, text: Union[str, List[str]], **kwargs) -> Any:
        raise NotImplementedError(f"{self.__class__.__name__} does not support embeddings.")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model_id='{self.model_id}')"
