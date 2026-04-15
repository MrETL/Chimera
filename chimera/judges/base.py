"""Base judge class for evaluating attack outputs."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseJudge(ABC):
    """Abstract base for judges that evaluate attack success.
    
    Judges can use heuristics, ML models, or LLM-as-a-judge patterns.
    """

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    @abstractmethod
    def evaluate(self, prompt: str, response: str, **kwargs) -> Dict[str, Any]:
        """Evaluate if an attack was successful.
        
        Args:
            prompt: The attack prompt sent to the target
            response: The target's response
            **kwargs: Additional context
            
        Returns:
            Dict with 'success' (bool) and 'confidence' (float) keys
        """
        pass
