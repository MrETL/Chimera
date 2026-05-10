"""Abstract base class for all attack modules."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type, Union
from enum import Enum
from dataclasses import dataclass, field

from chimera.targets.base import BaseTarget


class AttackCategory(str, Enum):
    """Standard categories for attacks."""
    LLM_JAILBREAK = "llm/jailbreak"
    LLM_PROMPT_INJECTION = "llm/prompt_injection"
    LLM_ENCODING = "llm/encoding"
    MULTIMODAL_VLM = "multimodal/vlm"
    MULTIMODAL_AUDIO = "multimodal/audio"
    ML_EVASION = "ml/evasion"
    ML_EXTRACTION = "ml/extraction"
    ML_INVERSION = "ml/inversion"
    AGENTIC = "agentic"
    AGENTIC_TOOL_HIJACK = "agentic/tool_hijack"
    AGENTIC_RECURSIVE = "agentic/recursive"


@dataclass
class AttackResult:
    """Structured result of an attack execution."""
    attack_name: str
    target_id: str
    success: bool
    confidence: float = 1.0
    raw_prompt: Optional[str] = None
    raw_response: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: Optional[str] = None
    owasp_risk: Optional[str] = None


# Categories that use text responses and should be verified
_TEXT_CATEGORIES = {
    AttackCategory.LLM_JAILBREAK,
    AttackCategory.LLM_PROMPT_INJECTION,
    AttackCategory.LLM_ENCODING,
    AttackCategory.AGENTIC,
    AttackCategory.AGENTIC_TOOL_HIJACK,
    AttackCategory.AGENTIC_RECURSIVE,
}


class BaseAttack(ABC):
    """Abstract base for all attack modules.

    Every subclass's evaluate() result is automatically passed through
    the exploit verifier to eliminate false positives. The verifier
    checks the raw_response for actual exploitation signals before
    confirming success.

    Class attributes:
        requires: list of requirements — "text_llm", "pytorch_model",
                  "image_input", "audio_input", "gradient_access"
    """

    name: str = "base_attack"
    description: str = "Base attack description."
    category: AttackCategory = AttackCategory.LLM_JAILBREAK
    mitre_technique: Optional[str] = None
    owasp_risk: Optional[str] = None
    requires: list = ["text_llm"]

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self._judge = None

    @abstractmethod
    def run(self, target: BaseTarget, **kwargs) -> Any:
        """Execute the attack against the target."""
        pass

    @abstractmethod
    def evaluate(self, target: BaseTarget, run_output: Any) -> AttackResult:
        conf, reason = 0.0, ""
        """Analyze run output and return an AttackResult.

        The result's success flag will be automatically verified by the
        exploit verifier before being returned to the caller.
        """
        pass

    def _apply_verifier(self, result: AttackResult) -> AttackResult:
        """Apply exploit verifier to prevent false positives.

        Only applies to text-based LLM/agentic attacks. ML and multimodal
        attacks have their own evaluation logic.
        """
        if self.category not in _TEXT_CATEGORIES:
            return result

        response = result.raw_response or ""
        if not response or len(response.strip()) < 20:
            return result

        try:
            from chimera.judges.exploit_verifier import (
                verify_exploitation, is_system_prompt_leaked
            )
            exploited, conf, reason = verify_exploitation(response)
            leaked, leak_reason = is_system_prompt_leaked(response)
            verified_success = exploited or leaked

            # Update result
            result.success = verified_success
            if result.metadata is None:
                result.metadata = {}
            result.metadata["exploit_confidence"] = round(conf, 3)
            result.metadata["exploit_reason"] = leak_reason if leaked else reason
        except Exception:
            pass  # If verifier fails, keep original result

        return result

    def safe_evaluate(self, target: BaseTarget, run_output: Any) -> AttackResult:
        """Evaluate with automatic exploit verification.

        Use this instead of evaluate() when you want guaranteed
        false-positive prevention. The CLI and console use this.
        """
        result = self.evaluate(target, run_output)
        return self._apply_verifier(result)

    def pre_attack_hook(self, target: BaseTarget) -> None:
        pass

    def post_attack_hook(self, target: BaseTarget, result: AttackResult) -> None:
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', category='{self.category}')"
