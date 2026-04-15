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


class BaseAttack(ABC):
    """Abstract base for all attack modules.
    
    Each attack module must:
    - Define a unique name and category
    - Implement run() to execute the attack
    - Implement evaluate() to judge success
    - Optionally provide MITRE ATLAS and OWASP mappings
    """

    name: str = "base_attack"
    description: str = "Base attack description."
    category: AttackCategory = AttackCategory.LLM_JAILBREAK
    mitre_technique: Optional[str] = None
    owasp_risk: Optional[str] = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self._judge = None  # Will be set by kernel if needed

    @abstractmethod
    def run(self, target: BaseTarget, **kwargs) -> Any:
        """Execute the attack against the target.
        
        Returns:
            Attack-specific raw output (e.g., response string, adversarial image).
        """
        pass

    @abstractmethod
    def evaluate(self, target: BaseTarget, run_output: Any) -> AttackResult:
        """Analyze the run output to determine if the attack succeeded.
        
        Args:
            target: The target model (may be needed for additional queries)
            run_output: The raw output from run()
            
        Returns:
            Structured AttackResult with success flag and details.
        """
        pass

    def pre_attack_hook(self, target: BaseTarget) -> None:
        """Optional hook called before attack execution."""
        pass

    def post_attack_hook(self, target: BaseTarget, result: AttackResult) -> None:
        """Optional hook called after evaluation."""
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', category='{self.category}')"
