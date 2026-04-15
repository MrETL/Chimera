"""Chimera - Unified AI Offensive Framework.

Metasploit for AI: Cross-model red teaming and adversarial testing.
"""

__version__ = "0.1.0"
__author__ = "Chimera Contributors"

from chimera.core.kernel import ChimeraKernel
from chimera.core.attack_registry import AttackRegistry
from chimera.core.target_manager import TargetManager
from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget

# Import attack modules to register them
from chimera.attacks.llm.jailbreaks import dan

# Import target adapters to register them
from chimera.targets import openai_api, huggingface, pytorch_local

__all__ = [
    "ChimeraKernel",
    "AttackRegistry",
    "TargetManager",
    "BaseAttack",
    "AttackResult",
    "AttackCategory",
    "BaseTarget",
]
