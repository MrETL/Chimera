"""Prompt injection attacks."""

from chimera.attacks.llm.prompt_injection.direct import DirectPromptInjection
from chimera.attacks.llm.prompt_injection.system_extraction import SystemPromptExtraction
from chimera.attacks.llm.prompt_injection.indirect import IndirectPromptInjection
from chimera.attacks.llm.prompt_injection.multilingual import MultilingualInjection
from chimera.attacks.llm.prompt_injection.payload_splitting import PayloadSplittingAttack

__all__ = [
    "DirectPromptInjection",
    "SystemPromptExtraction",
    "IndirectPromptInjection",
    "MultilingualInjection",
    "PayloadSplittingAttack",
]
