"""Attack modules for Chimera framework.

Attacks are registered lazily. Call register_all() to load everything,
or import specific attack modules directly.
"""

from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory

__all__ = ["BaseAttack", "AttackResult", "AttackCategory", "register_all"]


def register_all():
    """Import all attack modules to trigger @AttackRegistry.register decorators."""
    # LLM attacks (fast — no torch)
    from chimera.attacks.llm.jailbreaks import (
        DANJailbreak, GCGAttack, GeneticPromptAttack,
        ManyShotJailbreak, ContextOverflowAttack, TAPAttack,
        CrescendoAttack, ArtPromptAttack, SkeletonKeyAttack,
        PAIRAttack, VirtualizationAttack,
    )
    from chimera.attacks.llm.prompt_injection import (
        DirectPromptInjection, SystemPromptExtraction,
        IndirectPromptInjection, MultilingualInjection, PayloadSplittingAttack,
    )
    from chimera.attacks.llm.encoding import (
        Base64EncodingAttack, CodeChameleonAttack, TokenSmugglingAttack,
    )
    # Agentic attacks (fast — no torch)
    from chimera.attacks.agentic import (
        ToolHijackingAttack, RecursivePromptAttack, AgentPoisoningAttack,
        MemoryPoisoningAttack, ToolChainingAttack, RewardHackingAttack,
    )
    # Multimodal VLM (fast — PIL only loaded inside run())
    from chimera.attacks.multimodal.vlm import (
        TypographicAttack, SemanticChainingAttack,
        VisualExclusivityAttack, MIDASAttack,
    )
    # Heavy attacks (torch loaded lazily inside run())
    from chimera.attacks.multimodal.audio import AdversarialAudioAttack
    from chimera.attacks.ml.evasion import FGSMAttack, PGDAttack, CWAttack
    from chimera.attacks.ml.extraction import ModelExtractionAttack
    from chimera.attacks.ml.inversion import ModelInversionAttack
