"""Chimera - Autonomous AI Offensive Framework for Enterprise Red Teaming."""

__version__ = "1.0.0"
__author__ = "Chimera Contributors"

# Minimal imports only — heavy modules (torch, transformers, etc.)
# are loaded lazily when actually used.
from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.core.attack_registry import AttackRegistry

__all__ = ["BaseAttack", "AttackResult", "AttackCategory", "AttackRegistry"]
