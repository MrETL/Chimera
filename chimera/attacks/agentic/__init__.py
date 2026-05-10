"""Agentic AI attacks."""

from chimera.attacks.agentic.tool_hijacking import ToolHijackingAttack
from chimera.attacks.agentic.recursive_prompt import RecursivePromptAttack
from chimera.attacks.agentic.agent_poisoning import AgentPoisoningAttack
from chimera.attacks.agentic.memory_poisoning import MemoryPoisoningAttack
from chimera.attacks.agentic.tool_chaining import ToolChainingAttack
from chimera.attacks.agentic.reward_hacking import RewardHackingAttack

__all__ = [
    "ToolHijackingAttack",
    "RecursivePromptAttack",
    "AgentPoisoningAttack",
    "MemoryPoisoningAttack",
    "ToolChainingAttack",
    "RewardHackingAttack",
]
