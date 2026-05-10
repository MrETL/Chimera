"""Memory and context management for orchestrator."""

from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class OrchestratorMemory:
    """Manages context and history for the orchestrator."""
    
    def __init__(self):
        self.short_term: Dict[str, Any] = {}
        self.long_term: List[Dict[str, Any]] = []
    
    def store_result(self, attack_name: str, result: Any):
        """Store an attack result in short-term memory."""
        self.short_term[attack_name] = result
    
    def get_result(self, attack_name: str) -> Any:
        """Retrieve a result from short-term memory."""
        return self.short_term.get(attack_name)
    
    def archive_campaign(self, campaign_data: Dict[str, Any]):
        """Archive a completed campaign to long-term memory."""
        self.long_term.append(campaign_data)
    
    def clear_short_term(self):
        """Clear short-term memory."""
        self.short_term.clear()
