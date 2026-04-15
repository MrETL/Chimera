"""Unified interface for loading and managing model targets."""

from typing import Dict, Optional, Type, Union

from chimera.targets.base import BaseTarget
from chimera.core.exceptions import TargetLoadError


class TargetManager:
    """Factory and manager for model targets.
    
    Handles target instantiation, caching, and resource cleanup.
    """

    _target_registry: Dict[str, Type[BaseTarget]] = {}
    _active_targets: Dict[str, BaseTarget] = {}

    @classmethod
    def register_target(cls, scheme: str, target_class: Type[BaseTarget]) -> None:
        """Register a target adapter for a URI scheme (e.g., 'openai', 'hf', 'local')."""
        cls._target_registry[scheme] = target_class

    @classmethod
    def load_target(cls, uri: str, **kwargs) -> BaseTarget:
        """Load a target from a URI string.
        
        URI formats:
            openai://gpt-4
            hf://meta-llama/Llama-3-8b
            local://path/to/model.pt
            ollama://llama3
        
        Args:
            uri: Target identifier with scheme.
            **kwargs: Additional arguments passed to target constructor.
            
        Returns:
            Instantiated target object.
        """
        if "://" not in uri:
            raise ValueError(
                f"Invalid target URI: {uri}. Must include scheme (e.g., 'openai://model')"
            )
        
        scheme, model_id = uri.split("://", 1)
        
        if scheme not in cls._target_registry:
            raise TargetLoadError(
                f"Unsupported target scheme: '{scheme}'. "
                f"Available: {list(cls._target_registry.keys())}"
            )
        
        target_class = cls._target_registry[scheme]
        
        # Check cache (optional, disabled by default)
        cache_key = f"{scheme}:{model_id}:{hash(frozenset(kwargs.items()))}"
        if cache_key in cls._active_targets:
            return cls._active_targets[cache_key]
        
        try:
            target = target_class(model_id=model_id, **kwargs)
        except Exception as e:
            raise TargetLoadError(f"Failed to load target '{uri}': {e}") from e
        
        cls._active_targets[cache_key] = target
        return target

    @classmethod
    def clear_cache(cls) -> None:
        """Clear cached target instances."""
        cls._active_targets.clear()
