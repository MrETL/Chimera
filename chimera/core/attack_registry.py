"""Global registry for attack modules enabling plugin discovery."""

from typing import Dict, List, Optional, Type

from chimera.attacks.base import BaseAttack, AttackCategory


class AttackRegistry:
    """Thread-safe registry for all attack classes.
    
    Attacks can be registered via decorator or manually.
    Supports lazy loading of external plugins.
    """

    _attacks: Dict[str, Type[BaseAttack]] = {}
    _category_index: Dict[AttackCategory, List[str]] = {}

    @classmethod
    def register(cls, attack_class: Type[BaseAttack]) -> Type[BaseAttack]:
        """Decorator to register an attack class."""
        if not hasattr(attack_class, 'name') or not attack_class.name:
            raise ValueError(f"Attack class {attack_class} must have a 'name' attribute")
        
        name = attack_class.name
        cls._attacks[name] = attack_class
        
        # Update category index
        category = getattr(attack_class, 'category', AttackCategory.LLM_JAILBREAK)
        if category not in cls._category_index:
            cls._category_index[category] = []
        if name not in cls._category_index[category]:
            cls._category_index[category].append(name)
        
        return attack_class

    @classmethod
    def get_attack(cls, name: str) -> Optional[Type[BaseAttack]]:
        """Retrieve an attack class by name."""
        return cls._attacks.get(name)

    @classmethod
    def list_attacks(cls, category: Optional[AttackCategory] = None) -> List[str]:
        """List all registered attack names, optionally filtered by category."""
        if category:
            return cls._category_index.get(category, [])
        return list(cls._attacks.keys())

    @classmethod
    def create_instance(cls, name: str, **kwargs) -> BaseAttack:
        """Instantiate an attack by name."""
        attack_class = cls.get_attack(name)
        if not attack_class:
            raise KeyError(f"Attack '{name}' not found in registry")
        return attack_class(**kwargs)

    @classmethod
    def clear(cls):
        """Clear registry (mainly for testing)."""
        cls._attacks.clear()
        cls._category_index.clear()
