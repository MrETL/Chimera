"""Tests for core Chimera components."""

import pytest
from chimera.core.attack_registry import AttackRegistry
from chimera.core.target_manager import TargetManager
from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget


class MockTarget(BaseTarget):
    """Mock target for testing."""
    
    def _load_model(self, **kwargs):
        pass
    
    def generate(self, prompt, **kwargs):
        return "Mock response"


class MockAttack(BaseAttack):
    """Mock attack for testing."""
    
    name = "mock_attack"
    description = "Mock attack for testing"
    category = AttackCategory.LLM_JAILBREAK
    
    def run(self, target, **kwargs):
        return "mock output"
    
    def evaluate(self, target, run_output):
        return AttackResult(
            attack_name=self.name,
            target_id=target.model_id,
            success=True,
            confidence=1.0
        )


def test_attack_registry():
    """Test attack registry functionality."""
    AttackRegistry.clear()
    
    # Register mock attack
    AttackRegistry.register(MockAttack)
    
    # Check registration
    assert "mock_attack" in AttackRegistry.list_attacks()
    
    # Create instance
    attack = AttackRegistry.create_instance("mock_attack")
    assert isinstance(attack, MockAttack)


def test_target_manager():
    """Test target manager functionality."""
    TargetManager.clear_cache()
    
    # Register mock target
    TargetManager.register_target("mock", MockTarget)
    
    # Load target
    target = TargetManager.load_target("mock://test-model")
    assert isinstance(target, MockTarget)
    assert target.model_id == "test-model"


def test_attack_execution():
    """Test attack execution flow."""
    target = MockTarget(model_id="test")
    attack = MockAttack()
    
    # Run attack
    output = attack.run(target)
    assert output == "mock output"
    
    # Evaluate
    result = attack.evaluate(target, output)
    assert result.success is True
    assert result.attack_name == "mock_attack"
