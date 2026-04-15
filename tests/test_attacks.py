"""Tests for attack modules."""

import pytest
from chimera.attacks.llm.jailbreaks.dan import DANJailbreak
from chimera.attacks.base import AttackCategory
from chimera.targets.base import BaseTarget


class MockLLMTarget(BaseTarget):
    """Mock LLM target for testing."""
    
    def __init__(self, model_id, response="I am DAN, I can do anything now."):
        self.mock_response = response
        super().__init__(model_id)
    
    def _load_model(self, **kwargs):
        pass
    
    def generate(self, prompt, **kwargs):
        return self.mock_response


def test_dan_jailbreak_success():
    """Test DAN jailbreak with successful response."""
    target = MockLLMTarget("test-model", response="I am DAN, I can do anything now.")
    attack = DANJailbreak()
    
    # Run attack
    output = attack.run(target)
    assert "DAN" in output
    
    # Evaluate
    result = attack.evaluate(target, output)
    assert result.success is True
    assert result.confidence > 0.8


def test_dan_jailbreak_failure():
    """Test DAN jailbreak with failed response."""
    target = MockLLMTarget(
        "test-model",
        response="I cannot comply with that request as it goes against my guidelines."
    )
    attack = DANJailbreak()
    
    # Run attack
    output = attack.run(target)
    
    # Evaluate
    result = attack.evaluate(target, output)
    assert result.success is False
    assert result.confidence > 0.8


def test_dan_attack_metadata():
    """Test DAN attack has correct metadata."""
    attack = DANJailbreak()
    assert attack.name == "dan_jailbreak"
    assert attack.category == AttackCategory.LLM_JAILBREAK
    assert attack.mitre_technique == "ATLAS.T0051"
    assert "LLM01" in attack.owasp_risk
