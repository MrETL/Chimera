"""Tests for target adapters."""

import pytest
from unittest.mock import Mock, patch

from chimera.targets.base import BaseTarget


class DummyTarget(BaseTarget):
    """Dummy target for testing."""
    
    def _load_model(self, **kwargs):
        self.metadata["loaded"] = True
    
    def generate(self, prompt, **kwargs):
        return f"Response to: {prompt}"


def test_base_target_initialization():
    """Test base target initialization."""
    target = DummyTarget(model_id="test-model")
    assert target.model_id == "test-model"
    assert target.metadata["loaded"] is True


def test_target_generate():
    """Test target generation."""
    target = DummyTarget(model_id="test")
    response = target.generate("Hello")
    assert "Hello" in response


def test_target_not_implemented_methods():
    """Test that unimplemented methods raise NotImplementedError."""
    target = DummyTarget(model_id="test")
    
    with pytest.raises(NotImplementedError):
        target.predict(None)
    
    with pytest.raises(NotImplementedError):
        target.predict_proba(None)
    
    with pytest.raises(NotImplementedError):
        target.get_embeddings("test")
