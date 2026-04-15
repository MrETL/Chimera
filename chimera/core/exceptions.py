"""Custom exceptions for Chimera framework."""


class ChimeraError(Exception):
    """Base exception for all Chimera errors."""
    pass


class TargetLoadError(ChimeraError):
    """Raised when a target cannot be loaded."""
    pass


class AttackExecutionError(ChimeraError):
    """Raised when an attack fails during execution."""
    pass


class ConfigurationError(ChimeraError):
    """Raised for invalid configuration."""
    pass
