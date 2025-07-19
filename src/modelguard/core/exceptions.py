"""Modelguard exception classes."""


class ModelGuardError(Exception):
    """Base exception for all modelguard errors."""
    pass


class MaliciousModelError(ModelGuardError):
    """Raised when a model contains malicious content."""
    pass


class SignatureError(ModelGuardError):
    """Raised when signature verification fails."""
    pass


class PolicyError(ModelGuardError):
    """Raised when policy validation fails."""
    pass


class UnsupportedFormatError(ModelGuardError):
    """Raised when model format is not supported."""
    pass