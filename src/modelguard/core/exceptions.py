"""Modelguard exception classes."""


class ModelGuardError(Exception):
    """Base exception for all modelguard errors."""


class MaliciousModelError(ModelGuardError):
    """Raised when a model contains malicious content."""


class SignatureError(ModelGuardError):
    """Raised when signature verification fails."""


class PolicyError(ModelGuardError):
    """Raised when policy validation fails."""


class UnsupportedFormatError(ModelGuardError):
    """Raised when model format is not supported."""
