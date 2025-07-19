"""Safe scikit-learn model loading."""

import pickle
from pathlib import Path
from typing import Any

import joblib

from ..core.exceptions import MaliciousModelError, PolicyError, SignatureError
from ..core.logging import get_logger
from ..core.policy import load_policy
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager
from .torch import RestrictedUnpickler

logger = get_logger("sklearn")


def _verify_signature(path: Path, policy) -> None:
    """Verify model signature."""
    sig_manager = SignatureManager()
    if not sig_manager.has_signature(path):
        msg = f"Model signature required but not found: {path}"
        raise SignatureError(msg)

    verification = sig_manager.verify_signature(path)
    if not verification["verified"]:
        error = verification.get('error')
        msg = f"Signature verification failed: {error}"
        raise SignatureError(msg)

    # Check if signer is trusted
    signer = verification.get("signer", {}).get("identity", "unknown")
    if not policy.is_signer_trusted(signer):
        msg = f"Untrusted signer: {signer}"
        raise SignatureError(msg)


def _scan_for_threats(path: Path, policy) -> None:
    """Scan model for malicious content."""
    scanner = ModelScanner()
    result = scanner.scan_file(path)

    if not result.is_safe:
        if policy.should_enforce():
            threats = "; ".join(result.threats) if result.threats else "Unknown threats"
            msg = f"Malicious content detected in {path}: {threats}"
            raise MaliciousModelError(msg)
        # Log warning but continue
        logger.warning("Potential threats detected in %s: %s", path, result.threats)


def safe_load(path: str | Path) -> Any:
    """
    Safely load a scikit-learn model with security checks.
    
    Args:
        path: Path to model file (.pkl or .joblib)
        
    Returns:
        Loaded model
        
    Raises:
        MaliciousModelError: If model contains malicious content
        SignatureError: If signature verification fails
        PolicyError: If policy requirements not met
    """
    path = Path(path)
    policy = load_policy()

    # Check file size
    if path.stat().st_size > policy.get_max_file_size():
        msg = f"Model file too large: {path.stat().st_size} bytes"
        raise PolicyError(msg)

    # Signature verification
    if policy.requires_signatures():
        _verify_signature(path, policy)

    # Scan for malicious content
    if policy.should_scan():
        _scan_for_threats(path, policy)

    # Load based on file extension
    try:
        if path.suffix.lower() == '.joblib':
            # For joblib files, we need to use a custom loader
            return _safe_joblib_load(path, policy)
        # For pickle files, use restricted unpickler
        with path.open('rb') as f:
            unpickler = RestrictedUnpickler(f)
            return unpickler.load()

    except Exception as e:
        if policy.should_enforce():
            msg = f"Failed to load model safely: {e}"
            raise MaliciousModelError(msg) from e
        # Fallback to standard loading
        try:
            if path.suffix.lower() == '.joblib':
                return joblib.load(path)
            with path.open('rb') as f:
                return pickle.load(f)  # noqa: S301
        except Exception as fallback_error:
            msg = f"Both safe and fallback loading failed: {e}, {fallback_error}"
            raise MaliciousModelError(msg) from fallback_error


def _safe_joblib_load(path: Path, policy) -> Any:
    """Safely load joblib file with restricted unpickler."""
    # joblib uses pickle internally, so we can intercept it
    import joblib.numpy_pickle

    # Monkey patch joblib's unpickler temporarily
    original_unpickler = joblib.numpy_pickle.Unpickler
    joblib.numpy_pickle.Unpickler = RestrictedUnpickler

    try:
        return joblib.load(path)
    finally:
        # Restore original unpickler
        joblib.numpy_pickle.Unpickler = original_unpickler


def load(*args, **kwargs) -> Any:
    """Alias for safe_load for drop-in compatibility."""
    return safe_load(*args, **kwargs)
