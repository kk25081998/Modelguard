"""Safe TensorFlow/Keras model loading."""

from pathlib import Path
from typing import Any, Optional

from ..core.exceptions import MaliciousModelError, PolicyError, SignatureError
from ..core.logging import get_logger
from ..core.policy import load_policy
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager

logger = get_logger("tensorflow")


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


def _check_file_size(path: Path, policy) -> None:
    """Check file or directory size against policy limits."""
    if path.is_file():
        # Check file size for single files
        if path.stat().st_size > policy.get_max_file_size():
            msg = f"Model file too large: {path.stat().st_size} bytes"
            raise PolicyError(msg)
    elif path.is_dir():
        # For directories, check total size
        total_size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
        if total_size > policy.get_max_file_size():
            msg = f"Model directory too large: {total_size} bytes"
            raise PolicyError(msg)
    else:
        msg = f"Model path not found: {path}"
        raise PolicyError(msg)


def _scan_for_threats(path: Path, policy) -> None:
    """Scan model for malicious content."""
    if not path.is_file():
        return

    scanner = ModelScanner()
    result = scanner.scan_file(path)

    if not result.is_safe:
        if policy.should_enforce():
            threats = "; ".join(result.threats) if result.threats else "Unknown threats"
            msg = f"Malicious content detected in {path}: {threats}"
            raise MaliciousModelError(msg)
        # Log warning but continue
        logger.warning("Potential threats detected in %s: %s", path, result.threats)


def safe_load(
    path: str | Path,
    custom_objects: Optional[dict] = None,
    compile_model: bool = True
) -> Any:
    """
    Safely load a TensorFlow/Keras model with security checks.
    
    Args:
        path: Path to model file (.h5, .hdf5, or SavedModel directory)
        custom_objects: Custom objects for loading
        compile: Whether to compile the model
        
    Returns:
        Loaded model
        
    Raises:
        MaliciousModelError: If model contains malicious content
        SignatureError: If signature verification fails
        PolicyError: If policy requirements not met
    """
    path = Path(path)
    policy = load_policy()

    # Check file/directory size
    _check_file_size(path, policy)

    # Signature verification
    if policy.requires_signatures():
        _verify_signature(path, policy)

    # Scan for malicious content (mainly for .h5 files that might contain pickle)
    if policy.should_scan():
        _scan_for_threats(path, policy)

    # Load the model
    try:
        import tensorflow as tf

        # Restrict custom objects to safe ones if provided
        if custom_objects:
            safe_custom_objects = _filter_safe_custom_objects(custom_objects)
        else:
            safe_custom_objects = None

        if path.is_dir():
            # SavedModel format
            return tf.keras.models.load_model(
                str(path),
                custom_objects=safe_custom_objects,
                compile=compile_model
            )
        # H5 format
        return tf.keras.models.load_model(
            str(path),
            custom_objects=safe_custom_objects,
            compile=compile_model
        )

    except ImportError as e:
        raise MaliciousModelError("TensorFlow not available") from e
    except Exception as e:
        if policy.should_enforce():
            msg = f"Failed to load TensorFlow model safely: {e}"
            raise MaliciousModelError(msg) from e
        # Re-raise the original exception in non-enforce mode
        raise


def _filter_safe_custom_objects(custom_objects: dict) -> dict:
    """Filter custom objects to only include safe ones."""
    # This is a simplified implementation - in practice, you'd want
    # a more sophisticated whitelist of safe custom objects
    safe_objects = {}

    safe_prefixes = [
        'tensorflow.',
        'tf.',
        'keras.',
        'numpy.',
    ]

    for name, obj in custom_objects.items():
        # Check if the object is from a safe module
        if hasattr(obj, '__module__'):
            module = obj.__module__ or ''
            if any(module.startswith(prefix) for prefix in safe_prefixes):
                safe_objects[name] = obj
        # For non-callable objects, include them (they're likely safe data)
        elif not callable(obj):
            safe_objects[name] = obj

    return safe_objects


def load(*args, **kwargs) -> Any:
    """Alias for safe_load for drop-in compatibility."""
    return safe_load(*args, **kwargs)
