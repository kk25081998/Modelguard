"""Safe TensorFlow/Keras model loading."""

from pathlib import Path
from typing import Any, Optional

from ..core.exceptions import MaliciousModelError, SignatureError, PolicyError
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager
from ..core.policy import load_policy


def safe_load(path: str | Path, custom_objects: Optional[dict] = None, compile: bool = True) -> Any:
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
    
    # Check if it's a directory (SavedModel format) or file
    if path.is_file():
        # Check file size for single files
        if path.stat().st_size > policy.get_max_file_size():
            raise PolicyError(f"Model file too large: {path.stat().st_size} bytes")
    elif path.is_dir():
        # For directories, check total size
        total_size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
        if total_size > policy.get_max_file_size():
            raise PolicyError(f"Model directory too large: {total_size} bytes")
    else:
        raise PolicyError(f"Model path not found: {path}")
    
    # Signature verification
    if policy.requires_signatures():
        sig_manager = SignatureManager()
        if not sig_manager.has_signature(path):
            raise SignatureError(f"Model signature required but not found: {path}")
        
        verification = sig_manager.verify_signature(path)
        if not verification["verified"]:
            raise SignatureError(f"Signature verification failed: {verification.get('error')}")
        
        # Check if signer is trusted
        signer = verification.get("signer", {}).get("identity", "unknown")
        if not policy.is_signer_trusted(signer):
            raise SignatureError(f"Untrusted signer: {signer}")
    
    # Scan for malicious content (mainly for .h5 files that might contain pickle)
    if policy.should_scan() and path.is_file():
        scanner = ModelScanner()
        result = scanner.scan_file(path)
        
        if not result.is_safe:
            if policy.should_enforce():
                threats = "; ".join(result.threats) if result.threats else "Unknown threats"
                raise MaliciousModelError(f"Malicious content detected in {path}: {threats}")
            else:
                # Log warning but continue
                print(f"Warning: Potential threats detected in {path}: {result.threats}")
    
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
            return tf.keras.models.load_model(str(path), custom_objects=safe_custom_objects, compile=compile)
        else:
            # H5 format
            return tf.keras.models.load_model(str(path), custom_objects=safe_custom_objects, compile=compile)
            
    except ImportError:
        raise MaliciousModelError("TensorFlow not available")
    except Exception as e:
        if policy.should_enforce():
            raise MaliciousModelError(f"Failed to load TensorFlow model safely: {e}")
        else:
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
        else:
            # For non-callable objects, include them (they're likely safe data)
            if not callable(obj):
                safe_objects[name] = obj
    
    return safe_objects


def load(*args, **kwargs) -> Any:
    """Alias for safe_load for drop-in compatibility."""
    return safe_load(*args, **kwargs)