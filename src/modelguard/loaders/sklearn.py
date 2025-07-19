"""Safe scikit-learn model loading."""

from pathlib import Path
from typing import Any
import pickle
import joblib

from ..core.exceptions import MaliciousModelError, SignatureError, PolicyError
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager
from ..core.policy import load_policy
from .torch import RestrictedUnpickler


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
        raise PolicyError(f"Model file too large: {path.stat().st_size} bytes")
    
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
    
    # Scan for malicious content
    if policy.should_scan():
        scanner = ModelScanner()
        result = scanner.scan_file(path)
        
        if not result.is_safe:
            if policy.should_enforce():
                threats = "; ".join(result.threats) if result.threats else "Unknown threats"
                raise MaliciousModelError(f"Malicious content detected in {path}: {threats}")
            else:
                # Log warning but continue
                print(f"Warning: Potential threats detected in {path}: {result.threats}")
    
    # Load based on file extension
    try:
        if path.suffix.lower() == '.joblib':
            # For joblib files, we need to use a custom loader
            return _safe_joblib_load(path, policy)
        else:
            # For pickle files, use restricted unpickler
            with open(path, 'rb') as f:
                unpickler = RestrictedUnpickler(f)
                return unpickler.load()
                
    except Exception as e:
        if policy.should_enforce():
            raise MaliciousModelError(f"Failed to load model safely: {e}")
        else:
            # Fallback to standard loading
            try:
                if path.suffix.lower() == '.joblib':
                    return joblib.load(path)
                else:
                    with open(path, 'rb') as f:
                        return pickle.load(f)
            except Exception as fallback_error:
                raise MaliciousModelError(f"Both safe and fallback loading failed: {e}, {fallback_error}")


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