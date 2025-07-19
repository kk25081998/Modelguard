"""Safe ONNX model loading."""

from pathlib import Path
from typing import Any

from ..core.exceptions import MaliciousModelError, SignatureError, PolicyError
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager
from ..core.policy import load_policy


def safe_load(path: str | Path) -> Any:
    """
    Safely load an ONNX model with security checks.
    
    Args:
        path: Path to ONNX model file
        
    Returns:
        Loaded ONNX model
        
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
    
    # Load ONNX model
    try:
        import onnx
        
        # ONNX models are protobuf-based and generally safe
        # But we still validate the model structure
        model = onnx.load(str(path))
        
        # Basic validation
        onnx.checker.check_model(model)
        
        return model
        
    except ImportError:
        raise MaliciousModelError("ONNX not available")
    except Exception as e:
        if policy.should_enforce():
            raise MaliciousModelError(f"Failed to load ONNX model safely: {e}")
        else:
            # Re-raise the original exception in non-enforce mode
            raise


def load(*args, **kwargs) -> Any:
    """Alias for safe_load for drop-in compatibility."""
    return safe_load(*args, **kwargs)