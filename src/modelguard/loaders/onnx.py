"""Safe ONNX model loading."""

from pathlib import Path
from typing import Any

from ..core.exceptions import MaliciousModelError, PolicyError, SignatureError
from ..core.logging import get_logger
from ..core.policy import load_policy
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager

logger = get_logger("onnx")


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
        msg = f"Model file too large: {path.stat().st_size} bytes"
        raise PolicyError(msg)

    # Signature verification
    if policy.requires_signatures():
        _verify_signature(path, policy)

    # Scan for malicious content
    if policy.should_scan():
        _scan_for_threats(path, policy)

    # Load ONNX model
    try:
        import onnx

        # ONNX models are protobuf-based and generally safe
        # But we still validate the model structure
        model = onnx.load(str(path))

        # Basic validation
        onnx.checker.check_model(model)

        return model

    except ImportError as e:
        raise MaliciousModelError("ONNX not available") from e
    except Exception as e:
        if policy.should_enforce():
            msg = f"Failed to load ONNX model safely: {e}"
            raise MaliciousModelError(msg) from e
        # Re-raise the original exception in non-enforce mode
        raise


def load(*args, **kwargs) -> Any:
    """Alias for safe_load for drop-in compatibility."""
    return safe_load(*args, **kwargs)
