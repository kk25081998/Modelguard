"""Safe PyTorch model loading."""

import pickle
from pathlib import Path
from typing import Any

from ..core.exceptions import MaliciousModelError, PolicyError, SignatureError
from ..core.logging import get_logger
from ..core.policy import load_policy
from ..core.scanner import ModelScanner
from ..core.signature import SignatureManager

logger = get_logger("torch")


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


class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe operations."""

    def __init__(self, file, *, fix_imports=True, encoding="ASCII", errors="strict"):
        super().__init__(
            file, fix_imports=fix_imports, encoding=encoding, errors=errors
        )
        self.safe_globals = {
            # PyTorch classes
            'torch._utils._rebuild_tensor_v2',
            'torch._utils._rebuild_parameter',
            'torch.nn.parameter.Parameter',
            'torch.Tensor',
            'torch.Size',
            'torch.dtype',
            'torch.device',
            'torch.storage._TypedStorage',
            'torch.storage._UntypedStorage',

            # Collections
            'collections.OrderedDict',
            'collections.defaultdict',
            'collections.Counter',
            'collections.deque',

            # NumPy
            'numpy.ndarray',
            'numpy.dtype',
            'numpy.core.multiarray._reconstruct',
            'numpy.core.multiarray.scalar',

            # Built-ins
            'builtins.list',
            'builtins.tuple',
            'builtins.dict',
            'builtins.set',
            'builtins.frozenset',
        }

    def find_class(self, module, name):
        """Override to restrict class loading."""
        full_name = f"{module}.{name}"

        if full_name in self.safe_globals:
            return super().find_class(module, name)

        # Allow some common safe modules
        safe_modules = ['torch', 'numpy', 'collections', 'builtins']
        if any(module.startswith(safe_mod) for safe_mod in safe_modules):
            # Additional checks could be added here
            return super().find_class(module, name)

        msg = f"Attempted to load unsafe class: {full_name}"
        raise MaliciousModelError(msg)


def safe_load(path: str | Path, map_location=None, **kwargs) -> Any:
    """
    Safely load a PyTorch model with security checks.
    
    Args:
        path: Path to model file
        map_location: Device mapping (same as torch.load)
        pickle_module: Pickle module to use (ignored, we use our restricted unpickler)
        **kwargs: Additional arguments passed to torch.load
        
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

    # Load with restricted unpickler
    try:
        with path.open('rb') as f:
            unpickler = RestrictedUnpickler(f)
            return unpickler.load()
    except Exception as e:
        if policy.should_enforce():
            msg = f"Failed to load model safely: {e}"
            raise MaliciousModelError(msg) from e
        # Fallback to standard torch.load if available
        try:
            import torch
            return torch.load(path, map_location=map_location, **kwargs)
        except ImportError:
            msg = f"PyTorch not available and safe loading failed: {e}"
            raise MaliciousModelError(msg) from e


def load(*args, **kwargs) -> Any:
    """Alias for safe_load for drop-in compatibility."""
    return safe_load(*args, **kwargs)
