"""
Modelguard - A drop-in seat-belt library for ML model files.

Provides safe loading, signature verification, and malware detection
for PyTorch, TensorFlow, scikit-learn, and ONNX models.
"""

from .context import patched
from .core.exceptions import MaliciousModelError, ModelGuardError, SignatureError
from .core.policy import Policy, load_policy
from .core.scanner import ModelScanner
from .loaders import onnx, sklearn, tensorflow, torch

__version__ = "0.2.1"
__all__ = [
    "MaliciousModelError",
    "ModelGuardError",
    "ModelScanner",
    "Policy",
    "SignatureError",
    "load_policy",
    "onnx",
    "patched",
    "sklearn",
    "tensorflow",
    "torch",
]
