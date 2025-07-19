"""
Modelguard - A drop-in seat-belt library for ML model files.

Provides safe loading, signature verification, and malware detection
for PyTorch, TensorFlow, scikit-learn, and ONNX models.
"""

from .core.exceptions import ModelGuardError, MaliciousModelError, SignatureError
from .core.policy import Policy, load_policy
from .core.scanner import ModelScanner
from .loaders import torch, tensorflow, sklearn, onnx
from .context import patched

__version__ = "0.1.0"
__all__ = [
    "ModelGuardError",
    "MaliciousModelError", 
    "SignatureError",
    "Policy",
    "load_policy",
    "ModelScanner",
    "torch",
    "tensorflow", 
    "sklearn",
    "onnx",
    "patched",
]