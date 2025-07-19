"""Context managers for monkey-patching framework loaders."""

import contextlib
import sys
from collections.abc import Generator


@contextlib.contextmanager
def patched() -> Generator[None, None, None]:
    """
    Context manager that monkey-patches framework loaders to use safe versions.
    
    Usage:
        with modelguard.patched():
            model = torch.load('model.pth')  # Uses safe_load automatically
    """
    original_loaders = {}

    try:
        # Patch PyTorch
        if 'torch' in sys.modules:
            import torch

            from .loaders.torch import safe_load as torch_safe_load

            original_loaders['torch.load'] = torch.load
            torch.load = torch_safe_load

        # Patch scikit-learn
        if 'joblib' in sys.modules:
            import joblib

            from .loaders.sklearn import safe_load as sklearn_safe_load

            original_loaders['joblib.load'] = joblib.load
            joblib.load = sklearn_safe_load

        if 'pickle' in sys.modules:
            from .loaders.sklearn import safe_load as sklearn_safe_load

            # This is more complex since pickle.load is generic
            # For now, we'll skip patching pickle directly

        # Patch TensorFlow/Keras
        if 'tensorflow' in sys.modules:
            import tensorflow as tf

            from .loaders.tensorflow import safe_load as tf_safe_load

            if hasattr(tf.keras.models, 'load_model'):
                original_loaders['tf.keras.models.load_model'] = tf.keras.models.load_model
                tf.keras.models.load_model = tf_safe_load

        # Patch ONNX
        if 'onnx' in sys.modules:
            import onnx

            from .loaders.onnx import safe_load as onnx_safe_load

            original_loaders['onnx.load'] = onnx.load
            onnx.load = onnx_safe_load

        yield

    finally:
        # Restore original loaders
        if 'torch.load' in original_loaders:
            import torch
            torch.load = original_loaders['torch.load']

        if 'joblib.load' in original_loaders:
            import joblib
            joblib.load = original_loaders['joblib.load']

        if 'tf.keras.models.load_model' in original_loaders:
            import tensorflow as tf
            tf.keras.models.load_model = original_loaders['tf.keras.models.load_model']

        if 'onnx.load' in original_loaders:
            import onnx
            onnx.load = original_loaders['onnx.load']
