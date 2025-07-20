"""Tests for context management and monkey patching."""

import sys
from unittest.mock import Mock, patch

import pytest

from modelguard import context


class TestContextManager:
    """Test the patched() context manager."""

    def test_context_manager_basic(self):
        """Test basic context manager functionality."""
        # Should not raise any errors
        with context.patched():
            pass

    @patch.dict('sys.modules', {'torch': Mock()})
    def test_torch_patching(self):
        """Test PyTorch monkey patching."""
        mock_torch = Mock()
        mock_torch.load = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'torch': mock_torch}):
            with patch('modelguard.context.torch_safe_load') as mock_safe_load:
                mock_safe_load.return_value = "safe_result"
                
                with context.patched():
                    # torch.load should be patched
                    result = mock_torch.load("test.pth")
                    assert result == "safe_result"
                    mock_safe_load.assert_called_once_with("test.pth")
                
                # After context, should be restored
                result = mock_torch.load("test.pth")
                assert result == "original_result"

    @patch.dict('sys.modules', {'joblib': Mock()})
    def test_joblib_patching(self):
        """Test joblib monkey patching."""
        mock_joblib = Mock()
        mock_joblib.load = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'joblib': mock_joblib}):
            with patch('modelguard.context.sklearn_safe_load') as mock_safe_load:
                mock_safe_load.return_value = "safe_result"
                
                with context.patched():
                    # joblib.load should be patched
                    result = mock_joblib.load("test.joblib")
                    assert result == "safe_result"
                    mock_safe_load.assert_called_once_with("test.joblib")
                
                # After context, should be restored
                result = mock_joblib.load("test.joblib")
                assert result == "original_result"

    @patch.dict('sys.modules', {'tensorflow': Mock()})
    def test_tensorflow_patching(self):
        """Test TensorFlow monkey patching."""
        mock_tf = Mock()
        mock_tf.keras.models.load_model = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'tensorflow': mock_tf}):
            with patch('modelguard.context.tf_safe_load') as mock_safe_load:
                mock_safe_load.return_value = "safe_result"
                
                with context.patched():
                    # tf.keras.models.load_model should be patched
                    result = mock_tf.keras.models.load_model("test.h5")
                    assert result == "safe_result"
                    mock_safe_load.assert_called_once_with("test.h5")
                
                # After context, should be restored
                result = mock_tf.keras.models.load_model("test.h5")
                assert result == "original_result"

    @patch.dict('sys.modules', {'onnx': Mock()})
    def test_onnx_patching(self):
        """Test ONNX monkey patching."""
        mock_onnx = Mock()
        mock_onnx.load = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'onnx': mock_onnx}):
            with patch('modelguard.context.onnx_safe_load') as mock_safe_load:
                mock_safe_load.return_value = "safe_result"
                
                with context.patched():
                    # onnx.load should be patched
                    result = mock_onnx.load("test.onnx")
                    assert result == "safe_result"
                    mock_safe_load.assert_called_once_with("test.onnx")
                
                # After context, should be restored
                result = mock_onnx.load("test.onnx")
                assert result == "original_result"

    def test_no_modules_loaded(self):
        """Test context manager when no target modules are loaded."""
        # Clear all target modules from sys.modules temporarily
        modules_to_clear = ['torch', 'joblib', 'tensorflow', 'onnx', 'pickle']
        original_modules = {}
        
        for module in modules_to_clear:
            if module in sys.modules:
                original_modules[module] = sys.modules[module]
                del sys.modules[module]
        
        try:
            # Should not raise any errors even when modules aren't loaded
            with context.patched():
                pass
        finally:
            # Restore original modules
            for module, original in original_modules.items():
                sys.modules[module] = original

    def test_partial_module_loading(self):
        """Test context manager with only some modules loaded."""
        # Only load torch, not others
        mock_torch = Mock()
        mock_torch.load = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'torch': mock_torch}, clear=False):
            # Remove other modules if they exist
            modules_to_remove = ['joblib', 'tensorflow', 'onnx']
            removed_modules = {}
            
            for module in modules_to_remove:
                if module in sys.modules:
                    removed_modules[module] = sys.modules[module]
                    del sys.modules[module]
            
            try:
                with patch('modelguard.context.torch_safe_load') as mock_safe_load:
                    mock_safe_load.return_value = "safe_result"
                    
                    with context.patched():
                        # Only torch should be patched
                        result = mock_torch.load("test.pth")
                        assert result == "safe_result"
                        mock_safe_load.assert_called_once_with("test.pth")
            finally:
                # Restore removed modules
                for module, original in removed_modules.items():
                    sys.modules[module] = original

    def test_exception_in_context(self):
        """Test that original loaders are restored even if exception occurs."""
        mock_torch = Mock()
        mock_torch.load = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'torch': mock_torch}):
            with patch('modelguard.context.torch_safe_load') as mock_safe_load:
                mock_safe_load.return_value = "safe_result"
                
                try:
                    with context.patched():
                        # Verify patching works
                        result = mock_torch.load("test.pth")
                        assert result == "safe_result"
                        
                        # Raise an exception
                        raise ValueError("Test exception")
                except ValueError:
                    pass
                
                # After exception, should still be restored
                result = mock_torch.load("test.pth")
                assert result == "original_result"

    def test_nested_context_managers(self):
        """Test nested context managers."""
        mock_torch = Mock()
        mock_torch.load = Mock(return_value="original_result")
        
        with patch.dict('sys.modules', {'torch': mock_torch}):
            with patch('modelguard.context.torch_safe_load') as mock_safe_load:
                mock_safe_load.return_value = "safe_result"
                
                with context.patched():
                    # First level patching
                    result = mock_torch.load("test1.pth")
                    assert result == "safe_result"
                    
                    with context.patched():
                        # Nested patching should still work
                        result = mock_torch.load("test2.pth")
                        assert result == "safe_result"
                    
                    # Still patched after inner context
                    result = mock_torch.load("test3.pth")
                    assert result == "safe_result"
                
                # Restored after outer context
                result = mock_torch.load("test4.pth")
                assert result == "original_result"