"""Tests for model loaders."""

import pickle
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modelguard.core.exceptions import MaliciousModelError, PolicyError
from modelguard.loaders import torch, sklearn, tensorflow, onnx


class TestTorchLoader:
    """Test PyTorch loader functionality."""

    def test_restricted_unpickler_safe_class(self):
        """Test that RestrictedUnpickler allows safe classes."""
        import io
        fake_file = io.BytesIO(b"fake pickle data")
        unpickler = torch.RestrictedUnpickler(fake_file)
        
        # Should allow safe built-in classes
        result = unpickler.find_class("builtins", "list")
        assert result == list

    def test_restricted_unpickler_unsafe_class(self):
        """Test that RestrictedUnpickler blocks unsafe classes."""
        import io
        fake_file = io.BytesIO(b"fake pickle data")
        unpickler = torch.RestrictedUnpickler(fake_file)
        
        # Should block unsafe classes
        with pytest.raises(MaliciousModelError):
            unpickler.find_class("os", "system")

    def test_safe_load_with_safe_pickle(self):
        """Test safe loading of a safe pickle file."""
        test_data = {"model": "weights", "version": 1.0}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            result = torch.safe_load(f.name)
            assert result == test_data

    @patch('modelguard.loaders.torch.load_policy')
    def test_safe_load_with_policy_enforcement(self, mock_load_policy):
        """Test safe loading with policy enforcement."""
        mock_policy = Mock()
        mock_policy.get_max_file_size.return_value = 1  # Very small limit
        mock_policy.requires_signatures.return_value = False
        mock_policy.should_scan.return_value = False
        mock_load_policy.return_value = mock_policy
        
        test_data = {"large": "data" * 1000}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            with pytest.raises(PolicyError):
                torch.safe_load(f.name)

    def test_load_alias(self):
        """Test that load() is an alias for safe_load()."""
        test_data = {"test": "data"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            result = torch.load(f.name)
            assert result == test_data


class TestSklearnLoader:
    """Test scikit-learn loader functionality."""

    def test_safe_load_pickle_file(self):
        """Test safe loading of pickle file."""
        test_data = {"model": "sklearn_model", "params": [1, 2, 3]}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            result = sklearn.safe_load(f.name)
            assert result == test_data

    @patch('modelguard.loaders.sklearn.joblib')
    def test_safe_load_joblib_file(self, mock_joblib):
        """Test safe loading of joblib file."""
        mock_joblib.load.return_value = {"joblib": "data"}
        
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            f.write(b"fake joblib data")
            f.flush()
            
            # This will use the fallback since we can't easily create real joblib data
            with patch('modelguard.loaders.sklearn._safe_joblib_load') as mock_safe_joblib:
                mock_safe_joblib.return_value = {"joblib": "data"}
                result = sklearn.safe_load(f.name)
                assert result == {"joblib": "data"}

    @patch('modelguard.loaders.sklearn.load_policy')
    def test_safe_load_with_scanning(self, mock_load_policy):
        """Test safe loading with malware scanning."""
        mock_policy = Mock()
        mock_policy.get_max_file_size.return_value = 1000000
        mock_policy.requires_signatures.return_value = False
        mock_policy.should_scan.return_value = True
        mock_policy.should_enforce.return_value = True
        mock_load_policy.return_value = mock_policy
        
        test_data = {"test": "data"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            with patch('modelguard.loaders.sklearn.ModelScanner') as mock_scanner_class:
                mock_scanner = Mock()
                mock_result = Mock()
                mock_result.is_safe = False
                mock_result.threats = ["GLOBAL opcode detected"]
                mock_scanner.scan_file.return_value = mock_result
                mock_scanner_class.return_value = mock_scanner
                
                with pytest.raises(MaliciousModelError):
                    sklearn.safe_load(f.name)


class TestTensorflowLoader:
    """Test TensorFlow loader functionality."""

    @patch('modelguard.loaders.tensorflow.load_policy')
    def test_safe_load_file_size_check(self, mock_load_policy):
        """Test file size checking."""
        mock_policy = Mock()
        mock_policy.get_max_file_size.return_value = 1  # Very small limit
        mock_policy.requires_signatures.return_value = False
        mock_policy.should_scan.return_value = False
        mock_load_policy.return_value = mock_policy
        
        with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as f:
            f.write(b"fake model data that's too large")
            f.flush()
            
            with pytest.raises(PolicyError):
                tensorflow.safe_load(f.name)

    @patch('modelguard.loaders.tensorflow.load_policy')
    def test_safe_load_directory_size_check(self, mock_load_policy):
        """Test directory size checking for SavedModel format."""
        mock_policy = Mock()
        mock_policy.get_max_file_size.return_value = 1  # Very small limit
        mock_policy.requires_signatures.return_value = False
        mock_policy.should_scan.return_value = False
        mock_load_policy.return_value = mock_policy
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file in the directory
            test_file = Path(tmpdir) / "saved_model.pb"
            test_file.write_text("fake model data that's too large")
            
            with pytest.raises(PolicyError):
                tensorflow.safe_load(tmpdir)

    def test_filter_custom_objects(self):
        """Test custom object filtering."""
        custom_objects = {
            "safe_function": lambda x: x,  # Should be filtered out (callable)
            "safe_data": [1, 2, 3],  # Should be kept (non-callable)
            "tensorflow.keras.layers.Dense": Mock(),  # Should be kept (safe prefix)
        }
        
        result = tensorflow._filter_safe_custom_objects(custom_objects)
        
        # Should keep non-callable objects and safe tensorflow objects
        assert "safe_data" in result
        assert result["safe_data"] == [1, 2, 3]
        
        # Should filter out unsafe callables
        assert "safe_function" not in result


class TestOnnxLoader:
    """Test ONNX loader functionality."""

    @patch('modelguard.loaders.onnx.load_policy')
    def test_safe_load_file_size_check(self, mock_load_policy):
        """Test file size checking."""
        mock_policy = Mock()
        mock_policy.get_max_file_size.return_value = 1  # Very small limit
        mock_policy.requires_signatures.return_value = False
        mock_policy.should_scan.return_value = False
        mock_load_policy.return_value = mock_policy
        
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
            f.write(b"fake onnx model data that's too large")
            f.flush()
            
            with pytest.raises(PolicyError):
                onnx.safe_load(f.name)

    def test_safe_load_success(self):
        """Test successful ONNX model loading."""
        pytest.importorskip("onnx", reason="ONNX not available")
        
        with patch('modelguard.loaders.onnx.load_policy') as mock_load_policy:
            with patch('onnx.load') as mock_onnx_load:
                with patch('onnx.checker.check_model') as mock_check:
                    mock_policy = Mock()
                    mock_policy.get_max_file_size.return_value = 1000000
                    mock_policy.requires_signatures.return_value = False
                    mock_policy.should_scan.return_value = False
                    mock_load_policy.return_value = mock_policy
                    
                    mock_model = Mock()
                    mock_onnx_load.return_value = mock_model
                    
                    with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
                        f.write(b"fake onnx model data")
                        f.flush()
                        
                        result = onnx.safe_load(f.name)
                        assert result == mock_model
                        mock_onnx_load.assert_called_once()
                        mock_check.assert_called_once_with(mock_model)

    @patch('modelguard.loaders.onnx.load_policy')
    def test_safe_load_onnx_not_available(self, mock_load_policy):
        """Test handling when ONNX is not available."""
        mock_policy = Mock()
        mock_policy.get_max_file_size.return_value = 1000000
        mock_policy.requires_signatures.return_value = False
        mock_policy.should_scan.return_value = False
        mock_policy.should_enforce.return_value = True
        mock_load_policy.return_value = mock_policy
        
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
            f.write(b"fake onnx model data")
            f.flush()
            
            # Mock import error
            with patch('builtins.__import__', side_effect=ImportError("No module named 'onnx'")):
                with pytest.raises(MaliciousModelError, match="ONNX not available"):
                    onnx.safe_load(f.name)


class TestLoaderIntegration:
    """Integration tests for loaders."""

    def test_all_loaders_have_load_alias(self):
        """Test that all loaders have a load() alias."""
        assert hasattr(torch, 'load')
        assert hasattr(sklearn, 'load')
        assert hasattr(tensorflow, 'load')
        assert hasattr(onnx, 'load')
        
        # Test they're callable
        assert callable(torch.load)
        assert callable(sklearn.load)
        assert callable(tensorflow.load)
        assert callable(onnx.load)