"""Tests to expand coverage for uncovered code paths."""

import os
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

import pytest

from modelguard import context
from modelguard.core.exceptions import (
    ModelGuardError, MaliciousModelError, PolicyError, 
    SignatureError, UnsupportedFormatError
)
from modelguard.core.logging import get_logger, setup_logging
from modelguard.core.opcodes import DANGEROUS_OPCODES, SAFE_CLASSES
from modelguard.core.policy import PolicyConfig, Policy
from modelguard.core.scanner import ModelScanner
from modelguard.core.signature import SignatureManager
from modelguard.loaders import torch, sklearn, tensorflow, onnx


class TestExceptionHandling:
    """Test exception handling and error paths."""

    def test_modelguard_error_hierarchy(self):
        """Test ModelGuard exception hierarchy."""
        # Test base exception
        base_error = ModelGuardError("Base error")
        assert str(base_error) == "Base error"
        assert isinstance(base_error, Exception)
        
        # Test specific exceptions
        malicious_error = MaliciousModelError("Malicious model detected")
        assert isinstance(malicious_error, ModelGuardError)
        
        policy_error = PolicyError("Policy violation")
        assert isinstance(policy_error, ModelGuardError)
        
        signature_error = SignatureError("Signature invalid")
        assert isinstance(signature_error, ModelGuardError)
        
        format_error = UnsupportedFormatError("Unsupported format")
        assert isinstance(format_error, ModelGuardError)

    def test_exception_chaining(self):
        """Test exception chaining and context."""
        try:
            try:
                raise ValueError("Original error")
            except ValueError as e:
                raise MaliciousModelError("Wrapped error") from e
        except MaliciousModelError as e:
            assert e.__cause__ is not None
            assert isinstance(e.__cause__, ValueError)
            assert str(e.__cause__) == "Original error"


class TestLoggingSystem:
    """Test logging functionality."""

    def test_get_logger(self):
        """Test logger creation."""
        logger = get_logger("test_module")
        assert logger.name == "modelguard.test_module"
        
        # Test with different module names
        logger2 = get_logger("another.module")
        assert logger2.name == "modelguard.another.module"

    def test_setup_logging(self):
        """Test logging setup."""
        # Test with different log levels
        setup_logging("DEBUG")
        logger = get_logger("test")
        assert logger.isEnabledFor(10)  # DEBUG level
        
        setup_logging("INFO")
        assert logger.isEnabledFor(20)  # INFO level
        
        setup_logging("WARNING")
        assert logger.isEnabledFor(30)  # WARNING level

    def test_logging_with_invalid_level(self):
        """Test logging setup with invalid level."""
        # Should handle invalid levels gracefully
        setup_logging("INVALID_LEVEL")
        logger = get_logger("test")
        # Should still work, probably defaults to INFO


class TestPolicyEdgeCases:
    """Test policy edge cases and error conditions."""

    def test_policy_with_invalid_yaml(self):
        """Test policy loading with invalid YAML."""
        invalid_yaml = "invalid: yaml: content: ["
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            f.flush()
            temp_path = Path(f.name)
            
        try:
            # Should handle invalid YAML gracefully by catching the exception
            with pytest.raises(Exception):  # YAML parsing should fail
                policy = Policy.from_file(temp_path)
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass  # Ignore cleanup errors on Windows

    def test_policy_with_partial_config(self):
        """Test policy with partial configuration."""
        partial_config = PolicyConfig(enforce=True)  # Only set one field
        policy = Policy(partial_config)
        
        assert policy.should_enforce()
        assert not policy.requires_signatures()  # Should use default
        assert policy.is_signer_trusted("anyone")  # Should use default

    def test_policy_environment_variable_parsing(self):
        """Test environment variable parsing edge cases."""
        test_cases = {
            "MODELGUARD_ENFORCE": ["true", "True", "TRUE", "1", "yes"],
            "MODELGUARD_REQUIRE_SIGNATURES": ["false", "False", "FALSE", "0", "no"],
        }
        
        for env_var, true_values in test_cases.items():
            for value in true_values:
                with patch.dict('os.environ', {env_var: value}):
                    policy = Policy.from_env()
                    if env_var == "MODELGUARD_ENFORCE":
                        expected = value.lower() in ["true", "1", "yes"]
                        assert policy.should_enforce() == expected
                    elif env_var == "MODELGUARD_REQUIRE_SIGNATURES":
                        expected = value.lower() in ["true", "1", "yes"]
                        assert policy.requires_signatures() == expected

    def test_policy_trusted_signers_parsing(self):
        """Test trusted signers parsing from environment."""
        test_cases = [
            ("alice@example.com", ["alice@example.com"]),
            ("alice@example.com,bob@example.com", ["alice@example.com", "bob@example.com"]),
            ("alice@example.com, bob@example.com", ["alice@example.com", "bob@example.com"]),
            ("", []),
            ("   ", []),
        ]
        
        for env_value, expected_signers in test_cases:
            with patch.dict('os.environ', {'MODELGUARD_TRUSTED_SIGNERS': env_value}):
                policy = Policy.from_env()
                
                if not expected_signers:
                    # Empty list means trust all
                    assert policy.is_signer_trusted("anyone@example.com")
                else:
                    for signer in expected_signers:
                        assert policy.is_signer_trusted(signer)
                    assert not policy.is_signer_trusted("untrusted@example.com")


class TestScannerEdgeCases:
    """Test scanner edge cases and error conditions."""

    def test_scanner_with_permission_denied(self):
        """Test scanner behavior with permission denied."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test data")
            f.flush()
            temp_path = Path(f.name)
            
        try:
            # Mock permission error
            with patch('pathlib.Path.stat', side_effect=PermissionError("Permission denied")):
                scanner = ModelScanner()
                result = scanner.scan_file(temp_path)
                
                assert not result.is_safe
                assert "error" in result.details
                
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_scanner_with_corrupted_zip(self):
        """Test scanner with corrupted ZIP files."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            # Write invalid ZIP data
            f.write(b"PK\x03\x04corrupted zip data")
            f.flush()
            temp_path = Path(f.name)
            
        try:
            scanner = ModelScanner()
            result = scanner.scan_file(temp_path)
            
            # Should handle corrupted ZIP gracefully
            assert not result.is_safe
            assert "error" in result.details
            
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_scanner_with_empty_zip(self):
        """Test scanner with empty ZIP files."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            # Create empty ZIP
            with zipfile.ZipFile(f, 'w') as zf:
                pass  # Empty ZIP
            temp_path = Path(f.name)
            
        try:
            scanner = ModelScanner()
            result = scanner.scan_file(temp_path)
            
            # Empty ZIP should be considered safe
            assert result.is_safe
            assert result.details.get("archive_type") == "zip"
            
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_scanner_directory_with_symlinks(self):
        """Test directory scanning with symbolic links."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create a regular file
            regular_file = tmpdir_path / "regular.pkl"
            regular_file.write_bytes(b"regular file")
            
            try:
                # Create a symbolic link (may not work on all systems)
                symlink_file = tmpdir_path / "symlink.pkl"
                symlink_file.symlink_to(regular_file)
                
                scanner = ModelScanner()
                results = scanner.scan_directory(tmpdir_path)
                
                # Should handle symlinks appropriately
                assert len(results) >= 1  # At least the regular file
                
            except (OSError, NotImplementedError):
                # Symlinks might not be supported on all systems
                pytest.skip("Symbolic links not supported on this system")

    def test_scanner_with_very_deep_directory(self):
        """Test scanner with very deep directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create deep directory structure
            current_dir = tmpdir_path
            for i in range(10):  # 10 levels deep
                current_dir = current_dir / f"level_{i}"
                current_dir.mkdir()
            
            # Create file at the deepest level
            deep_file = current_dir / "deep.pkl"
            deep_file.write_bytes(b"deep file")
            
            scanner = ModelScanner()
            results = scanner.scan_directory(tmpdir_path, recursive=True)
            
            assert len(results) == 1
            assert results[0].path == deep_file


class TestLoaderEdgeCases:
    """Test loader edge cases and error conditions."""

    def test_torch_loader_with_invalid_file_object(self):
        """Test torch loader with invalid file object."""
        # Test with None
        with pytest.raises(Exception):
            torch.RestrictedUnpickler(None)

    def test_torch_loader_with_string_path(self):
        """Test torch loader with string path vs Path object."""
        test_data = {"string_path": "test"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            import pickle
            pickle.dump(test_data, f)
            f.flush()
            temp_path = Path(f.name)
            
        try:
            # Test with string path
            result1 = torch.safe_load(str(temp_path))
            assert result1 == test_data
            
            # Test with Path object
            result2 = torch.safe_load(temp_path)
            assert result2 == test_data
            
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_sklearn_loader_with_nonexistent_file(self):
        """Test sklearn loader with nonexistent file."""
        with pytest.raises(Exception):
            sklearn.safe_load("nonexistent_file.pkl")

    def test_tensorflow_loader_with_invalid_custom_objects(self):
        """Test tensorflow loader custom object filtering."""
        # Test the actual filtering function if it exists
        try:
            from modelguard.loaders.tensorflow import _filter_custom_objects
            
            custom_objects = {
                "safe_function": lambda x: x,  # Should be filtered
                "safe_data": [1, 2, 3],  # Should be kept
                "tensorflow.keras.layers.Dense": Mock(),  # Should be kept
                "malicious_function": eval,  # Should be filtered
            }
            
            filtered = _filter_custom_objects(custom_objects)
            
            assert "safe_data" in filtered
            assert "safe_function" not in filtered
            assert "malicious_function" not in filtered
            
        except ImportError:
            # Function might not exist, skip test
            pytest.skip("_filter_custom_objects not available")

    def test_onnx_loader_without_onnx_installed(self):
        """Test ONNX loader when ONNX is not available."""
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
            f.write(b"fake onnx data")
            f.flush()
            temp_path = Path(f.name)
            
        try:
            # Mock ONNX not being available
            with patch('builtins.__import__', side_effect=ImportError("No module named 'onnx'")):
                with patch('modelguard.loaders.onnx.load_policy') as mock_policy:
                    mock_policy_obj = Mock()
                    mock_policy_obj.should_enforce.return_value = True
                    mock_policy_obj.get_max_file_size.return_value = 1000000
                    mock_policy_obj.requires_signatures.return_value = False
                    mock_policy_obj.should_scan.return_value = False
                    mock_policy.return_value = mock_policy_obj
                    
                    with pytest.raises(MaliciousModelError, match="ONNX not available"):
                        onnx.safe_load(str(temp_path))
                        
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass


class TestSignatureManagerEdgeCases:
    """Test signature manager edge cases."""

    def test_signature_manager_with_invalid_json(self):
        """Test signature verification with invalid JSON."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model")
            f.flush()
            temp_path = Path(f.name)
            
        # Create invalid signature file
        sig_path = temp_path.with_suffix(temp_path.suffix + ".sig")
        sig_path.write_text("invalid json content")
        
        try:
            sig_manager = SignatureManager()
            result = sig_manager.verify_signature(temp_path)
            
            assert not result["verified"]
            assert "error" in result
            
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass
            try:
                sig_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_signature_manager_with_empty_signature(self):
        """Test signature verification with empty signature file."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model")
            f.flush()
            temp_path = Path(f.name)
            
        # Create empty signature file
        sig_path = temp_path.with_suffix(temp_path.suffix + ".sig")
        sig_path.write_text("")
        
        try:
            sig_manager = SignatureManager()
            result = sig_manager.verify_signature(temp_path)
            
            assert not result["verified"]
            assert "error" in result
            
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass
            try:
                sig_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_signature_manager_extract_signer_info(self):
        """Test signer info extraction."""
        sig_manager = SignatureManager()
        
        # Test with None bundle
        result = sig_manager._extract_signer_info(None)
        assert result["identity"] == "unknown"
        assert result["issuer"] == "unknown"
        assert result["timestamp"] is None
        
        # Test with mock bundle
        mock_bundle = Mock()
        mock_bundle.verification_material.certificate.subject = "test@example.com"
        
        # This might not work depending on implementation, but test the structure
        result = sig_manager._extract_signer_info(mock_bundle)
        assert "identity" in result
        assert "issuer" in result
        assert "timestamp" in result


class TestOpcodeAnalysisEdgeCases:
    """Test opcode analysis edge cases."""

    def test_dangerous_opcodes_constants(self):
        """Test that dangerous opcodes constants are properly defined."""
        assert isinstance(DANGEROUS_OPCODES, (list, tuple, set))
        assert len(DANGEROUS_OPCODES) > 0
        
        # Should include known dangerous opcodes
        dangerous_set = set(DANGEROUS_OPCODES)
        expected_dangerous = {"GLOBAL", "REDUCE", "BUILD", "INST", "OBJ", "STACK_GLOBAL"}
        
        # At least some of these should be in the dangerous list
        assert len(dangerous_set.intersection(expected_dangerous)) > 0

    def test_safe_classes_constants(self):
        """Test that safe classes constants are properly defined."""
        assert isinstance(SAFE_CLASSES, (list, tuple, set))
        assert len(SAFE_CLASSES) > 0
        
        # Should include known safe classes
        safe_set = set(SAFE_CLASSES)
        expected_safe = {"builtins.list", "builtins.dict", "builtins.tuple", "builtins.str"}
        
        # At least some of these should be in the safe list
        assert len(safe_set.intersection(expected_safe)) > 0

    def test_opcode_analysis_with_truncated_pickle(self):
        """Test opcode analysis with truncated pickle data."""
        # Create truncated pickle (starts correctly but cuts off)
        truncated_pickle = b'\x80\x03}q\x00'  # Incomplete
        
        from modelguard.core.opcodes import analyze_pickle_opcodes
        analysis = analyze_pickle_opcodes(truncated_pickle)
        
        # Should handle gracefully
        assert "error" in analysis or not analysis.get("is_safe", True)

    def test_opcode_analysis_with_binary_data(self):
        """Test opcode analysis with random binary data."""
        import random
        
        # Generate random binary data
        random_data = bytes([random.randint(0, 255) for _ in range(100)])
        
        from modelguard.core.opcodes import analyze_pickle_opcodes
        analysis = analyze_pickle_opcodes(random_data)
        
        # Should handle gracefully without crashing
        assert isinstance(analysis, dict)


class TestContextManagerEdgeCases:
    """Test context manager edge cases."""

    def test_context_manager_with_missing_modules(self):
        """Test context manager when target modules are not available."""
        # Temporarily remove modules from sys.modules
        import sys
        
        modules_to_remove = ['torch', 'joblib', 'tensorflow', 'onnx']
        original_modules = {}
        
        for module in modules_to_remove:
            if module in sys.modules:
                original_modules[module] = sys.modules[module]
                del sys.modules[module]
        
        try:
            # Should not crash even when modules are missing
            with context.patched():
                pass  # Should complete without error
                
        finally:
            # Restore modules
            for module, original in original_modules.items():
                sys.modules[module] = original

    def test_context_manager_nested_calls(self):
        """Test nested context manager calls."""
        # Should handle nested calls gracefully
        with context.patched():
            with context.patched():
                with context.patched():
                    pass  # Should work without issues


class TestFileHandlingEdgeCases:
    """Test file handling edge cases."""

    def test_file_size_calculation_edge_cases(self):
        """Test file size calculations with edge cases."""
        # Test with empty file
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.flush()  # Empty file
            temp_path = Path(f.name)
            
        try:
            scanner = ModelScanner()
            result = scanner.scan_file(temp_path)
            
            # Should handle empty files
            assert not result.is_safe  # Empty files are not valid models
            
        finally:
            try:
                temp_path.unlink()
            except (PermissionError, FileNotFoundError):
                pass

    def test_directory_scanning_with_special_files(self):
        """Test directory scanning with special files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create files with special names
            special_files = [
                ".hidden.pkl",
                "file with spaces.pkl",
                "file-with-dashes.pkl",
                "file_with_underscores.pkl",
                "UPPERCASE.PKL",
            ]
            
            for filename in special_files:
                file_path = tmpdir_path / filename
                file_path.write_bytes(b"test data")
            
            scanner = ModelScanner()
            results = scanner.scan_directory(tmpdir_path)
            
            # Should find all files regardless of naming
            assert len(results) == len(special_files)

    def test_path_handling_with_unicode(self):
        """Test path handling with Unicode characters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create file with Unicode name
            unicode_file = tmpdir_path / "模型文件.pkl"
            unicode_file.write_bytes(b"unicode test data")
            
            try:
                scanner = ModelScanner()
                result = scanner.scan_file(unicode_file)
                
                # Should handle Unicode paths
                assert result.path == unicode_file
                
            except (UnicodeError, OSError):
                # Some systems might not support Unicode filenames
                pytest.skip("Unicode filenames not supported on this system")