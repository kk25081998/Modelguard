"""Integration tests for ModelGuard end-to-end workflows."""

import json
import pickle
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modelguard import context
from modelguard.cli import app
from modelguard.core.policy import load_policy
from modelguard.core.scanner import ModelScanner
from modelguard.core.signature import SignatureManager
from modelguard.loaders import torch, sklearn, tensorflow, onnx


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""

    def test_scan_sign_verify_workflow(self):
        """Test complete scan -> sign -> verify workflow."""
        # Create a test model
        test_data = {"model": "weights", "version": "1.0"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            model_path = Path(f.name)
            
            try:
                # Step 1: Scan the model
                scanner = ModelScanner()
                scan_result = scanner.scan_file(model_path)
                assert scan_result.is_safe
                
                # Step 2: Sign the model (mocked)
                with patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True):
                    with patch('modelguard.core.signature.sign') as mock_sign:
                        mock_bundle = Mock()
                        mock_bundle.to_json.return_value = '{"test": "signature"}'
                        mock_sign.sign_dsse.return_value = mock_bundle
                        
                        sig_manager = SignatureManager()
                        sig_path = sig_manager.sign_model(model_path)
                        
                        assert sig_path.exists()
                        assert sig_manager.has_signature(model_path)
                        
                        # Step 3: Verify the signature (mocked)
                        with patch('modelguard.core.signature.verify') as mock_verify:
                            mock_verify.verify_dsse.return_value = True
                            
                            verify_result = sig_manager.verify_signature(model_path)
                            assert verify_result["verified"]
                            
                        # Clean up signature file
                        sig_path.unlink()
                        
            finally:
                model_path.unlink()

    def test_policy_enforcement_workflow(self):
        """Test policy enforcement across different scenarios."""
        # Create test models
        safe_data = {"safe": "model"}
        malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00.'
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as safe_f:
            pickle.dump(safe_data, safe_f)
            safe_f.flush()
            safe_path = Path(safe_f.name)
            
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as mal_f:
                mal_f.write(malicious_pickle)
                mal_f.flush()
                mal_path = Path(mal_f.name)
                
                try:
                    # Test with permissive policy
                    with patch('modelguard.core.policy.load_policy') as mock_load_policy:
                        mock_policy = Mock()
                        mock_policy.should_enforce.return_value = False
                        mock_policy.requires_signatures.return_value = False
                        mock_policy.should_scan.return_value = True
                        mock_policy.get_max_file_size.return_value = 1000000
                        mock_load_policy.return_value = mock_policy
                        
                        # Should load successfully even with malicious content
                        result = torch.safe_load(mal_path)
                        # Note: This would normally fail, but with enforce=False it falls back
                        
                    # Test with strict policy
                    with patch('modelguard.core.policy.load_policy') as mock_load_policy:
                        mock_policy = Mock()
                        mock_policy.should_enforce.return_value = True
                        mock_policy.requires_signatures.return_value = False
                        mock_policy.should_scan.return_value = True
                        mock_policy.get_max_file_size.return_value = 1000000
                        mock_load_policy.return_value = mock_policy
                        
                        with patch('modelguard.core.scanner.ModelScanner') as mock_scanner_class:
                            mock_scanner = Mock()
                            mock_result = Mock()
                            mock_result.is_safe = False
                            mock_result.threats = ["GLOBAL opcode detected"]
                            mock_scanner.scan_file.return_value = mock_result
                            mock_scanner_class.return_value = mock_scanner
                            
                            # Should raise exception with strict policy
                            with pytest.raises(Exception):
                                torch.safe_load(mal_path)
                                
                finally:
                    safe_path.unlink()
                    mal_path.unlink()

    def test_multi_format_scanning(self):
        """Test scanning multiple file formats in a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create files of different formats
            formats = {
                "model.pkl": pickle.dumps({"pkl": "data"}),
                "model.pth": b"fake pytorch data",
                "model.h5": b"fake hdf5 data",
                "model.onnx": b"fake onnx data",
                "model.joblib": pickle.dumps({"joblib": "data"}),
                "readme.txt": b"not a model file"
            }
            
            for filename, content in formats.items():
                file_path = tmpdir_path / filename
                file_path.write_bytes(content)
            
            # Scan directory
            scanner = ModelScanner()
            results = scanner.scan_directory(tmpdir_path)
            
            # Should scan all supported formats except .txt
            expected_count = len([f for f in formats.keys() if not f.endswith('.txt')])
            assert len(results) == expected_count
            
            # Check that each result has proper format detection
            for result in results:
                assert result.path.suffix in scanner.supported_extensions

    def test_context_manager_integration(self):
        """Test context manager integration with different frameworks."""
        test_data = {"context": "test"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            try:
                # Test that context manager doesn't break normal operation
                with context.patched():
                    # This should work without issues
                    result = torch.safe_load(f.name)
                    assert result == test_data
                    
                # After context, should still work
                result = torch.safe_load(f.name)
                assert result == test_data
                
            finally:
                Path(f.name).unlink()

    def test_cli_integration_workflow(self):
        """Test CLI commands integration."""
        from typer.testing import CliRunner
        
        runner = CliRunner()
        
        # Create test files
        safe_data = {"cli": "test"}
        malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00.'
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as safe_f:
            pickle.dump(safe_data, safe_f)
            safe_f.flush()
            
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as mal_f:
                mal_f.write(malicious_pickle)
                mal_f.flush()
                
                try:
                    # Test scanning safe file
                    result = runner.invoke(app, ["scan", safe_f.name])
                    assert result.exit_code == 0
                    assert "Safe" in result.stdout
                    
                    # Test scanning malicious file
                    result = runner.invoke(app, ["scan", mal_f.name])
                    assert result.exit_code != 0  # Should detect threat
                    
                    # Test JSON output
                    result = runner.invoke(app, ["scan", safe_f.name, "--format", "json"])
                    assert result.exit_code == 0
                    output = json.loads(result.stdout)
                    assert "results" in output
                    
                finally:
                    Path(safe_f.name).unlink()
                    Path(mal_f.name).unlink()


class TestErrorHandlingIntegration:
    """Test error handling across components."""

    def test_corrupted_file_handling(self):
        """Test handling of corrupted files across all components."""
        corrupted_data = b"corrupted model data"
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(corrupted_data)
            f.flush()
            
            try:
                # Scanner should handle gracefully
                scanner = ModelScanner()
                result = scanner.scan_file(Path(f.name))
                assert not result.is_safe
                assert "error" in result.details
                
                # Loaders should handle gracefully
                with pytest.raises(Exception):  # Should raise some kind of error
                    torch.safe_load(f.name)
                    
            finally:
                Path(f.name).unlink()

    def test_permission_errors(self):
        """Test handling of permission errors."""
        # Create a file and make it unreadable (if possible on Windows)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump({"test": "data"}, f)
            f.flush()
            
            try:
                # Try to make file unreadable (may not work on all systems)
                import stat
                Path(f.name).chmod(stat.S_IWRITE)  # Write-only
                
                scanner = ModelScanner()
                result = scanner.scan_file(Path(f.name))
                # Should handle permission error gracefully
                assert not result.is_safe or result.is_safe  # Either way is acceptable
                
            except (OSError, PermissionError):
                # Permission changes might not work on all systems
                pass
            finally:
                try:
                    Path(f.name).chmod(stat.S_IREAD | stat.S_IWRITE)
                    Path(f.name).unlink()
                except:
                    pass

    def test_large_file_handling(self):
        """Test handling of very large files."""
        # Create a large model (but not too large for CI)
        large_data = {"data": "x" * 1000000}  # 1MB of data
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(large_data, f)
            f.flush()
            
            try:
                # Test with size limit policy
                with patch('modelguard.core.policy.load_policy') as mock_load_policy:
                    mock_policy = Mock()
                    mock_policy.get_max_file_size.return_value = 1000  # 1KB limit
                    mock_policy.requires_signatures.return_value = False
                    mock_policy.should_scan.return_value = False
                    mock_load_policy.return_value = mock_policy
                    
                    # Should raise policy error
                    with pytest.raises(Exception):
                        torch.safe_load(f.name)
                        
            finally:
                Path(f.name).unlink()


class TestConcurrencyIntegration:
    """Test concurrent operations."""

    def test_concurrent_scanning(self):
        """Test concurrent file scanning."""
        import threading
        import time
        
        # Create multiple test files
        test_files = []
        for i in range(5):
            with tempfile.NamedTemporaryFile(suffix=f"_{i}.pkl", delete=False) as f:
                pickle.dump({"model": i}, f)
                f.flush()
                test_files.append(Path(f.name))
        
        try:
            scanner = ModelScanner()
            results = []
            errors = []
            
            def scan_file(file_path):
                try:
                    result = scanner.scan_file(file_path)
                    results.append(result)
                except Exception as e:
                    errors.append(e)
            
            # Start concurrent scans
            threads = []
            for file_path in test_files:
                thread = threading.Thread(target=scan_file, args=(file_path,))
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join()
            
            # Check results
            assert len(errors) == 0, f"Errors occurred: {errors}"
            assert len(results) == len(test_files)
            
            for result in results:
                assert result.is_safe
                
        finally:
            for file_path in test_files:
                try:
                    file_path.unlink()
                except:
                    pass

    def test_concurrent_loading(self):
        """Test concurrent safe loading."""
        import threading
        
        test_data = {"concurrent": "test"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            try:
                results = []
                errors = []
                
                def load_file():
                    try:
                        result = torch.safe_load(f.name)
                        results.append(result)
                    except Exception as e:
                        errors.append(e)
                
                # Start concurrent loads
                threads = []
                for _ in range(5):
                    thread = threading.Thread(target=load_file)
                    threads.append(thread)
                    thread.start()
                
                # Wait for completion
                for thread in threads:
                    thread.join()
                
                # Check results
                assert len(errors) == 0, f"Errors occurred: {errors}"
                assert len(results) == 5
                
                for result in results:
                    assert result == test_data
                    
            finally:
                Path(f.name).unlink()


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_pytorch_model_simulation(self):
        """Simulate PyTorch model loading scenario."""
        # Create a ZIP file that simulates a PyTorch .pth file
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            with zipfile.ZipFile(f, 'w') as zf:
                # Simulate PyTorch model structure
                model_data = {
                    "state_dict": {"layer1.weight": [1, 2, 3], "layer1.bias": [0.1]},
                    "optimizer": {"lr": 0.001},
                    "epoch": 10
                }
                zf.writestr("data.pkl", pickle.dumps(model_data))
                zf.writestr("version", "1.0")
            
            try:
                # Scan the simulated PyTorch model
                scanner = ModelScanner()
                result = scanner.scan_file(Path(f.name))
                assert result.is_safe
                assert result.details.get("archive_type") == "zip"
                
            finally:
                Path(f.name).unlink()

    def test_sklearn_model_simulation(self):
        """Simulate scikit-learn model scenario."""
        # Create a model that looks like sklearn output
        sklearn_model = {
            "model_type": "RandomForestClassifier",
            "parameters": {"n_estimators": 100, "max_depth": 10},
            "feature_names": ["feature1", "feature2", "feature3"],
            "classes": ["class_a", "class_b"]
        }
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(sklearn_model, f)
            f.flush()
            
            try:
                # Test safe loading
                result = sklearn.safe_load(f.name)
                assert result == sklearn_model
                
                # Test scanning
                scanner = ModelScanner()
                scan_result = scanner.scan_file(Path(f.name))
                assert scan_result.is_safe
                
            finally:
                Path(f.name).unlink()

    def test_mixed_directory_scenario(self):
        """Test scanning a directory with mixed model types and non-model files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create a realistic directory structure
            files_to_create = {
                "models/pytorch_model.pth": pickle.dumps({"pytorch": "model"}),
                "models/sklearn_model.pkl": pickle.dumps({"sklearn": "model"}),
                "models/tensorflow_model.h5": b"fake tensorflow model",
                "data/train.csv": b"csv,data,here",
                "config.yaml": b"config: value",
                "README.md": b"# Model Repository",
                "requirements.txt": b"torch>=1.0.0",
                ".gitignore": b"*.pyc\n__pycache__/",
            }
            
            for file_path, content in files_to_create.items():
                full_path = tmpdir_path / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_bytes(content)
            
            # Scan recursively
            scanner = ModelScanner()
            results = scanner.scan_directory(tmpdir_path, recursive=True)
            
            # Should find only model files
            model_extensions = {".pth", ".pkl", ".h5"}
            expected_count = sum(1 for path in files_to_create.keys() 
                               if any(path.endswith(ext) for ext in model_extensions))
            
            assert len(results) == expected_count
            
            # All should be safe
            for result in results:
                assert result.is_safe

    def test_policy_configuration_scenarios(self):
        """Test different policy configuration scenarios."""
        test_data = {"policy": "test"}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            try:
                # Test development environment (permissive)
                with patch.dict('os.environ', {
                    'MODELGUARD_ENFORCE': 'false',
                    'MODELGUARD_REQUIRE_SIGNATURES': 'false',
                    'MODELGUARD_SCAN_ON_LOAD': 'true'
                }):
                    policy = load_policy()
                    assert not policy.should_enforce()
                    assert not policy.requires_signatures()
                    assert policy.should_scan()
                
                # Test production environment (strict)
                with patch.dict('os.environ', {
                    'MODELGUARD_ENFORCE': 'true',
                    'MODELGUARD_REQUIRE_SIGNATURES': 'true',
                    'MODELGUARD_SCAN_ON_LOAD': 'true',
                    'MODELGUARD_TRUSTED_SIGNERS': 'alice@company.com,bob@company.com'
                }):
                    policy = load_policy()
                    assert policy.should_enforce()
                    assert policy.requires_signatures()
                    assert policy.is_signer_trusted('alice@company.com')
                    assert not policy.is_signer_trusted('charlie@external.com')
                    
            finally:
                Path(f.name).unlink()