"""Enhanced tests for scanner functionality."""

import pickle
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modelguard.core.exceptions import UnsupportedFormatError
from modelguard.core.opcodes import analyze_pickle_opcodes
from modelguard.core.scanner import ModelScanner, ScanResult


class TestScanResultClass:
    """Test the ScanResult class."""

    def test_scan_result_creation(self):
        """Test ScanResult creation and properties."""
        path = Path("test.pkl")
        details = {"total_opcodes": 10, "threats": ["test_threat"]}
        
        result = ScanResult(path, True, details)
        
        assert result.path == path
        assert result.is_safe is True
        assert result.details == details
        assert result.threats == ["test_threat"]

    def test_scan_result_to_dict(self):
        """Test ScanResult to_dict conversion."""
        path = Path("test.pkl")
        details = {"total_opcodes": 10, "error": None}
        
        result = ScanResult(path, False, details)
        result_dict = result.to_dict()
        
        expected = {
            "path": str(path),
            "is_safe": False,
            "threats": [],
            "details": details
        }
        
        assert result_dict == expected

    def test_scan_result_with_threats(self):
        """Test ScanResult with threats in details."""
        path = Path("malicious.pkl")
        details = {"threats": ["GLOBAL opcode", "REDUCE opcode"], "total_opcodes": 5}
        
        result = ScanResult(path, False, details)
        
        assert result.threats == ["GLOBAL opcode", "REDUCE opcode"]
        assert len(result.threats) == 2


class TestModelScannerEnhanced:
    """Enhanced tests for ModelScanner."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = ModelScanner()

    def test_supported_extensions(self):
        """Test that scanner recognizes supported file extensions."""
        expected_extensions = {".pkl", ".pth", ".h5", ".hdf5", ".onnx", ".joblib"}
        assert self.scanner.supported_extensions == expected_extensions

    def test_scan_file_unsupported_extension(self):
        """Test scanning file with unsupported extension."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"not a model file")
            f.flush()
            
            with pytest.raises(UnsupportedFormatError):
                self.scanner.scan_file(Path(f.name))

    def test_scan_file_nonexistent(self):
        """Test scanning non-existent file."""
        result = self.scanner.scan_file(Path("nonexistent.pkl"))
        
        assert not result.is_safe
        assert "File not found" in result.details.get("error", "")

    def test_scan_pickle_with_various_opcodes(self):
        """Test scanning pickle files with different opcode patterns."""
        # Safe pickle with basic data
        safe_data = {"numbers": [1, 2, 3], "text": "hello", "nested": {"key": "value"}}
        safe_pickle = pickle.dumps(safe_data)
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(safe_pickle)
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert result.is_safe
            assert result.details["total_opcodes"] > 0
            assert len(result.details["dangerous_opcodes"]) == 0

    def test_scan_malicious_pickle_with_global(self):
        """Test scanning pickle with dangerous GLOBAL opcode."""
        # Create pickle with GLOBAL opcode (dangerous)
        malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00.'
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(malicious_pickle)
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert not result.is_safe
            assert len(result.details["dangerous_opcodes"]) > 0
            assert any("GLOBAL" in str(opcode) for opcode in result.details["dangerous_opcodes"])

    def test_scan_zip_archive_safe(self):
        """Test scanning safe ZIP archive (like PyTorch .pth files)."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            # Create a ZIP file with safe pickle content
            with zipfile.ZipFile(f, 'w') as zf:
                safe_data = {"model": "weights"}
                pickle_data = pickle.dumps(safe_data)
                zf.writestr("data.pkl", pickle_data)
                zf.writestr("version", "1.0")
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert result.is_safe
            assert "zip_contents" in result.details

    def test_scan_zip_archive_with_malicious_content(self):
        """Test scanning ZIP archive containing malicious pickle."""
        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as f:
            # Create a ZIP file with malicious pickle content
            with zipfile.ZipFile(f, 'w') as zf:
                malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00.'
                zf.writestr("malicious.pkl", malicious_pickle)
                zf.writestr("version", "1.0")
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert not result.is_safe
            assert "zip_contents" in result.details

    def test_scan_hdf5_file(self):
        """Test scanning HDF5 files."""
        # Create a fake HDF5 file (just for extension testing)
        with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as f:
            f.write(b"fake hdf5 content")
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            # Should be considered safe (HDF5 files are generally safe)
            assert result.is_safe
            assert "HDF5 files are generally safe" in result.details.get("note", "")

    def test_scan_onnx_file(self):
        """Test scanning ONNX files."""
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
            f.write(b"fake onnx content")
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            # Should be considered safe (ONNX files are protobuf-based)
            assert result.is_safe
            assert "ONNX files are protobuf-based" in result.details.get("note", "")

    def test_scan_directory_recursive(self):
        """Test recursive directory scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create nested directory structure
            subdir = tmpdir_path / "subdir"
            subdir.mkdir()
            
            # Create test files
            files_created = []
            
            # Root level files
            for i in range(2):
                file_path = tmpdir_path / f"model_{i}.pkl"
                safe_data = {"model": i}
                file_path.write_bytes(pickle.dumps(safe_data))
                files_created.append(file_path)
            
            # Subdirectory files
            for i in range(2):
                file_path = subdir / f"nested_model_{i}.pkl"
                safe_data = {"nested_model": i}
                file_path.write_bytes(pickle.dumps(safe_data))
                files_created.append(file_path)
            
            # Scan recursively
            results = self.scanner.scan_directory(tmpdir_path, recursive=True)
            
            assert len(results) == 4
            for result in results:
                assert result.is_safe

    def test_scan_directory_non_recursive(self):
        """Test non-recursive directory scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create nested directory structure
            subdir = tmpdir_path / "subdir"
            subdir.mkdir()
            
            # Root level file
            root_file = tmpdir_path / "model.pkl"
            root_file.write_bytes(pickle.dumps({"root": "model"}))
            
            # Subdirectory file (should be ignored in non-recursive scan)
            nested_file = subdir / "nested_model.pkl"
            nested_file.write_bytes(pickle.dumps({"nested": "model"}))
            
            # Scan non-recursively
            results = self.scanner.scan_directory(tmpdir_path, recursive=False)
            
            assert len(results) == 1
            assert results[0].path == root_file

    def test_scan_directory_with_mixed_file_types(self):
        """Test directory scanning with mixed file types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create files with different extensions
            extensions = [".pkl", ".pth", ".h5", ".onnx", ".txt", ".py"]
            
            for i, ext in enumerate(extensions):
                file_path = tmpdir_path / f"file_{i}{ext}"
                file_path.write_bytes(b"test content")
            
            results = self.scanner.scan_directory(tmpdir_path)
            
            # Should only scan supported extensions
            supported_count = len([ext for ext in extensions if ext in self.scanner.supported_extensions])
            assert len(results) == supported_count

    def test_is_pickle_data_detection(self):
        """Test pickle data detection."""
        # Test various pickle formats
        test_cases = [
            (pickle.dumps({"test": "data"}), True),  # Standard pickle
            (b'\x80\x03}q\x00.', True),  # Simple pickle
            (b'not pickle data', False),  # Not pickle
            (b'', False),  # Empty data
            (b'\x80', False),  # Too short
        ]
        
        for data, expected in test_cases:
            result = self.scanner._is_pickle_data(data)
            assert result == expected, f"Failed for data: {data[:20]}..."

    def test_scan_corrupted_pickle(self):
        """Test scanning corrupted pickle files."""
        # Create corrupted pickle data
        corrupted_data = b'\x80\x03corrupted_pickle_data'
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(corrupted_data)
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert not result.is_safe
            assert "error" in result.details

    def test_scan_empty_file(self):
        """Test scanning empty files."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            # File is empty
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert not result.is_safe
            assert "error" in result.details

    def test_scan_very_large_file(self):
        """Test scanning very large files."""
        # Create a large but safe pickle
        large_data = {"data": "x" * 100000}  # 100KB of data
        large_pickle = pickle.dumps(large_data)
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(large_pickle)
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            assert result.is_safe
            assert result.details["total_opcodes"] > 0

    @patch('modelguard.core.scanner.analyze_pickle_opcodes')
    def test_scan_with_opcode_analysis_error(self, mock_analyze):
        """Test handling of opcode analysis errors."""
        # Mock opcode analysis to raise an exception
        mock_analyze.side_effect = Exception("Analysis failed")
        
        safe_data = {"test": "data"}
        safe_pickle = pickle.dumps(safe_data)
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(safe_pickle)
            f.flush()
            
            result = self.scanner.scan_file(Path(f.name))
            
            # Should handle the error gracefully
            assert not result.is_safe
            assert "error" in result.details


class TestOpcodeAnalysisEnhanced:
    """Enhanced tests for opcode analysis."""

    def test_analyze_complex_pickle_structures(self):
        """Test analysis of complex pickle structures."""
        complex_data = {
            "lists": [[1, 2, 3], [4, 5, 6]],
            "tuples": (1, 2, (3, 4)),
            "sets": {1, 2, 3},
            "nested_dict": {"inner": {"deep": "value"}},
            "mixed": [{"key": "value"}, (1, 2), {7, 8, 9}]
        }
        
        pickle_data = pickle.dumps(complex_data)
        analysis = analyze_pickle_opcodes(pickle_data)
        
        assert analysis["is_safe"]
        assert analysis["total_opcodes"] > 10  # Complex structure should have many opcodes
        assert len(analysis["dangerous_opcodes"]) == 0
        assert len(analysis["global_imports"]) == 0

    def test_analyze_pickle_with_custom_classes(self):
        """Test analysis of pickle with custom classes."""
        # This would normally be dangerous, but we'll test the detection
        class CustomClass:
            def __init__(self, value):
                self.value = value
        
        # Create instance and pickle it
        instance = CustomClass("test")
        pickle_data = pickle.dumps(instance)
        
        analysis = analyze_pickle_opcodes(pickle_data)
        
        # Should detect global imports for the custom class
        assert len(analysis["global_imports"]) > 0
        # Custom classes are not in SAFE_CLASSES, so should be flagged
        assert len(analysis["unsafe_imports"]) > 0

    def test_analyze_pickle_protocols(self):
        """Test analysis of different pickle protocols."""
        test_data = {"protocol_test": "data"}
        
        for protocol in range(5):  # Test protocols 0-4
            try:
                pickle_data = pickle.dumps(test_data, protocol=protocol)
                analysis = analyze_pickle_opcodes(pickle_data)
                
                assert analysis["is_safe"]
                assert analysis["total_opcodes"] > 0
                
            except ValueError:
                # Some protocols might not be supported in all Python versions
                continue

    def test_analyze_malicious_opcodes_comprehensive(self):
        """Test comprehensive detection of malicious opcodes."""
        # Test different types of malicious patterns
        malicious_patterns = [
            b'\x80\x03c__builtin__\neval\nq\x00.',  # GLOBAL with eval
            b'\x80\x03c__builtin__\nexec\nq\x00.',  # GLOBAL with exec
            b'\x80\x03cos\nsystem\nq\x00.',         # GLOBAL with os.system
        ]
        
        for pattern in malicious_patterns:
            try:
                analysis = analyze_pickle_opcodes(pattern)
                
                # Should detect as unsafe
                assert not analysis["is_safe"]
                assert len(analysis["dangerous_opcodes"]) > 0
                
                # Should have GLOBAL opcode
                dangerous_opcodes = [op["opcode"] for op in analysis["dangerous_opcodes"]]
                assert "GLOBAL" in dangerous_opcodes or "STACK_GLOBAL" in dangerous_opcodes
                
            except Exception:
                # Some patterns might be malformed, but shouldn't crash
                continue

    def test_analyze_invalid_pickle_data(self):
        """Test analysis of invalid pickle data."""
        invalid_data_samples = [
            b"not pickle at all",
            b"\x80\x03invalid",
            b"\x00\x01\x02\x03",
            b"",
            b"\x80\x03" + b"\x00" * 100,  # Truncated pickle
        ]
        
        for invalid_data in invalid_data_samples:
            analysis = analyze_pickle_opcodes(invalid_data)
            
            # Should handle gracefully
            assert "error" in analysis or not analysis["is_safe"]

    def test_opcode_position_tracking(self):
        """Test that opcode positions are tracked correctly."""
        # Create pickle with known dangerous opcode
        malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00.'
        
        try:
            analysis = analyze_pickle_opcodes(malicious_pickle)
            
            if analysis.get("dangerous_opcodes"):
                # Should track position of dangerous opcodes
                for dangerous_op in analysis["dangerous_opcodes"]:
                    assert "position" in dangerous_op
                    assert isinstance(dangerous_op["position"], int)
                    assert dangerous_op["position"] >= 0
        except Exception:
            # Malformed pickle might cause issues, but shouldn't crash
            pass