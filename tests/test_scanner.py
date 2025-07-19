"""Tests for model scanner functionality."""

import pickle
import tempfile
from pathlib import Path
import pytest

from modelguard.core.scanner import ModelScanner
from modelguard.core.opcodes import analyze_pickle_opcodes


class TestModelScanner:
    """Test cases for ModelScanner."""
    
    def test_scan_safe_pickle(self):
        """Test scanning a safe pickle file."""
        scanner = ModelScanner()
        
        # Create a safe pickle file
        safe_data = {"model": [1, 2, 3], "weights": {"layer1": [0.1, 0.2]}}
        
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            pickle.dump(safe_data, f)
            temp_path = Path(f.name)
        
        try:
            result = scanner.scan_file(temp_path)
            assert result.is_safe
            assert len(result.threats) == 0
        finally:
            temp_path.unlink()
    
    def test_scan_malicious_pickle(self):
        """Test scanning a malicious pickle file."""
        scanner = ModelScanner()
        
        # Create malicious pickle with GLOBAL opcode
        malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00X\x0e\x00\x00\x00print("pwned")q\x01\x85q\x02Rq\x03.'
        
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(malicious_pickle)
            temp_path = Path(f.name)
        
        try:
            result = scanner.scan_file(temp_path)
            assert not result.is_safe
            assert len(result.threats) > 0
            assert any("Dangerous opcode" in threat for threat in result.threats)
        finally:
            temp_path.unlink()
    
    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist."""
        scanner = ModelScanner()
        result = scanner.scan_file(Path("nonexistent.pkl"))
        
        assert not result.is_safe
        assert "File not found" in result.details.get("error", "")
    
    def test_scan_unsupported_format(self):
        """Test scanning an unsupported file format."""
        scanner = ModelScanner()
        
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"not a model file")
            temp_path = Path(f.name)
        
        try:
            result = scanner.scan_file(temp_path)
            assert not result.is_safe
            assert "Unsupported file extension" in result.details.get("error", "")
        finally:
            temp_path.unlink()


class TestOpcodeAnalysis:
    """Test cases for pickle opcode analysis."""
    
    def test_analyze_safe_opcodes(self):
        """Test analysis of safe pickle opcodes."""
        safe_data = [1, 2, 3, "hello"]
        pickle_bytes = pickle.dumps(safe_data)
        
        analysis = analyze_pickle_opcodes(pickle_bytes)
        
        assert analysis["is_safe"]
        assert len(analysis["dangerous_opcodes"]) == 0
        assert len(analysis["unsafe_imports"]) == 0
    
    def test_analyze_dangerous_opcodes(self):
        """Test analysis of dangerous pickle opcodes."""
        # Create a proper malicious pickle with GLOBAL opcode
        import pickle
        import io
        
        # Create pickle data that uses GLOBAL opcode
        buffer = io.BytesIO()
        pickler = pickle.Pickler(buffer)
        
        # This will create a pickle with GLOBAL opcode for eval function
        try:
            pickler.dump(eval)  # This creates GLOBAL opcode
            malicious_pickle = buffer.getvalue()
        except:
            # Fallback: create minimal pickle with GLOBAL manually
            malicious_pickle = b'\x80\x03c__builtin__\neval\nq\x00.'
        
        analysis = analyze_pickle_opcodes(malicious_pickle)
        
        assert not analysis["is_safe"]
        assert len(analysis["dangerous_opcodes"]) > 0
        # Should find either GLOBAL or STACK_GLOBAL (both are dangerous)
        dangerous_opcode = analysis["dangerous_opcodes"][0]["opcode"]
        assert dangerous_opcode in ["GLOBAL", "STACK_GLOBAL"]
    
    def test_analyze_invalid_pickle(self):
        """Test analysis of invalid pickle data."""
        invalid_data = b"not pickle data"
        
        analysis = analyze_pickle_opcodes(invalid_data)
        
        assert not analysis["is_safe"]
        assert "error" in analysis