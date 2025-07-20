"""Tests for signature management functionality."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modelguard.core.exceptions import SignatureError
from modelguard.core.signature import SignatureManager


class TestSignatureManager:
    """Test signature management functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.signature_manager = SignatureManager()

    def test_has_signature_nonexistent_file(self):
        """Test has_signature with non-existent file."""
        result = self.signature_manager.has_signature(Path("nonexistent.pkl"))
        assert not result

    def test_has_signature_no_signature_file(self):
        """Test has_signature when signature file doesn't exist."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            result = self.signature_manager.has_signature(Path(f.name))
            assert not result

    def test_has_signature_with_signature_file(self):
        """Test has_signature when signature file exists."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            # Create corresponding signature file
            sig_path = Path(f.name + ".sig")
            sig_path.write_text('{"fake": "signature"}')
            
            try:
                result = self.signature_manager.has_signature(Path(f.name))
                assert result
            finally:
                sig_path.unlink()

    def test_sign_model_sigstore_not_available(self):
        """Test signing when Sigstore is not available."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            # Mock SIGSTORE_AVAILABLE to False
            with patch('modelguard.core.signature.SIGSTORE_AVAILABLE', False):
                with pytest.raises(SignatureError, match="Sigstore not available"):
                    self.signature_manager.sign_model(Path(f.name))

    def test_sign_model_nonexistent_file(self):
        """Test signing non-existent file."""
        with patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True):
            with pytest.raises(SignatureError, match="Model file not found"):
                self.signature_manager.sign_model(Path("nonexistent.pkl"))

    @patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True)
    @patch('modelguard.core.signature.sign')
    def test_sign_model_success(self, mock_sign):
        """Test successful model signing."""
        # Mock the sigstore sign function
        mock_bundle = Mock()
        mock_bundle.to_json.return_value = '{"signature": "data"}'
        mock_sign.sign_dsse.return_value = mock_bundle
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            result = self.signature_manager.sign_model(Path(f.name))
            
            # Should return signature file path
            expected_sig_path = Path(f.name + ".sig")
            assert result == expected_sig_path
            
            # Signature file should be created
            assert expected_sig_path.exists()
            
            # Should contain the mocked signature data
            sig_content = expected_sig_path.read_text()
            assert sig_content == '{"signature": "data"}'
            
            # Clean up
            expected_sig_path.unlink()

    @patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True)
    @patch('modelguard.core.signature.sign')
    def test_sign_model_signing_failure(self, mock_sign):
        """Test handling of signing failures."""
        # Mock signing to raise an exception
        mock_sign.sign_dsse.side_effect = Exception("Signing failed")
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            with pytest.raises(SignatureError, match="Failed to sign model"):
                self.signature_manager.sign_model(Path(f.name))

    def test_verify_signature_nonexistent_model(self):
        """Test verifying signature for non-existent model."""
        with pytest.raises(SignatureError, match="Model file not found"):
            self.signature_manager.verify_signature(Path("nonexistent.pkl"))

    def test_verify_signature_no_signature_file(self):
        """Test verifying when no signature file exists."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            result = self.signature_manager.verify_signature(Path(f.name))
            
            assert not result["verified"]
            assert "No signature file found" in result["error"]

    @patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True)
    @patch('modelguard.core.signature.verify')
    def test_verify_signature_success(self, mock_verify):
        """Test successful signature verification."""
        # Mock the verification result
        mock_verify.verify_dsse.return_value = True
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            # Create signature file
            sig_path = Path(f.name + ".sig")
            sig_path.write_text('{"fake": "signature"}')
            
            try:
                result = self.signature_manager.verify_signature(Path(f.name))
                
                assert result["verified"]
                assert result["signature_path"] == str(sig_path)
                assert "signer" in result
            finally:
                sig_path.unlink()

    @patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True)
    @patch('modelguard.core.signature.verify')
    def test_verify_signature_failure(self, mock_verify):
        """Test signature verification failure."""
        # Mock verification to fail
        mock_verify.verify_dsse.side_effect = Exception("Verification failed")
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            # Create signature file
            sig_path = Path(f.name + ".sig")
            sig_path.write_text('{"fake": "signature"}')
            
            try:
                result = self.signature_manager.verify_signature(Path(f.name))
                
                assert not result["verified"]
                assert "Verification failed" in result["error"]
            finally:
                sig_path.unlink()

    def test_verify_signature_custom_signature_path(self):
        """Test verification with custom signature path."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            # Create custom signature file
            with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sig_f:
                sig_f.write(b'{"custom": "signature"}')
                sig_f.flush()
                
                result = self.signature_manager.verify_signature(
                    Path(f.name), 
                    Path(sig_f.name)
                )
                
                assert not result["verified"]  # Will fail due to mocked verification
                assert result["signature_path"] == sig_f.name

    def test_extract_signer_info_basic(self):
        """Test basic signer info extraction."""
        # This method currently returns placeholder data
        result = self.signature_manager._extract_signer_info(None)
        
        assert "identity" in result
        assert "email" in result
        assert result["identity"] == "unknown"

    def test_signature_file_naming_convention(self):
        """Test that signature files follow the .sig naming convention."""
        test_files = [
            "model.pkl",
            "model.pth", 
            "model.h5",
            "model.onnx",
            "model.joblib"
        ]
        
        for filename in test_files:
            with tempfile.NamedTemporaryFile(suffix=f".{filename.split('.')[-1]}", delete=False) as f:
                f.write(b"test data")
                f.flush()
                
                model_path = Path(f.name)
                expected_sig_path = model_path.with_suffix(model_path.suffix + ".sig")
                
                # Test that has_signature looks for the right file
                assert not self.signature_manager.has_signature(model_path)
                
                # Create the signature file
                expected_sig_path.write_text('{"test": "signature"}')
                
                try:
                    assert self.signature_manager.has_signature(model_path)
                finally:
                    expected_sig_path.unlink()


class TestSignatureIntegration:
    """Integration tests for signature functionality."""

    def test_sign_and_verify_workflow(self):
        """Test the complete sign and verify workflow."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test model data")
            f.flush()
            
            signature_manager = SignatureManager()
            
            # Initially no signature
            assert not signature_manager.has_signature(Path(f.name))
            
            # Mock successful signing
            with patch('modelguard.core.signature.SIGSTORE_AVAILABLE', True):
                with patch('modelguard.core.signature.sign') as mock_sign:
                    mock_bundle = Mock()
                    mock_bundle.to_json.return_value = '{"test": "signature"}'
                    mock_sign.sign_dsse.return_value = mock_bundle
                    
                    # Sign the model
                    sig_path = signature_manager.sign_model(Path(f.name))
                    
                    try:
                        # Now should have signature
                        assert signature_manager.has_signature(Path(f.name))
                        assert sig_path.exists()
                        
                        # Mock successful verification
                        with patch('modelguard.core.signature.verify') as mock_verify:
                            mock_verify.verify_dsse.return_value = True
                            
                            # Verify the signature
                            result = signature_manager.verify_signature(Path(f.name))
                            assert result["verified"]
                            
                    finally:
                        # Clean up
                        if sig_path.exists():
                            sig_path.unlink()

    def test_multiple_signature_formats(self):
        """Test handling of different signature file formats."""
        signature_contents = [
            '{"format": "dsse", "payload": "test"}',
            '{"format": "simple", "signature": "abcd1234"}',
            'invalid json content',
            ''
        ]
        
        for i, content in enumerate(signature_contents):
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(b"test model data")
                f.flush()
                
                # Create signature file with different content
                sig_path = Path(f.name + ".sig")
                sig_path.write_text(content)
                
                try:
                    signature_manager = SignatureManager()
                    
                    # Should detect signature exists
                    assert signature_manager.has_signature(Path(f.name))
                    
                    # Verification will fail for invalid content, but shouldn't crash
                    result = signature_manager.verify_signature(Path(f.name))
                    # We expect most of these to fail verification, but not crash
                    assert "verified" in result
                    
                finally:
                    sig_path.unlink()