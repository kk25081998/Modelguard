"""Signature verification using Sigstore."""

from pathlib import Path
from typing import Any, Optional

from .exceptions import SignatureError

try:
    from sigstore import sign, verify
    from sigstore.models import Bundle
    SIGSTORE_AVAILABLE = True
except ImportError:
    SIGSTORE_AVAILABLE = False


class SignatureManager:
    """Manages model signatures using Sigstore."""

    def __init__(self):
        pass

    def sign_model(self, model_path: Path, identity: Optional[str] = None) -> Path:
        """
        Sign a model file using Sigstore.
        
        Args:
            model_path: Path to model file
            identity: Signer identity (email)
            
        Returns:
            Path to signature file
        """
        if not SIGSTORE_AVAILABLE:
            raise SignatureError(
                "Sigstore not available. Install with: pip install sigstore"
            )

        if not model_path.exists():
            raise SignatureError(f"Model file not found: {model_path}")

        signature_path = model_path.with_suffix(model_path.suffix + ".sig")

        try:
            # Read model data
            with model_path.open('rb') as f:
                model_data = f.read()

            # Sign using Sigstore
            bundle = sign.sign_dsse(
                input_=model_data,
                identity_token=None,  # Will use ambient OIDC
                sign_bundle=True
            )

            # Save signature bundle
            with signature_path.open('w') as f:
                f.write(bundle.to_json())

            return signature_path

        except Exception as e:
            msg = f"Failed to sign model: {e}"
            raise SignatureError(msg) from e

    def verify_signature(
        self, model_path: Path, signature_path: Optional[Path] = None
    ) -> dict[str, Any]:
        """
        Verify a model's signature.
        
        Args:
            model_path: Path to model file
            signature_path: Path to signature file (optional, will auto-detect)
            
        Returns:
            Verification result dictionary
        """
        if not SIGSTORE_AVAILABLE:
            return {
                "verified": False,
                "error": "Sigstore not available. Install with: pip install sigstore",
                "signature_path": str(signature_path) if signature_path else "unknown"
            }

        if not model_path.exists():
            raise SignatureError(f"Model file not found: {model_path}")

        # Auto-detect signature file if not provided
        if signature_path is None:
            signature_path = model_path.with_suffix(model_path.suffix + ".sig")

        if not signature_path.exists():
            return {
                "verified": False,
                "error": "Signature file not found",
                "signature_path": str(signature_path)
            }

        try:
            # Read model data
            with model_path.open('rb') as f:
                model_data = f.read()

            # Read signature bundle
            with signature_path.open() as f:
                bundle_json = f.read()

            bundle = Bundle.from_json(bundle_json)

            # Verify signature
            verify.verify_dsse(
                input_=model_data,
                bundle=bundle,
                expected_type="application/vnd.in-toto+json"
            )

            # Extract signer information
            signer_info = self._extract_signer_info(bundle)

            return {
                "verified": True,
                "signer": signer_info,
                "signature_path": str(signature_path)
            }

        except Exception as e:
            return {
                "verified": False,
                "error": str(e),
                "signature_path": str(signature_path)
            }

    def _extract_signer_info(self, bundle) -> dict[str, Any]:
        """Extract signer information from signature bundle."""
        try:
            # This is a simplified extraction - real implementation would
            # parse the certificate and extract proper identity information
            return {
                "identity": "unknown",  # Would extract from certificate
                "issuer": "unknown",    # Would extract from certificate
                "timestamp": None       # Would extract timestamp
            }
        except Exception:
            return {"identity": "unknown", "issuer": "unknown", "timestamp": None}

    def has_signature(self, model_path: Path) -> bool:
        """Check if a model has an associated signature file."""
        signature_path = model_path.with_suffix(model_path.suffix + ".sig")
        return signature_path.exists()
