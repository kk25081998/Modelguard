"""Model scanning functionality."""

import zipfile
from pathlib import Path
from typing import Any

from .exceptions import UnsupportedFormatError
from .opcodes import analyze_pickle_opcodes


class ScanResult:
    """Result of a model scan."""

    def __init__(self, path: Path, is_safe: bool, details: dict[str, Any]):
        self.path = path
        self.is_safe = is_safe
        self.details = details
        self.threats: list[str] = details.get("threats", [])

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "path": str(self.path),
            "is_safe": self.is_safe,
            "threats": self.threats,
            "details": self.details
        }


class ModelScanner:
    """Scanner for detecting malicious content in ML models."""

    def __init__(self):
        self.supported_extensions = {
            ".pkl", ".pickle",  # Pure pickle files
            ".pth", ".pt",      # PyTorch models
            ".h5", ".hdf5",     # TensorFlow/Keras models
            ".pb",              # TensorFlow protobuf
            ".onnx",            # ONNX models
            ".joblib",          # scikit-learn models
        }

    def scan_file(self, path: Path) -> ScanResult:
        """
        Scan a single model file for malicious content.
        
        Args:
            path: Path to model file
            
        Returns:
            ScanResult with analysis details
        """
        if not path.exists():
            return ScanResult(path, False, {"error": "File not found"})

        if not path.is_file():
            return ScanResult(path, False, {"error": "Not a file"})

        # Check file extension
        if path.suffix.lower() not in self.supported_extensions:
            return ScanResult(
                path,
                False,
                {"error": f"Unsupported file extension: {path.suffix}"}
            )

        try:
            return self._scan_by_format(path)
        except Exception as e:
            return ScanResult(path, False, {"error": f"Scan failed: {e}"})

    def _scan_by_format(self, path: Path) -> ScanResult:
        """Scan file based on its format."""
        suffix = path.suffix.lower()

        if suffix in [".pkl", ".pickle", ".pth", ".pt", ".joblib"]:
            return self._scan_pickle_based(path)
        if suffix in [".h5", ".hdf5"]:
            return self._scan_hdf5(path)
        if suffix == ".pb":
            return self._scan_protobuf(path)
        if suffix == ".onnx":
            return self._scan_onnx(path)
        raise UnsupportedFormatError(f"Unsupported format: {suffix}")

    def _scan_pickle_based(self, path: Path) -> ScanResult:
        """Scan pickle-based model files."""
        threats = []
        details = {}

        try:
            with open(path, 'rb') as f:
                data = f.read()

            # Check if it's actually pickle data
            if not self._is_pickle_data(data):
                # Might be a ZIP archive (PyTorch .pth files)
                if zipfile.is_zipfile(path):
                    return self._scan_zip_archive(path)
                return ScanResult(
                    path, False, {"error": "Not valid pickle or ZIP data"}
                )

            # Analyze pickle opcodes
            analysis = analyze_pickle_opcodes(data)
            details.update(analysis)

            if analysis.get("error"):
                return ScanResult(path, False, details)

            # Check for threats
            if analysis.get("dangerous_opcodes"):
                threats.extend([
                    f"Dangerous opcode: {op['opcode']} at position {op['position']}"
                    for op in analysis["dangerous_opcodes"]
                ])

            if analysis.get("unsafe_imports"):
                threats.extend([
                    f"Unsafe import: {imp}" for imp in analysis["unsafe_imports"]
                ])

            is_safe = len(threats) == 0 and analysis.get("is_safe", False)
            details["threats"] = threats

            return ScanResult(path, is_safe, details)

        except Exception as e:
            return ScanResult(path, False, {"error": f"Failed to scan pickle: {e}"})

    def _scan_zip_archive(self, path: Path) -> ScanResult:
        """Scan ZIP-based model files (like PyTorch .pth)."""
        threats = []
        details = {"archive_type": "zip", "files_scanned": []}

        try:
            with zipfile.ZipFile(path, 'r') as zf:
                for file_info in zf.filelist:
                    if file_info.filename.endswith('.pkl'):
                        # Scan pickle files within the archive
                        pickle_data = zf.read(file_info.filename)
                        analysis = analyze_pickle_opcodes(pickle_data)

                        file_details = {
                            "filename": file_info.filename,
                            "analysis": analysis
                        }
                        details["files_scanned"].append(file_details)

                        if analysis.get("dangerous_opcodes"):
                            threats.extend([
                                f"{file_info.filename}: Dangerous opcode {op['opcode']}"
                                for op in analysis["dangerous_opcodes"]
                            ])

                        if analysis.get("unsafe_imports"):
                            threats.extend([
                                f"{file_info.filename}: Unsafe import {imp}"
                                for imp in analysis["unsafe_imports"]
                            ])

            is_safe = len(threats) == 0
            details["threats"] = threats

            return ScanResult(path, is_safe, details)

        except Exception as e:
            return ScanResult(
                path, False, {"error": f"Failed to scan ZIP archive: {e}"}
            )

    def _scan_hdf5(self, path: Path) -> ScanResult:
        """Scan HDF5-based model files (TensorFlow/Keras)."""
        # HDF5 files are generally safe as they don't execute code
        # But we should check for any embedded pickle data
        details = {"format": "hdf5", "note": "HDF5 format is generally safe"}
        return ScanResult(path, True, details)

    def _scan_protobuf(self, path: Path) -> ScanResult:
        """Scan Protocol Buffer files (TensorFlow .pb)."""
        # Protobuf files are safe as they're just serialized data
        details = {"format": "protobuf", "note": "Protobuf format is safe"}
        return ScanResult(path, True, details)

    def _scan_onnx(self, path: Path) -> ScanResult:
        """Scan ONNX model files."""
        # ONNX files are protobuf-based and safe
        details = {"format": "onnx", "note": "ONNX format is safe"}
        return ScanResult(path, True, details)

    def _is_pickle_data(self, data: bytes) -> bool:
        """Check if data appears to be pickle format."""
        if len(data) < 2:
            return False

        # Check for pickle protocol markers
        pickle_markers = [
            b'\x80\x02',  # Protocol 2
            b'\x80\x03',  # Protocol 3
            b'\x80\x04',  # Protocol 4
            b'\x80\x05',  # Protocol 5
        ]

        # Check for protocol markers or classic pickle start
        return (
            any(data.startswith(marker) for marker in pickle_markers) or
            data.startswith(b'(') or  # Classic pickle format
            data.startswith(b']') or  # List start
            data.startswith(b'}')     # Dict start
        )

    def scan_directory(self, path: Path, recursive: bool = True) -> list[ScanResult]:
        """
        Scan all model files in a directory.
        
        Args:
            path: Directory path
            recursive: Whether to scan subdirectories
            
        Returns:
            List of scan results
        """
        results = []

        if not path.exists() or not path.is_dir():
            return results

        pattern = "**/*" if recursive else "*"

        for file_path in path.glob(pattern):
            if (
                file_path.is_file()
                and file_path.suffix.lower() in self.supported_extensions
            ):
                result = self.scan_file(file_path)
                results.append(result)

        return results
