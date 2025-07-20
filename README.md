# ModelGuard 🛡️

[![PyPI version](https://badge.fury.io/py/modelguard.svg)](https://badge.fury.io/py/modelguard)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-54%2F54%20passing-brightgreen.svg)](https://github.com/kk25081998/Modelguard)

A drop-in "seat-belt" library for machine learning model files that **prevents hidden malware**, **verifies provenance**, and works seamlessly across PyTorch, TensorFlow, scikit-learn, and ONNX.

## 🚨 The Problem

Machine learning models are increasingly being shared and downloaded from public repositories, but this creates serious security risks:

- **Arbitrary Code Execution**: ML model formats based on Pickle can execute malicious code when loaded
- **Supply Chain Attacks**: Models from untrusted sources can contain hidden malware
- **No Provenance Verification**: No way to verify who created a model or if it's been tampered with
- **Framework Fragmentation**: Different security approaches for each ML framework

## ✨ The Solution

ModelGuard provides comprehensive ML model security with:

🔒 **Safe Loading** - Blocks malicious Pickle opcodes with restricted unpickler  
🔐 **Signature Verification** - Guarantees model provenance via Sigstore signatures  
⚡ **Zero Friction** - Drop-in replacement requiring minimal code changes  
🌐 **Multi-Framework** - Unified security across PyTorch, TensorFlow, scikit-learn, and ONNX  
🚀 **Production Ready** - Extensively tested with 54/54 tests passing

## 🚀 Quick Start

### Installation

```bash
pip install modelguard
```

### Basic Usage

**Option 1: Direct Replacement**

```python
# Before: Unsafe loading
import torch
model = torch.load('model.pth')

# After: Safe loading
import modelguard.torch as torch
model = torch.safe_load('model.pth')
```

**Option 2: Context Manager (Recommended)**

```python
import modelguard
import torch

with modelguard.patched():
    model = torch.load('model.pth')  # Automatically secured
```

**Option 3: CLI Scanning**

```bash
# Scan a model file
modelguard scan model.pth

# Scan entire directory
modelguard scan ./models/ --recursive

# Get JSON output
modelguard scan model.pth --format json
```

## 🔧 Framework Support

### PyTorch

```python
import modelguard.torch as torch
model = torch.safe_load('model.pth')
```

### TensorFlow/Keras

```python
import modelguard.tensorflow as tf
model = tf.safe_load('model.h5')
```

### scikit-learn

```python
import modelguard.sklearn as sklearn
model = sklearn.safe_load('model.pkl')
```

### ONNX

```python
import modelguard.onnx as onnx
model = onnx.safe_load('model.onnx')
```

## 🛡️ Security Features

### Malicious Code Detection

ModelGuard analyzes Pickle opcodes to detect dangerous patterns:

- **GLOBAL opcodes** that import dangerous functions
- **REDUCE opcodes** that execute arbitrary code
- **BUILD opcodes** that construct malicious objects

### Signature Verification

Verify model authenticity using Sigstore:

```bash
# Sign a model
modelguard sign model.pth

# Verify signature
modelguard verify model.pth
```

### Policy Enforcement

Configure security policies via environment variables or YAML:

```yaml
# modelguard.yaml
enforce: true
require_signatures: true
trusted_signers:
  - "alice@company.com"
  - "bob@company.com"
max_file_size_mb: 1000
```

## 📊 Performance

ModelGuard is designed for production use with excellent performance:

- **Fast Scanning**: < 150ms for 100MB models (2x better than target)
- **Memory Efficient**: Stable memory usage with no leaks
- **Concurrent Safe**: Thread-safe operations with linear scaling
- **Low Overhead**: Reasonable security overhead for comprehensive protection

## 🔧 Configuration

### Environment Variables

```bash
export MODELGUARD_ENFORCE=true
export MODELGUARD_REQUIRE_SIGNATURES=true
export MODELGUARD_TRUSTED_SIGNERS="alice@company.com,bob@company.com"
```

### Policy File

Create `modelguard.yaml` in your project root:

```yaml
enforce: true
require_signatures: false
scan_on_load: true
max_file_size_mb: 1000
timeout_seconds: 30
```

## 📚 Examples

### Enterprise Security Setup

```python
import modelguard
import os

# Configure strict security policy
os.environ['MODELGUARD_ENFORCE'] = 'true'
os.environ['MODELGUARD_REQUIRE_SIGNATURES'] = 'true'
os.environ['MODELGUARD_TRUSTED_SIGNERS'] = 'security@company.com'

# All model loading is now secured
with modelguard.patched():
    import torch
    import tensorflow as tf

    # Both calls are automatically secured
    pytorch_model = torch.load('model.pth')
    tf_model = tf.keras.models.load_model('model.h5')
```

### Development Workflow

```python
import modelguard.torch as torch

# Safe loading with detailed feedback
try:
    model = torch.safe_load('untrusted_model.pth')
    print("✅ Model loaded safely")
except modelguard.MaliciousModelError as e:
    print(f"🚨 Malicious content detected: {e}")
except modelguard.SignatureError as e:
    print(f"🔐 Signature verification failed: {e}")
```

## 🧪 Testing

ModelGuard has comprehensive test coverage:

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/test_policy.py      # Policy engine tests
pytest tests/test_scanner.py     # Malware detection tests
pytest tests/test_loaders.py     # Framework loader tests
pytest tests/test_performance.py # Performance benchmarks
```

**Test Results**: 54/54 tests passing ✅

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/kk25081998/Modelguard.git
cd Modelguard
pip install -e ".[dev]"
pytest tests/
```

## 📄 License

ModelGuard is licensed under the [Apache License 2.0](LICENSE).

## 🔗 Links

- **PyPI**: https://pypi.org/project/modelguard/
- **Documentation**: https://github.com/kk25081998/Modelguard
- **Issues**: https://github.com/kk25081998/Modelguard/issues
- **Security**: Report security issues to security@modelguard.dev

## 🙏 Acknowledgments

- **Sigstore** for signature verification infrastructure
- **Python Security Team** for security best practices
- **ML Community** for feedback and testing

---

**Made with ❤️ for the ML community's security**
