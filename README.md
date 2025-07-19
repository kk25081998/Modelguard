# Modelguard

A drop-in "seat-belt" library for machine-learning model files that prevents hidden malware, verifies provenance, and works the same way across PyTorch, TensorFlow, scikit-learn, and ONNX.

## 🚨 Problem

- ML model formats based on Pickle can execute arbitrary code on load
- Engineers routinely download and load models from public repositories without authenticity checks
- Existing tools solve only slices of the problem and aren't integrated into the data-science workflow

## ✨ Solution

Modelguard provides:

- **Safe Loading**: Blocks malicious Pickle opcodes with restricted unpickler
- **Signature Verification**: Guarantees model provenance via Sigstore signatures
- **Zero Friction**: Drop-in replacement requiring < 10 lines of code changes
- **Multi-Framework**: Works with PyTorch, TensorFlow/Keras, scikit-learn, and ONNX

## 🚀 Quick Start

### Installation

```bash
pip install modelguard
```

### Basic Usage

Replace your existing model loading code:

```python
# Before
import torch
model = torch.load('model.pth')

# After
import modelguard.torch as torch
model = torch.safe_load('model.pth')
```

Or use the context manager for automatic patching:

```python
import modelguard
import torch

with modelguard.patched():
    model = torch.load('model.pth')  # Automatically uses safe loading
```

### Framework Support

```python
# PyTorch
import modelguard.torch as torch
model = torch.safe_load('model.pth')

# TensorFlow/Keras
import modelguard.tensorflow as tf
model = tf.safe_load('model.h5')

# scikit-learn
import modelguard.sklearn as sklearn
model = sklearn.safe_load('model.pkl')

# ONNX
import modelguard.onnx as onnx
model = onnx.safe_load('model.onnx')
```

## 🛡️ Security Features

### Malware Detection

Modelguard scans models for dangerous Pickle opcodes:

```bash
# Scan individual files
modelguard scan model.pth

# Scan directories recursively
modelguard scan ./models/ --recursive

# Output as JSON
modelguard scan model.pth --format json
```

### Signature Verification

Sign and verify models using Sigstore:

```bash
# Sign a model
modelguard sign model.pth --identity me@example.com

# Verify signature
modelguard verify model.pth
```

## ⚙️ Configuration

Create a `modelguard.yaml` policy file:

```bash
modelguard policy init
```

Example configuration:

```yaml
# Enforcement mode - block unsafe models
enforce: true

# Require valid signatures
require_signatures: true
trusted_signers:
  - "alice@company.com"
  - "bob@company.com"

# Scan models on load
scan_on_load: true

# File size limits (MB)
max_file_size_mb: 1000

# Operation timeout (seconds)
timeout_seconds: 30
```

### Environment Variables

Override settings with environment variables:

```bash
export MODELGUARD_ENFORCE=true
export MODELGUARD_REQUIRE_SIGNATURES=true
export MODELGUARD_TRUSTED_SIGNERS="alice@company.com,bob@company.com"
```

## 🔧 Advanced Usage

### Policy-Based Loading

```python
from modelguard.core.policy import load_policy
import modelguard.torch as torch

# Load with current policy
policy = load_policy()
if policy.should_enforce():
    model = torch.safe_load('model.pth')
else:
    model = torch.load('model.pth')  # Fallback
```

### Custom Scanning

```python
from modelguard.core.scanner import ModelScanner

scanner = ModelScanner()
result = scanner.scan_file('model.pth')

if not result.is_safe:
    print(f"Threats found: {result.threats}")
    print(f"Details: {result.details}")
```

## 📋 Requirements

- Python >= 3.9
- Operating Systems: Linux, macOS, Windows 10+

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

Apache 2.0 - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- [Documentation](https://docs.modelguard.dev)
- [GitHub Repository](https://github.com/example/modelguard)
- [Issue Tracker](https://github.com/example/modelguard/issues)
- [PyPI Package](https://pypi.org/project/modelguard/)

## 🛣️ Roadmap

- [x] v0.1: Core scanning, signing, PyTorch/scikit-learn support
- [ ] v0.2: TensorFlow/ONNX support, performance optimizations
- [ ] v0.3: Enterprise policy server, advanced threat detection
- [ ] v1.0: Production hardening, comprehensive documentation
