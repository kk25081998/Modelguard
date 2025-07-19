# Installation Guide

## Quick Install

```bash
pip install modelguard
```

## Development Install

1. Clone the repository:

```bash
git clone https://github.com/example/modelguard.git
cd modelguard
```

2. Install in development mode:

```bash
pip install -e .
```

3. Install development dependencies:

```bash
pip install -e ".[dev]"
```

## Framework-Specific Dependencies

### PyTorch Support

```bash
pip install "modelguard[torch]"
```

### TensorFlow Support

```bash
pip install "modelguard[tensorflow]"
```

### scikit-learn Support

```bash
pip install "modelguard[sklearn]"
```

### ONNX Support

```bash
pip install "modelguard[onnx]"
```

### All Frameworks

```bash
pip install "modelguard[torch,tensorflow,sklearn,onnx]"
```

## Requirements

- Python >= 3.9
- Operating Systems: Linux, macOS, Windows 10+

## Verification

Test your installation:

```bash
python -c "import modelguard; print('✓ Modelguard installed successfully')"
```

Run basic functionality test:

```bash
python -c "
from modelguard.core.policy import PolicyConfig
from modelguard.core.scanner import ModelScanner
config = PolicyConfig()
scanner = ModelScanner()
print('✓ Core functionality working')
"
```

## CLI Usage

After installation, the `modelguard` command should be available:

```bash
modelguard --help
```

## Troubleshooting

### Import Errors

If you get import errors, ensure you have the required dependencies:

```bash
pip install pydantic pyyaml
```

### Sigstore Issues

For signature functionality, install sigstore:

```bash
pip install sigstore
```

### Framework Issues

Install the specific framework you need:

```bash
# For PyTorch
pip install torch

# For TensorFlow
pip install tensorflow

# For scikit-learn
pip install scikit-learn

# For ONNX
pip install onnx onnxruntime
```
