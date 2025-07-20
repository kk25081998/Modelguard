#!/usr/bin/env python3
"""
🛡️ ModelGuard Quick Start: Detect Bad Models

This script demonstrates how to protect your ML applications from malicious model files.

What you'll learn:
- How malicious ML models can execute arbitrary code
- How to detect and block dangerous models
- Safe loading techniques for PyTorch, TensorFlow, and scikit-learn
- Real-world security best practices
"""

import pickle
import tempfile
import os
import time
from pathlib import Path

print("🛡️ ModelGuard Quick Start: Detect Bad Models")
print("=" * 50)

# =============================================================================
# 🚨 The Problem: Malicious Models
# =============================================================================

print("\n🚨 The Problem: Malicious Models")
print("-" * 30)

# Create a malicious model that executes code when loaded
class MaliciousModel:
    def __reduce__(self):
        # This code will execute when the model is unpickled!
        return (print, ("🚨 DANGER: Malicious code executed! This could have been anything...",))

# Save the malicious model (using Windows-compatible temp directory)
temp_dir = tempfile.gettempdir()
malicious_path = os.path.join(temp_dir, "malicious_model.pkl")

with open(malicious_path, 'wb') as f:
    pickle.dump(MaliciousModel(), f)

print(f"Created malicious model at: {malicious_path}")
print("⚠️  This model will execute code when loaded with standard pickle.load()")

# Demonstrating the Danger
print("\n### Demonstrating the Danger")
print("Loading malicious model with standard pickle...")

with open(malicious_path, 'rb') as f:
    dangerous_model = pickle.load(f)  # Code executes here!

print("\n💀 As you can see, the malicious code executed automatically!")
print("   In a real attack, this could:")
print("   - Steal your data")
print("   - Install malware")
print("   - Access your cloud credentials")
print("   - Anything the attacker wants!")

# =============================================================================
# ✅ The Solution: ModelGuard
# =============================================================================

print("\n\n✅ The Solution: ModelGuard")
print("-" * 30)

from modelguard.core.scanner import ModelScanner

# Scan the malicious model
scanner = ModelScanner()
result = scanner.scan_file(Path(malicious_path))

print("🔍 ModelGuard Scan Results:")
print(f"   Is Safe: {result.is_safe}")
print(f"   Threats Found: {len(result.threats)}")
print(f"   Threat Details: {result.threats}")

if not result.is_safe:
    print("\n🛡️ ModelGuard detected the malicious content and blocked it!")
else:
    print("\n⚠️  Model appears safe (this shouldn't happen with our malicious example)")

# =============================================================================
# 🔒 Safe Loading with ModelGuard
# =============================================================================

print("\n\n🔒 Safe Loading with ModelGuard")
print("-" * 30)

from modelguard import sklearn

print("Attempting to load malicious model with ModelGuard...")

# Enable enforcement mode for this demonstration
os.environ["MODELGUARD_ENFORCE"] = "true"
os.environ["MODELGUARD_SCAN_ON_LOAD"] = "true"

try:
    # This should fail safely
    model = sklearn.safe_load(malicious_path)
    print("❌ Unexpected: Model loaded (this shouldn't happen!)")
except Exception as e:
    print(f"✅ ModelGuard blocked the malicious model: {type(e).__name__}")
    print(f"   Error details: {str(e)[:100]}...")
    print("\n🛡️ Your system is protected!")
finally:
    # Clean up environment variables
    os.environ.pop("MODELGUARD_ENFORCE", None)
    os.environ.pop("MODELGUARD_SCAN_ON_LOAD", None)

# =============================================================================
# ✅ Working with Legitimate Models
# =============================================================================

print("\n\n✅ Working with Legitimate Models")
print("-" * 30)

# For this demo, we'll use simpler models that don't require PyTorch
import numpy as np
from sklearn.linear_model import LinearRegression
from collections import OrderedDict

# Create a legitimate PyTorch-style model (OrderedDict)
pytorch_style_model = OrderedDict([
    ('linear.weight', np.random.randn(10, 1).tolist()),
    ('linear.bias', [0.1])
])
pytorch_path = os.path.join(temp_dir, "safe_pytorch_model.pkl")

with open(pytorch_path, 'wb') as f:
    pickle.dump(pytorch_style_model, f)

# Create a legitimate scikit-learn model
X = np.random.randn(100, 5)
y = np.random.randn(100)
sklearn_model = LinearRegression().fit(X, y)
sklearn_path = os.path.join(temp_dir, "safe_sklearn_model.pkl")

with open(sklearn_path, 'wb') as f:
    pickle.dump(sklearn_model, f)

print("✅ Created legitimate models:")
print(f"   PyTorch-style model: {pytorch_path}")
print(f"   Scikit-learn model: {sklearn_path}")

# Scanning Legitimate Models
print("\n### Scanning Legitimate Models")
print("🔍 Scanning legitimate models...\n")

for name, path in [("PyTorch-style", pytorch_path), ("Scikit-learn", sklearn_path)]:
    result = scanner.scan_file(Path(path))
    print(f"{name} Model:")
    print(f"   ✅ Is Safe: {result.is_safe}")
    print(f"   🔍 Threats: {len(result.threats)}")
    if result.threats:
        print(f"   ⚠️  Details: {result.threats}")
    print()

# Safe Loading of Legitimate Models
print("### Safe Loading of Legitimate Models")
from modelguard import sklearn as safe_sklearn

print("🔒 Loading legitimate models with ModelGuard...\n")

# Load PyTorch-style model safely
try:
    loaded_pytorch = safe_sklearn.safe_load(pytorch_path)  # Using sklearn loader for pickle files
    print("✅ PyTorch-style model loaded successfully!")
    print(f"   Model keys: {list(loaded_pytorch.keys())[:3]}...")
except Exception as e:
    print(f"❌ PyTorch-style loading failed: {e}")

# Load scikit-learn model safely
try:
    loaded_sklearn = safe_sklearn.safe_load(sklearn_path)
    print("\n✅ Scikit-learn model loaded successfully!")
    print(f"   Model type: {type(loaded_sklearn).__name__}")
    print(f"   Coefficients shape: {loaded_sklearn.coef_.shape}")
except Exception as e:
    print(f"❌ Scikit-learn loading failed: {e}")

# =============================================================================
# 🎯 Advanced: Context Manager (Recommended)
# =============================================================================

print("\n\n🎯 Advanced: Context Manager (Recommended)")
print("-" * 30)

import modelguard

print("🎯 Using ModelGuard context manager...\n")

# Create fresh models for this demo
context_pytorch_path = os.path.join(temp_dir, "context_pytorch_model.pkl")
with open(context_pytorch_path, 'wb') as f:
    pickle.dump(pytorch_style_model, f)

# Create scikit-learn model
sklearn_model_fresh = LinearRegression().fit(X, y)

# Set enforcement policy for this demo
os.environ["MODELGUARD_ENFORCE"] = "true"
os.environ["MODELGUARD_SCAN_ON_LOAD"] = "true"

# Everything inside this context is automatically secured
with modelguard.patched():
    print("1. Loading PyTorch-style model with pickle.load()...")
    try:
        with open(context_pytorch_path, 'rb') as f:
            model = pickle.load(f)  # Automatically secured!
        print("   ✅ Success! PyTorch-style model loaded safely")
        print(f"   Model keys: {list(model.keys())[:3]}...")
    except Exception as e:
        print(f"   ❌ Failed: {e}")
    
    print("\n2. Loading scikit-learn model with pickle.load()...")
    try:
        # Save model for this test
        joblib_path = os.path.join(temp_dir, "context_sklearn_model.pkl")
        with open(joblib_path, 'wb') as f:
            pickle.dump(sklearn_model_fresh, f)
        
        with open(joblib_path, 'rb') as f:
            model = pickle.load(f)  # Automatically secured!
        print("   ✅ Success! Scikit-learn model loaded safely")
        print(f"   Model type: {type(model).__name__}")
    except Exception as e:
        print(f"   ❌ Failed: {e}")

print("\n🛡️ Context manager provides seamless protection for framework loaders!")
print("💡 Note: For direct pickle.load(), use modelguard.sklearn.safe_load() instead")

# Clean up environment
os.environ.pop("MODELGUARD_ENFORCE", None)
os.environ.pop("MODELGUARD_SCAN_ON_LOAD", None)

# =============================================================================
# ⚙️ Policy Configuration
# =============================================================================

print("\n\n⚙️ Policy Configuration")
print("-" * 30)

from modelguard.core.policy import Policy, PolicyConfig

print("⚙️ Configuring ModelGuard policies...\n")

# Method 1: Environment variables
os.environ["MODELGUARD_ENFORCE"] = "true"
os.environ["MODELGUARD_SCAN_ON_LOAD"] = "true"
os.environ["MODELGUARD_MAX_FILE_SIZE_MB"] = "100"

print("Environment-based policy:")
print(f"   MODELGUARD_ENFORCE: {os.environ.get('MODELGUARD_ENFORCE')}")
print(f"   MODELGUARD_SCAN_ON_LOAD: {os.environ.get('MODELGUARD_SCAN_ON_LOAD')}")
print(f"   MODELGUARD_MAX_FILE_SIZE_MB: {os.environ.get('MODELGUARD_MAX_FILE_SIZE_MB')}")

# Method 2: Programmatic configuration
config = PolicyConfig(
    enforce=True,
    require_signatures=False,  # Set to False for this demo
    scan_on_load=True,
    max_file_size_mb=50
)

policy = Policy(config)

print("\nProgrammatic policy:")
print(f"   Enforce mode: {policy.should_enforce()}")
print(f"   Scan on load: {policy.should_scan()}")
print(f"   Max file size: {policy.get_max_file_size()} bytes")
print(f"   Requires signatures: {policy.requires_signatures()}")

# =============================================================================
# 🌍 Real-World Usage Patterns
# =============================================================================

print("\n\n🌍 Real-World Usage Patterns")
print("-" * 30)

print("🌍 Real-world usage patterns:\n")

# Pattern 1: Drop-in replacement
print("1. Drop-in Replacement Pattern:")
print("   # Before: import torch")
print("   # After:  import modelguard.torch as torch")
print("   # All torch.load() calls are now secured!")

# Pattern 2: Explicit safe loading
print("\n2. Explicit Safe Loading Pattern:")
print("   model = modelguard.torch.safe_load('model.pth')")
print("   # Clear intent, explicit security")

# Pattern 3: Context manager for mixed loading
print("\n3. Context Manager Pattern:")
print("   with modelguard.patched():")
print("       # All model loading is secured")
print("       pytorch_model = torch.load('model.pth')")
print("       sklearn_model = pickle.load(open('model.pkl', 'rb'))")

# Pattern 4: Enterprise security
print("\n4. Enterprise Security Pattern:")
print("   # Set strict policies via environment")
print("   export MODELGUARD_ENFORCE=true")
print("   export MODELGUARD_REQUIRE_SIGNATURES=true")
print("   # All applications automatically secured")

print("\n✨ Choose the pattern that fits your workflow!")

# =============================================================================
# ⚡ Performance Demonstration
# =============================================================================

print("\n\n⚡ Performance Demonstration")
print("-" * 30)

print("⚡ Performance comparison...\n")

# Create a larger model for testing
large_model = {
    'weights': np.random.randn(1000, 1000).tolist(),
    'bias': np.random.randn(1000).tolist(),
    'metadata': {'version': '1.0', 'framework': 'test'}
}

large_model_path = os.path.join(temp_dir, "large_model.pkl")
with open(large_model_path, 'wb') as f:
    pickle.dump(large_model, f)

file_size = os.path.getsize(large_model_path) / (1024 * 1024)  # MB
print(f"Test model size: {file_size:.1f} MB")

# Time scanning
start_time = time.time()
scan_result = scanner.scan_file(Path(large_model_path))
scan_time = time.time() - start_time

print(f"\n🔍 Scanning performance:")
print(f"   Time: {scan_time*1000:.1f} ms")
print(f"   Rate: {file_size/scan_time:.1f} MB/s")
print(f"   Result: {'✅ Safe' if scan_result.is_safe else '❌ Unsafe'}")

# Time safe loading
start_time = time.time()
try:
    loaded_model = sklearn.safe_load(large_model_path)
    load_time = time.time() - start_time
    print(f"\n🔒 Safe loading performance:")
    print(f"   Time: {load_time*1000:.1f} ms")
    print(f"   Rate: {file_size/load_time:.1f} MB/s")
    print(f"   Status: ✅ Success")
except Exception as e:
    print(f"\n🔒 Safe loading: ❌ {e}")

print(f"\n🚀 ModelGuard adds minimal overhead while providing comprehensive security!")

# =============================================================================
# 🧹 Cleanup
# =============================================================================

print("\n\n🧹 Cleanup")
print("-" * 30)

# Clean up temporary files
cleanup_paths = [
    malicious_path, pytorch_path, sklearn_path, large_model_path,
    context_pytorch_path
]

# Add joblib_path if it exists
if 'joblib_path' in locals():
    cleanup_paths.append(joblib_path)

for path in cleanup_paths:
    if os.path.exists(path):
        os.remove(path)

# Clean up environment variables
for env_var in ["MODELGUARD_ENFORCE", "MODELGUARD_SCAN_ON_LOAD", "MODELGUARD_MAX_FILE_SIZE_MB"]:
    os.environ.pop(env_var, None)

print("🧹 Cleanup complete!")

# =============================================================================
# 🎉 Summary
# =============================================================================

print("\n\n🎉 Summary")
print("-" * 30)

print("Congratulations! You've learned how to protect your ML applications with ModelGuard:")

print("\n✅ What We Covered")
print("- The Risk: ML models can contain malicious code that executes when loaded")
print("- Detection: ModelGuard scans models for dangerous patterns")
print("- Protection: Safe loading prevents malicious code execution")
print("- Flexibility: Multiple usage patterns for different workflows")
print("- Performance: Minimal overhead with comprehensive security")

print("\n🚀 Next Steps")
print("1. Install ModelGuard in your projects: pip install ml-modelguard")
print("2. Choose your pattern: Drop-in replacement, explicit safe loading, or context manager")
print("3. Configure policies: Set up organizational security policies")
print("4. Stay secure: Always scan models from untrusted sources")

print("\n📚 Learn More")
print("- GitHub: https://github.com/kk25081998/Modelguard")
print("- PyPI: https://pypi.org/project/ml-modelguard/")
print("- Documentation: Check the README for advanced features")

print("\n🛡️ Remember")
print("Never load untrusted models without ModelGuard protection!")

print("\n" + "=" * 50)
print("Made with ❤️ for the ML community's security")