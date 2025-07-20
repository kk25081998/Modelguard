#!/usr/bin/env python3
"""
Test script to verify Colab compatibility of ModelGuard notebook examples.
This simulates the key parts of the notebook without Jupyter dependencies.
"""

import pickle
import tempfile
import os
from pathlib import Path
from collections import OrderedDict
import numpy as np
from sklearn.linear_model import LinearRegression

print("🧪 Testing Colab Compatibility for ModelGuard Notebook")
print("=" * 60)

# Test 1: Basic imports
print("\n1. Testing basic imports...")
try:
    import modelguard
    from modelguard.core.scanner import ModelScanner
    from modelguard import sklearn
    print(f"   ✅ ModelGuard v{modelguard.__version__} imported successfully")
except Exception as e:
    print(f"   ❌ Import failed: {e}")
    exit(1)

# Test 2: Malicious model detection
print("\n2. Testing malicious model detection...")
try:
    class MaliciousModel:
        def __reduce__(self):
            return (print, ("🚨 DANGER: Malicious code executed!",))

    temp_dir = tempfile.gettempdir()
    malicious_path = os.path.join(temp_dir, "test_malicious.pkl")
    
    with open(malicious_path, 'wb') as f:
        pickle.dump(MaliciousModel(), f)
    
    scanner = ModelScanner()
    result = scanner.scan_file(Path(malicious_path))
    
    if not result.is_safe and len(result.threats) > 0:
        print("   ✅ Malicious model correctly detected as unsafe")
    else:
        print("   ❌ Malicious model not detected")
    
    os.remove(malicious_path)
except Exception as e:
    print(f"   ❌ Malicious model test failed: {e}")

# Test 3: Legitimate model handling
print("\n3. Testing legitimate model handling...")
try:
    # Create PyTorch-style model
    pytorch_style_model = OrderedDict([
        ('linear.weight', np.random.randn(10, 1).tolist()),
        ('linear.bias', [0.1])
    ])
    pytorch_path = os.path.join(temp_dir, "test_pytorch_style.pkl")
    
    with open(pytorch_path, 'wb') as f:
        pickle.dump(pytorch_style_model, f)
    
    # Create scikit-learn model
    X = np.random.randn(100, 5)
    y = np.random.randn(100)
    sklearn_model = LinearRegression().fit(X, y)
    sklearn_path = os.path.join(temp_dir, "test_sklearn.pkl")
    
    with open(sklearn_path, 'wb') as f:
        pickle.dump(sklearn_model, f)
    
    # Test scanning
    pytorch_result = scanner.scan_file(Path(pytorch_path))
    sklearn_result = scanner.scan_file(Path(sklearn_path))
    
    if pytorch_result.is_safe and sklearn_result.is_safe:
        print("   ✅ Legitimate models correctly identified as safe")
    else:
        print(f"   ❌ Legitimate models flagged as unsafe: PyTorch={pytorch_result.is_safe}, sklearn={sklearn_result.is_safe}")
    
    # Test safe loading
    loaded_pytorch = sklearn.safe_load(pytorch_path)
    loaded_sklearn = sklearn.safe_load(sklearn_path)
    
    if isinstance(loaded_pytorch, OrderedDict) and hasattr(loaded_sklearn, 'coef_'):
        print("   ✅ Safe loading works correctly")
    else:
        print("   ❌ Safe loading failed")
    
    os.remove(pytorch_path)
    os.remove(sklearn_path)
except Exception as e:
    print(f"   ❌ Legitimate model test failed: {e}")

# Test 4: Context manager
print("\n4. Testing context manager...")
try:
    context_path = os.path.join(temp_dir, "test_context.pkl")
    test_data = {'test': 'data', 'numbers': [1, 2, 3]}
    
    with open(context_path, 'wb') as f:
        pickle.dump(test_data, f)
    
    # Set enforcement
    os.environ["MODELGUARD_ENFORCE"] = "true"
    os.environ["MODELGUARD_SCAN_ON_LOAD"] = "true"
    
    with modelguard.patched():
        with open(context_path, 'rb') as f:
            loaded_data = pickle.load(f)
    
    if loaded_data == test_data:
        print("   ✅ Context manager works correctly")
    else:
        print("   ❌ Context manager failed")
    
    # Cleanup
    os.environ.pop("MODELGUARD_ENFORCE", None)
    os.environ.pop("MODELGUARD_SCAN_ON_LOAD", None)
    os.remove(context_path)
except Exception as e:
    print(f"   ❌ Context manager test failed: {e}")

# Test 5: Policy configuration
print("\n5. Testing policy configuration...")
try:
    from modelguard.core.policy import Policy, PolicyConfig
    
    config = PolicyConfig(
        enforce=True,
        require_signatures=False,
        scan_on_load=True,
        max_file_size_mb=50
    )
    
    policy = Policy(config)
    
    if (policy.should_enforce() and 
        policy.should_scan() and 
        not policy.requires_signatures()):
        print("   ✅ Policy configuration works correctly")
    else:
        print("   ❌ Policy configuration failed")
except Exception as e:
    print(f"   ❌ Policy configuration test failed: {e}")

print("\n" + "=" * 60)
print("🎉 Colab compatibility test completed!")
print("The notebook should now work correctly in Google Colab.")