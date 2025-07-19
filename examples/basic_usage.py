"""Basic usage examples for modelguard."""

import tempfile
import pickle
from pathlib import Path

# Create a sample model file for demonstration
def create_sample_model():
    """Create a sample model file."""
    model_data = {
        "weights": [[0.1, 0.2], [0.3, 0.4]],
        "bias": [0.1, 0.2],
        "metadata": {"version": "1.0", "framework": "custom"}
    }
    
    temp_file = tempfile.NamedTemporaryFile(suffix='.pkl', delete=False)
    with open(temp_file.name, 'wb') as f:
        pickle.dump(model_data, f)
    
    return Path(temp_file.name)


def example_safe_loading():
    """Example of safe model loading."""
    print("=== Safe Loading Example ===")
    
    # Create sample model
    model_path = create_sample_model()
    print(f"Created sample model: {model_path}")
    
    try:
        # Method 1: Direct safe loading
        import modelguard.torch as torch
        model = torch.safe_load(model_path)
        print(f"✓ Loaded model safely: {type(model)}")
        
        # Method 2: Context manager (monkey patching)
        import modelguard
        import pickle as std_pickle
        
        with modelguard.patched():
            # This would use safe loading automatically if torch was imported
            model2 = std_pickle.load(open(model_path, 'rb'))
            print(f"✓ Loaded with context manager: {type(model2)}")
            
    finally:
        # Clean up
        model_path.unlink()


def example_scanning():
    """Example of model scanning."""
    print("\n=== Scanning Example ===")
    
    # Create sample model
    model_path = create_sample_model()
    print(f"Scanning model: {model_path}")
    
    try:
        from modelguard.core.scanner import ModelScanner
        
        scanner = ModelScanner()
        result = scanner.scan_file(model_path)
        
        print(f"Is safe: {result.is_safe}")
        print(f"Threats: {result.threats}")
        print(f"Details: {result.details}")
        
    finally:
        # Clean up
        model_path.unlink()


def example_policy():
    """Example of policy configuration."""
    print("\n=== Policy Example ===")
    
    from modelguard.core.policy import Policy, PolicyConfig
    
    # Create custom policy
    config = PolicyConfig(
        enforce=True,
        require_signatures=False,  # Set to False for this example
        scan_on_load=True,
        max_file_size_mb=100
    )
    
    policy = Policy(config)
    
    print(f"Enforce mode: {policy.should_enforce()}")
    print(f"Requires signatures: {policy.requires_signatures()}")
    print(f"Should scan: {policy.should_scan()}")
    print(f"Max file size: {policy.get_max_file_size()} bytes")


def example_with_policy():
    """Example of loading with policy enforcement."""
    print("\n=== Policy Enforcement Example ===")
    
    # Create sample model
    model_path = create_sample_model()
    print(f"Loading model with policy: {model_path}")
    
    try:
        # Set up a permissive policy for this example
        from modelguard.core.policy import Policy, PolicyConfig
        import os
        
        # Use environment variables to configure policy
        os.environ["MODELGUARD_ENFORCE"] = "false"  # Permissive for demo
        os.environ["MODELGUARD_SCAN_ON_LOAD"] = "true"
        
        import modelguard.torch as torch
        model = torch.safe_load(model_path)
        print(f"✓ Model loaded successfully: {type(model)}")
        
    finally:
        # Clean up
        model_path.unlink()
        os.environ.pop("MODELGUARD_ENFORCE", None)
        os.environ.pop("MODELGUARD_SCAN_ON_LOAD", None)


if __name__ == "__main__":
    print("Modelguard Basic Usage Examples")
    print("=" * 40)
    
    try:
        example_safe_loading()
        example_scanning()
        example_policy()
        example_with_policy()
        
        print("\n✓ All examples completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Example failed: {e}")
        import traceback
        traceback.print_exc()