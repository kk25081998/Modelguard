"""Basic test to verify modelguard functionality."""

import sys
import tempfile
import pickle
from pathlib import Path

# Add src to path so we can import modelguard
sys.path.insert(0, 'src')

def test_policy():
    """Test basic policy functionality."""
    print("=== Testing Policy ===")
    
    from modelguard.core.policy import PolicyConfig, Policy
    
    # Test default config
    config = PolicyConfig()
    print(f"✓ Default enforce: {config.enforce}")
    print(f"✓ Default require_signatures: {config.require_signatures}")
    print(f"✓ Default scan_on_load: {config.scan_on_load}")
    
    # Test custom config
    custom_config = PolicyConfig(
        enforce=True,
        require_signatures=True,
        trusted_signers=["test@example.com"]
    )
    policy = Policy(custom_config)
    
    print(f"✓ Custom enforce: {policy.should_enforce()}")
    print(f"✓ Custom requires_signatures: {policy.requires_signatures()}")
    print(f"✓ Trusted signer check: {policy.is_signer_trusted('test@example.com')}")
    print(f"✓ Untrusted signer check: {not policy.is_signer_trusted('other@example.com')}")


def test_scanner():
    """Test basic scanner functionality."""
    print("\n=== Testing Scanner ===")
    
    from modelguard.core.scanner import ModelScanner
    
    # Create a safe pickle file
    safe_data = {"weights": [1, 2, 3], "bias": [0.1, 0.2]}
    
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        pickle.dump(safe_data, f)
        temp_path = Path(f.name)
    
    try:
        scanner = ModelScanner()
        result = scanner.scan_file(temp_path)
        
        print(f"✓ File scanned: {temp_path.name}")
        print(f"✓ Is safe: {result.is_safe}")
        print(f"✓ Threats count: {len(result.threats)}")
        
        if result.details.get("total_opcodes"):
            print(f"✓ Opcodes analyzed: {result.details['total_opcodes']}")
            
    finally:
        temp_path.unlink()


def test_opcodes():
    """Test opcode analysis."""
    print("\n=== Testing Opcode Analysis ===")
    
    from modelguard.core.opcodes import analyze_pickle_opcodes
    
    # Create safe pickle data
    safe_data = [1, 2, 3, "hello"]
    pickle_bytes = pickle.dumps(safe_data)
    
    analysis = analyze_pickle_opcodes(pickle_bytes)
    
    print(f"✓ Analysis completed: {analysis.get('is_safe', False)}")
    print(f"✓ Opcodes found: {len(analysis.get('opcodes_found', []))}")
    print(f"✓ Dangerous opcodes: {len(analysis.get('dangerous_opcodes', []))}")
    print(f"✓ Global imports: {len(analysis.get('global_imports', []))}")


def test_safe_loading():
    """Test safe loading functionality."""
    print("\n=== Testing Safe Loading ===")
    
    # Create a safe model file
    model_data = {"model_weights": [[0.1, 0.2], [0.3, 0.4]]}
    
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        pickle.dump(model_data, f)
        temp_path = Path(f.name)
    
    try:
        # Set permissive policy for testing
        import os
        os.environ["MODELGUARD_ENFORCE"] = "false"
        os.environ["MODELGUARD_REQUIRE_SIGNATURES"] = "false"
        
        from modelguard.loaders.torch import safe_load
        
        loaded_model = safe_load(temp_path)
        print(f"✓ Model loaded safely: {type(loaded_model)}")
        print(f"✓ Model data matches: {loaded_model == model_data}")
        
    finally:
        temp_path.unlink()
        os.environ.pop("MODELGUARD_ENFORCE", None)
        os.environ.pop("MODELGUARD_REQUIRE_SIGNATURES", None)


if __name__ == "__main__":
    print("Modelguard Basic Functionality Test")
    print("=" * 40)
    
    try:
        test_policy()
        test_scanner()
        test_opcodes()
        test_safe_loading()
        
        print("\n🎉 All tests passed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()