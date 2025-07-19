#!/usr/bin/env python3
"""Development setup script for Modelguard."""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        return False


def main():
    """Set up development environment."""
    print("🚀 Setting up Modelguard development environment")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install basic dependencies
    basic_deps = [
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "typer>=0.9.0",
        "rich>=13.0.0"
    ]
    
    for dep in basic_deps:
        if not run_command(f"pip install {dep}", f"Installing {dep}"):
            print(f"⚠️  Failed to install {dep}, continuing...")
    
    # Install optional dependencies
    optional_deps = {
        "sigstore": "Signature verification",
        "pytest": "Testing framework",
        "mypy": "Type checking",
        "ruff": "Code linting"
    }
    
    for dep, desc in optional_deps.items():
        run_command(f"pip install {dep}", f"Installing {dep} ({desc})")
    
    # Run basic functionality test
    print("\n🧪 Running basic functionality test...")
    if run_command("python test_basic.py", "Basic functionality test"):
        print("\n🎉 Development environment setup complete!")
        print("\nNext steps:")
        print("1. Run tests: python -m pytest tests/")
        print("2. Try examples: python examples/basic_usage.py")
        print("3. Test CLI: python -m src.modelguard.cli --help")
    else:
        print("\n⚠️  Setup completed but basic test failed")
        print("Check the error messages above and install missing dependencies")


if __name__ == "__main__":
    main()