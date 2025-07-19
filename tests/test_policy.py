"""Tests for policy engine."""

import os
import tempfile
from pathlib import Path
import yaml
import pytest

from modelguard.core.policy import Policy, PolicyConfig, load_policy


class TestPolicyConfig:
    """Test cases for PolicyConfig."""
    
    def test_default_config(self):
        """Test default policy configuration."""
        config = PolicyConfig()
        
        assert config.enforce is False
        assert config.require_signatures is False
        assert config.trusted_signers == []
        assert config.allow_unsigned is True
        assert config.scan_on_load is True
        assert config.max_file_size_mb == 1000
        assert config.timeout_seconds == 30
    
    def test_custom_config(self):
        """Test custom policy configuration."""
        config = PolicyConfig(
            enforce=True,
            require_signatures=True,
            trusted_signers=["alice@example.com", "bob@example.com"],
            max_file_size_mb=500
        )
        
        assert config.enforce is True
        assert config.require_signatures is True
        assert config.trusted_signers == ["alice@example.com", "bob@example.com"]
        assert config.max_file_size_mb == 500


class TestPolicy:
    """Test cases for Policy class."""
    
    def test_default_policy(self):
        """Test default policy behavior."""
        policy = Policy()
        
        assert not policy.should_enforce()
        assert not policy.requires_signatures()
        assert policy.is_signer_trusted("anyone@example.com")
        assert policy.should_scan()
        assert policy.get_max_file_size() == 1000 * 1024 * 1024
        assert policy.get_timeout() == 30
    
    def test_policy_from_file(self):
        """Test loading policy from YAML file."""
        policy_data = {
            "enforce": True,
            "require_signatures": True,
            "trusted_signers": ["alice@example.com"],
            "max_file_size_mb": 500
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(policy_data, f)
            temp_path = Path(f.name)
        
        try:
            policy = Policy.from_file(temp_path)
            
            assert policy.should_enforce()
            assert policy.requires_signatures()
            assert policy.is_signer_trusted("alice@example.com")
            assert not policy.is_signer_trusted("bob@example.com")
            assert policy.get_max_file_size() == 500 * 1024 * 1024
        finally:
            temp_path.unlink()
    
    def test_policy_from_nonexistent_file(self):
        """Test loading policy from nonexistent file returns defaults."""
        policy = Policy.from_file(Path("nonexistent.yaml"))
        
        assert not policy.should_enforce()
        assert not policy.requires_signatures()
    
    def test_policy_from_env(self):
        """Test loading policy from environment variables."""
        env_vars = {
            "MODELGUARD_ENFORCE": "true",
            "MODELGUARD_REQUIRE_SIGNATURES": "true", 
            "MODELGUARD_TRUSTED_SIGNERS": "alice@example.com,bob@example.com",
            "MODELGUARD_MAX_FILE_SIZE_MB": "250"
        }
        
        # Set environment variables
        for key, value in env_vars.items():
            os.environ[key] = value
        
        try:
            policy = Policy.from_env()
            
            assert policy.should_enforce()
            assert policy.requires_signatures()
            assert policy.is_signer_trusted("alice@example.com")
            assert policy.is_signer_trusted("bob@example.com")
            assert not policy.is_signer_trusted("charlie@example.com")
            assert policy.get_max_file_size() == 250 * 1024 * 1024
        finally:
            # Clean up environment variables
            for key in env_vars:
                os.environ.pop(key, None)
    
    def test_trusted_signers_empty_means_trust_all(self):
        """Test that empty trusted_signers list means trust all signers."""
        config = PolicyConfig(trusted_signers=[])
        policy = Policy(config)
        
        assert policy.is_signer_trusted("anyone@example.com")
        assert policy.is_signer_trusted("another@example.com")
    
    def test_trusted_signers_specific_list(self):
        """Test that specific trusted_signers list restricts trust."""
        config = PolicyConfig(trusted_signers=["alice@example.com", "bob@example.com"])
        policy = Policy(config)
        
        assert policy.is_signer_trusted("alice@example.com")
        assert policy.is_signer_trusted("bob@example.com")
        assert not policy.is_signer_trusted("charlie@example.com")


class TestLoadPolicy:
    """Test cases for load_policy function."""
    
    def test_load_policy_defaults(self):
        """Test loading policy with no config files or env vars."""
        # Ensure no relevant env vars are set
        env_vars_to_clear = [
            "MODELGUARD_ENFORCE",
            "MODELGUARD_REQUIRE_SIGNATURES",
            "MODELGUARD_TRUSTED_SIGNERS"
        ]
        
        original_values = {}
        for var in env_vars_to_clear:
            original_values[var] = os.environ.pop(var, None)
        
        try:
            policy = load_policy()
            
            # Should return default policy
            assert not policy.should_enforce()
            assert not policy.requires_signatures()
        finally:
            # Restore original environment
            for var, value in original_values.items():
                if value is not None:
                    os.environ[var] = value