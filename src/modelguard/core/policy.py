"""Policy engine for modelguard configuration."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class PolicyConfig(BaseModel):
    """Policy configuration model."""

    enforce: bool = Field(default=False, description="Enable enforcement mode")
    require_signatures: bool = Field(
        default=False, description="Require valid signatures"
    )
    trusted_signers: list[str] = Field(
        default_factory=list, description="List of trusted signer identities"
    )
    allow_unsigned: bool = Field(
        default=True, description="Allow unsigned models when signatures not required"
    )
    scan_on_load: bool = Field(
        default=True, description="Scan models for malicious content on load"
    )
    max_file_size_mb: int = Field(
        default=1000, description="Maximum model file size in MB"
    )
    timeout_seconds: int = Field(
        default=30, description="Timeout for operations in seconds"
    )

    model_config = {"extra": "forbid"}


class Policy:
    """Policy manager for modelguard."""

    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        """Load policy from YAML file."""
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        config = PolicyConfig(**data)
        return cls(config)

    @classmethod
    def from_env(cls) -> "Policy":
        """Load policy from environment variables."""
        config_data = {}

        # Map environment variables to config fields
        env_mapping = {
            "MODELGUARD_ENFORCE": "enforce",
            "MODELGUARD_REQUIRE_SIGNATURES": "require_signatures",
            "MODELGUARD_TRUSTED_SIGNERS": "trusted_signers",
            "MODELGUARD_ALLOW_UNSIGNED": "allow_unsigned",
            "MODELGUARD_SCAN_ON_LOAD": "scan_on_load",
            "MODELGUARD_MAX_FILE_SIZE_MB": "max_file_size_mb",
            "MODELGUARD_TIMEOUT_SECONDS": "timeout_seconds",
        }

        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                if config_key in [
                    "enforce", "require_signatures", "allow_unsigned", "scan_on_load"
                ]:
                    config_data[config_key] = value.lower() in (
                        "true", "1", "yes", "on"
                    )
                elif config_key in ["max_file_size_mb", "timeout_seconds"]:
                    config_data[config_key] = int(value)
                elif config_key == "trusted_signers":
                    config_data[config_key] = [
                        s.strip() for s in value.split(",") if s.strip()
                    ]
                else:
                    config_data[config_key] = value

        config = PolicyConfig(**config_data)
        return cls(config)

    def should_enforce(self) -> bool:
        """Check if enforcement mode is enabled."""
        return self.config.enforce

    def requires_signatures(self) -> bool:
        """Check if signatures are required."""
        return self.config.require_signatures

    def is_signer_trusted(self, signer: str) -> bool:
        """Check if a signer is trusted."""
        if not self.config.trusted_signers:
            return True  # If no trusted signers specified, trust all
        return signer in self.config.trusted_signers

    def should_scan(self) -> bool:
        """Check if models should be scanned."""
        return self.config.scan_on_load

    def get_max_file_size(self) -> int:
        """Get maximum file size in bytes."""
        return self.config.max_file_size_mb * 1024 * 1024

    def get_timeout(self) -> int:
        """Get timeout in seconds."""
        return self.config.timeout_seconds


def load_policy() -> Policy:
    """
    Load policy with precedence: CLI args > ENV vars > YAML config > defaults.
    
    For now, only supports ENV vars and YAML config.
    """
    # Try to load from YAML files in order of precedence
    config_paths = [
        Path.cwd() / "modelguard.yaml",
        Path.cwd() / ".modelguard.yaml",
        Path.home() / ".config" / "modelguard" / "config.yaml",
    ]

    # Check XDG_CONFIG_HOME
    xdg_config = os.getenv("XDG_CONFIG_HOME")
    if xdg_config:
        config_paths.insert(-1, Path(xdg_config) / "modelguard" / "config.yaml")

    # Load from first existing config file
    yaml_policy = None
    for path in config_paths:
        if path.exists():
            yaml_policy = Policy.from_file(path)
            break

    # Load from environment (higher precedence)
    env_policy = Policy.from_env()

    # Merge policies (env overrides yaml)
    if yaml_policy and env_policy:
        # Create merged config
        yaml_data = yaml_policy.config.dict()
        env_data = env_policy.config.dict()

        # Only override with env values that were actually set
        merged_data = yaml_data.copy()
        for key, value in env_data.items():
            env_var = f"MODELGUARD_{key.upper()}"
            if os.getenv(env_var) is not None:
                merged_data[key] = value

        merged_config = PolicyConfig(**merged_data)
        return Policy(merged_config)

    return env_policy or yaml_policy or Policy()
