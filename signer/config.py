"""Configuration file loading and validation."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from .policy import Policy, PolicyEngine


class ConfigError(Exception):
    """Configuration validation error."""
    pass


class SigningConfig:
    """Configuration for signing operations."""

    def __init__(self, data: Dict[str, Any]):
        """
        Initialize configuration from dictionary.

        Args:
            data: Configuration dictionary from YAML
        """
        self.data = data
        self._validate()

    def _validate(self) -> None:
        """Validate configuration schema."""
        # Validate backends section
        if "backends" in self.data:
            backends = self.data["backends"]
            if not isinstance(backends, dict):
                raise ConfigError("backends must be a dictionary")

            # Validate each backend configuration
            for backend_name, backend_config in backends.items():
                if not isinstance(backend_config, dict):
                    raise ConfigError(
                        f"backends.{backend_name} must be a dictionary"
                    )

                # Check if backend is enabled
                if "enabled" in backend_config:
                    if not isinstance(backend_config["enabled"], bool):
                        raise ConfigError(
                            f"backends.{backend_name}.enabled must be boolean"
                        )

        # Validate policies section
        if "policies" in self.data:
            policies = self.data["policies"]
            if not isinstance(policies, list):
                raise ConfigError("policies must be a list")

            for idx, policy in enumerate(policies):
                if not isinstance(policy, dict):
                    raise ConfigError(f"policies[{idx}] must be a dictionary")

                if "match" not in policy:
                    raise ConfigError(f"policies[{idx}] missing required 'match' field")

                if "require" not in policy:
                    raise ConfigError(
                        f"policies[{idx}] missing required 'require' field"
                    )

                if not isinstance(policy["require"], list):
                    raise ConfigError(f"policies[{idx}].require must be a list")

    def get_enabled_backends(self) -> List[str]:
        """
        Get list of enabled backend names.

        Returns:
            List of enabled backend names
        """
        backends = self.data.get("backends", {})
        return [
            name
            for name, config in backends.items()
            if config.get("enabled", True)
        ]

    def get_backend_config(self, backend_name: str) -> Dict[str, Any]:
        """
        Get configuration for specific backend.

        Args:
            backend_name: Name of backend (e.g., "gpg", "cosign")

        Returns:
            Backend configuration dictionary
        """
        return self.data.get("backends", {}).get(backend_name, {})

    def get_policies(self) -> List[Dict[str, Any]]:
        """
        Get list of policy rules as dictionaries.

        Returns:
            List of policy dictionaries
        """
        return self.data.get("policies", [])

    def get_policy_engine(self) -> PolicyEngine:
        """
        Get PolicyEngine instance from configuration.

        Returns:
            PolicyEngine with configured policies
        """
        policy_list = []
        for policy_dict in self.get_policies():
            policy = Policy(
                match=policy_dict.get("match", "*"),
                require=policy_dict.get("require", []),
                min_signatures=policy_dict.get("min_signatures", 1),
                allow_expired=policy_dict.get("allow_expired", False),
            )
            policy_list.append(policy)

        return PolicyEngine(policy_list)

    def get_required_backends(self, artifact_path: str) -> Optional[List[str]]:
        """
        Get required backends for artifact based on policies.

        Args:
            artifact_path: Path to artifact

        Returns:
            List of required backend names, or None if no policy matches
        """
        policy_engine = self.get_policy_engine()
        required = policy_engine.get_required_backends(artifact_path)
        return required if required else None

    def merge_with_cli_args(
        self,
        backends: Optional[List[str]] = None,
        backend_configs: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> "SigningConfig":
        """
        Merge configuration with CLI arguments.
        CLI arguments take precedence over config file.

        Args:
            backends: List of backend names from CLI
            backend_configs: Backend-specific configs from CLI

        Returns:
            New SigningConfig with merged values
        """
        merged = self.data.copy()

        # Merge backends if specified
        if backends:
            # If specific backends are requested, enable only those
            for backend_name in merged.get("backends", {}).keys():
                if backend_name in backends:
                    merged["backends"][backend_name]["enabled"] = True
                else:
                    merged["backends"][backend_name]["enabled"] = False

        # Merge backend configs if specified
        if backend_configs:
            if "backends" not in merged:
                merged["backends"] = {}

            for backend_name, config in backend_configs.items():
                if backend_name not in merged["backends"]:
                    merged["backends"][backend_name] = {}
                merged["backends"][backend_name].update(config)

        return SigningConfig(merged)

    def apply_environment_overrides(self) -> "SigningConfig":
        """
        Apply environment variable overrides.

        Environment variables:
        - SIGNER_FULCIO_URL: Override Fulcio URL
        - SIGNER_REKOR_URL: Override Rekor URL
        - SIGNER_GPG_KEY_TYPE: Override GPG key type

        Returns:
            New SigningConfig with environment overrides applied
        """
        merged = self.data.copy()

        # Apply Fulcio URL override
        fulcio_url = os.getenv("SIGNER_FULCIO_URL")
        if fulcio_url:
            if "backends" not in merged:
                merged["backends"] = {}
            if "cosign" not in merged["backends"]:
                merged["backends"]["cosign"] = {}
            merged["backends"]["cosign"]["fulcio_url"] = fulcio_url

        # Apply Rekor URL override
        rekor_url = os.getenv("SIGNER_REKOR_URL")
        if rekor_url:
            if "backends" not in merged:
                merged["backends"] = {}
            if "cosign" not in merged["backends"]:
                merged["backends"]["cosign"] = {}
            merged["backends"]["cosign"]["rekor_url"] = rekor_url

        # Apply GPG key type override
        gpg_key_type = os.getenv("SIGNER_GPG_KEY_TYPE")
        if gpg_key_type:
            if "backends" not in merged:
                merged["backends"] = {}
            if "gpg" not in merged["backends"]:
                merged["backends"]["gpg"] = {}
            merged["backends"]["gpg"]["key_type"] = gpg_key_type

        return SigningConfig(merged)


def load_config(config_path: str) -> SigningConfig:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        SigningConfig instance

    Raises:
        ConfigError: If config file is invalid
        FileNotFoundError: If config file doesn't exist
    """
    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in config file: {e}")

    if data is None:
        data = {}

    return SigningConfig(data)


def find_default_config() -> Optional[Path]:
    """
    Find default configuration file.

    Searches for .signing/config.yaml in:
    1. Current directory
    2. Parent directories up to git root
    3. Home directory

    Returns:
        Path to config file, or None if not found
    """
    # Check current directory and parents
    current = Path.cwd()
    while True:
        config_path = current / ".signing" / "config.yaml"
        if config_path.exists():
            return config_path

        # Check if we're at git root
        if (current / ".git").exists():
            break

        # Move to parent
        parent = current.parent
        if parent == current:  # Reached filesystem root
            break
        current = parent

    # Check home directory
    home_config = Path.home() / ".signing" / "config.yaml"
    if home_config.exists():
        return home_config

    return None


def load_default_config() -> Optional[SigningConfig]:
    """
    Load configuration from default location.

    Returns:
        SigningConfig if found, None otherwise
    """
    config_path = find_default_config()
    if config_path:
        return load_config(str(config_path))
    return None
