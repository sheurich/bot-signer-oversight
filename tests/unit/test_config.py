"""Unit tests for config.py module."""

import os
import tempfile
import pytest
from pathlib import Path

from signer.config import (
    SigningConfig,
    ConfigError,
    load_config,
    find_default_config,
)


class TestSigningConfig:
    """Tests for SigningConfig class."""

    def test_init_empty(self):
        """Test initializing with empty config."""
        config = SigningConfig({})

        assert config.data == {}
        assert config.get_enabled_backends() == []
        assert config.get_policies() == []

    def test_init_with_backends(self):
        """Test initializing with backend configuration."""
        data = {
            "backends": {
                "gpg": {"enabled": True, "key_type": "Ed25519"},
                "cosign": {"enabled": False},
            }
        }
        config = SigningConfig(data)

        assert config.get_enabled_backends() == ["gpg"]
        assert config.get_backend_config("gpg") == {
            "enabled": True,
            "key_type": "Ed25519",
        }

    def test_init_with_policies(self):
        """Test initializing with policies."""
        data = {
            "policies": [
                {"match": "*.tar.gz", "require": ["gpg", "cosign"]},
                {"match": "*.txt", "require": ["gpg"]},
            ]
        }
        config = SigningConfig(data)

        policies = config.get_policies()
        assert len(policies) == 2
        assert policies[0]["match"] == "*.tar.gz"

    def test_validation_invalid_backends_type(self):
        """Test validation fails with invalid backends type."""
        data = {"backends": "not-a-dict"}

        with pytest.raises(ConfigError, match="backends must be a dictionary"):
            SigningConfig(data)

    def test_validation_invalid_backend_config(self):
        """Test validation fails with invalid backend config."""
        data = {"backends": {"gpg": "not-a-dict"}}

        with pytest.raises(ConfigError, match="backends.gpg must be a dictionary"):
            SigningConfig(data)

    def test_validation_invalid_enabled_type(self):
        """Test validation fails with invalid enabled type."""
        data = {"backends": {"gpg": {"enabled": "yes"}}}

        with pytest.raises(ConfigError, match="backends.gpg.enabled must be boolean"):
            SigningConfig(data)

    def test_validation_invalid_policies_type(self):
        """Test validation fails with invalid policies type."""
        data = {"policies": "not-a-list"}

        with pytest.raises(ConfigError, match="policies must be a list"):
            SigningConfig(data)

    def test_validation_invalid_policy_item(self):
        """Test validation fails with invalid policy item."""
        data = {"policies": ["not-a-dict"]}

        with pytest.raises(ConfigError, match="policies\\[0\\] must be a dictionary"):
            SigningConfig(data)

    def test_validation_missing_policy_match(self):
        """Test validation fails with missing policy match."""
        data = {"policies": [{"require": ["gpg"]}]}

        with pytest.raises(ConfigError, match="policies\\[0\\] missing required 'match'"):
            SigningConfig(data)

    def test_validation_missing_policy_require(self):
        """Test validation fails with missing policy require."""
        data = {"policies": [{"match": "*.tar.gz"}]}

        with pytest.raises(
            ConfigError, match="policies\\[0\\] missing required 'require'"
        ):
            SigningConfig(data)

    def test_validation_invalid_policy_require_type(self):
        """Test validation fails with invalid require type."""
        data = {"policies": [{"match": "*.tar.gz", "require": "gpg"}]}

        with pytest.raises(ConfigError, match="policies\\[0\\].require must be a list"):
            SigningConfig(data)


class TestGetEnabledBackends:
    """Tests for get_enabled_backends method."""

    def test_no_backends(self):
        """Test with no backends configured."""
        config = SigningConfig({})

        assert config.get_enabled_backends() == []

    def test_all_enabled(self):
        """Test with all backends enabled."""
        data = {
            "backends": {
                "gpg": {"enabled": True},
                "cosign": {"enabled": True},
            }
        }
        config = SigningConfig(data)

        backends = config.get_enabled_backends()
        assert set(backends) == {"gpg", "cosign"}

    def test_some_disabled(self):
        """Test with some backends disabled."""
        data = {
            "backends": {
                "gpg": {"enabled": True},
                "cosign": {"enabled": False},
                "intoto": {"enabled": True},
            }
        }
        config = SigningConfig(data)

        backends = config.get_enabled_backends()
        assert set(backends) == {"gpg", "intoto"}

    def test_default_enabled(self):
        """Test that backends without enabled field default to enabled."""
        data = {"backends": {"gpg": {}, "cosign": {"enabled": False}}}
        config = SigningConfig(data)

        assert config.get_enabled_backends() == ["gpg"]


class TestGetBackendConfig:
    """Tests for get_backend_config method."""

    def test_existing_backend(self):
        """Test getting config for existing backend."""
        data = {"backends": {"gpg": {"key_type": "Ed25519", "enabled": True}}}
        config = SigningConfig(data)

        backend_config = config.get_backend_config("gpg")
        assert backend_config == {"key_type": "Ed25519", "enabled": True}

    def test_nonexistent_backend(self):
        """Test getting config for nonexistent backend."""
        config = SigningConfig({})

        backend_config = config.get_backend_config("gpg")
        assert backend_config == {}


class TestGetRequiredBackends:
    """Tests for get_required_backends method."""

    def test_no_policies(self):
        """Test with no policies configured."""
        config = SigningConfig({})

        result = config.get_required_backends("test.tar.gz")
        assert result is None

    def test_policy_match(self):
        """Test with matching policy."""
        data = {
            "policies": [
                {"match": "*.tar.gz", "require": ["gpg", "cosign"]},
            ]
        }
        config = SigningConfig(data)

        result = config.get_required_backends("release.tar.gz")
        assert result == ["gpg", "cosign"]

    def test_policy_no_match(self):
        """Test with no matching policy."""
        data = {
            "policies": [
                {"match": "*.tar.gz", "require": ["gpg"]},
            ]
        }
        config = SigningConfig(data)

        result = config.get_required_backends("release.zip")
        assert result is None


class TestMergeWithCliArgs:
    """Tests for merge_with_cli_args method."""

    def test_merge_backends(self):
        """Test merging backend selection."""
        data = {
            "backends": {
                "gpg": {"enabled": True},
                "cosign": {"enabled": True},
            }
        }
        config = SigningConfig(data)

        merged = config.merge_with_cli_args(backends=["gpg"])

        assert merged.get_enabled_backends() == ["gpg"]

    def test_merge_backend_configs(self):
        """Test merging backend configurations."""
        data = {
            "backends": {
                "gpg": {"key_type": "Ed25519"},
            }
        }
        config = SigningConfig(data)

        merged = config.merge_with_cli_args(
            backend_configs={"gpg": {"key_type": "RSA"}}
        )

        assert merged.get_backend_config("gpg")["key_type"] == "RSA"

    def test_merge_no_changes(self):
        """Test merge with no CLI args."""
        data = {"backends": {"gpg": {"enabled": True}}}
        config = SigningConfig(data)

        merged = config.merge_with_cli_args()

        assert merged.get_enabled_backends() == ["gpg"]


class TestEnvironmentOverrides:
    """Tests for apply_environment_overrides method."""

    def test_fulcio_url_override(self):
        """Test Fulcio URL environment override."""
        data = {"backends": {"cosign": {}}}
        config = SigningConfig(data)

        os.environ["SIGNER_FULCIO_URL"] = "https://test.fulcio.dev"
        try:
            merged = config.apply_environment_overrides()
            assert (
                merged.get_backend_config("cosign")["fulcio_url"]
                == "https://test.fulcio.dev"
            )
        finally:
            del os.environ["SIGNER_FULCIO_URL"]

    def test_rekor_url_override(self):
        """Test Rekor URL environment override."""
        data = {"backends": {"cosign": {}}}
        config = SigningConfig(data)

        os.environ["SIGNER_REKOR_URL"] = "https://test.rekor.dev"
        try:
            merged = config.apply_environment_overrides()
            assert (
                merged.get_backend_config("cosign")["rekor_url"]
                == "https://test.rekor.dev"
            )
        finally:
            del os.environ["SIGNER_REKOR_URL"]

    def test_gpg_key_type_override(self):
        """Test GPG key type environment override."""
        data = {"backends": {"gpg": {"key_type": "Ed25519"}}}
        config = SigningConfig(data)

        os.environ["SIGNER_GPG_KEY_TYPE"] = "RSA"
        try:
            merged = config.apply_environment_overrides()
            assert merged.get_backend_config("gpg")["key_type"] == "RSA"
        finally:
            del os.environ["SIGNER_GPG_KEY_TYPE"]

    def test_no_overrides(self):
        """Test with no environment variables set."""
        data = {"backends": {"gpg": {"key_type": "Ed25519"}}}
        config = SigningConfig(data)

        merged = config.apply_environment_overrides()

        assert merged.get_backend_config("gpg")["key_type"] == "Ed25519"


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_valid_config(self):
        """Test loading valid YAML config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("backends:\n  gpg:\n    enabled: true\n")
            config_path = f.name

        try:
            config = load_config(config_path)
            assert config.get_enabled_backends() == ["gpg"]
        finally:
            os.unlink(config_path)

    def test_load_nonexistent_file(self):
        """Test loading nonexistent file."""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_load_invalid_yaml(self):
        """Test loading invalid YAML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: syntax:\n")
            config_path = f.name

        try:
            with pytest.raises(ConfigError, match="Invalid YAML"):
                load_config(config_path)
        finally:
            os.unlink(config_path)

    def test_load_empty_file(self):
        """Test loading empty file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_path = f.name

        try:
            config = load_config(config_path)
            assert config.data == {}
        finally:
            os.unlink(config_path)


class TestFindDefaultConfig:
    """Tests for find_default_config function."""

    def test_find_in_current_directory(self):
        """Test finding config in current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / ".signing"
            config_dir.mkdir()
            config_path = config_dir / "config.yaml"
            config_path.write_text("backends: {}")

            # Change to temp directory
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                result = find_default_config()
                # Resolve both paths to handle symlinks (macOS /var -> /private/var)
                assert result.resolve() == config_path.resolve()
            finally:
                os.chdir(old_cwd)

    def test_find_in_parent_directory(self):
        """Test finding config in parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create config in parent
            config_dir = Path(tmpdir) / ".signing"
            config_dir.mkdir()
            config_path = config_dir / "config.yaml"
            config_path.write_text("backends: {}")

            # Create subdirectory
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()

            # Change to subdirectory
            old_cwd = os.getcwd()
            os.chdir(subdir)
            try:
                result = find_default_config()
                # Resolve both paths to handle symlinks (macOS /var -> /private/var)
                assert result.resolve() == config_path.resolve()
            finally:
                os.chdir(old_cwd)

    def test_not_found(self):
        """Test when config is not found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                result = find_default_config()
                # May find one in home directory or return None
                assert result is None or result.exists()
            finally:
                os.chdir(old_cwd)
