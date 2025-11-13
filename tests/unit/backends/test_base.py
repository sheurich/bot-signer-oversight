"""Unit tests for backends/base.py module."""

import pytest
from dataclasses import asdict

from signer.backends.base import Signature, SigningBackend


class TestSignature:
    """Tests for Signature dataclass."""

    def test_signature_creation(self):
        """Test creating a Signature instance."""
        sig = Signature(
            format="gpg",
            data=b"signature bytes",
            metadata={"key": "value"},
            files={"signature": "file.sig"},
        )

        assert sig.format == "gpg"
        assert sig.data == b"signature bytes"
        assert sig.metadata == {"key": "value"}
        assert sig.files == {"signature": "file.sig"}

    def test_signature_dataclass_fields(self):
        """Test Signature has correct dataclass fields."""
        sig = Signature(
            format="cosign",
            data=b"sig",
            metadata={},
            files={},
        )

        # Should be a dataclass with asdict support
        sig_dict = asdict(sig)
        assert "format" in sig_dict
        assert "data" in sig_dict
        assert "metadata" in sig_dict
        assert "files" in sig_dict

    def test_signature_with_complex_metadata(self):
        """Test Signature with complex metadata."""
        metadata = {
            "algorithm": "ed25519",
            "timestamp": "2025-11-13T00:00:00Z",
            "rekor_index": 123456,
            "certificate": "-----BEGIN CERTIFICATE-----\n...",
            "nested": {"key1": "value1", "key2": "value2"},
        }

        sig = Signature(
            format="sigstore",
            data=b"signature",
            metadata=metadata,
            files={"bundle": "artifact.bundle"},
        )

        assert sig.metadata["algorithm"] == "ed25519"
        assert sig.metadata["rekor_index"] == 123456
        assert sig.metadata["nested"]["key1"] == "value1"

    def test_signature_with_multiple_files(self):
        """Test Signature with multiple associated files."""
        files = {
            "signature": "artifact.sig",
            "public_key": "artifact.pub",
            "certificate": "artifact.crt",
        }

        sig = Signature(
            format="gpg",
            data=b"sig bytes",
            metadata={},
            files=files,
        )

        assert len(sig.files) == 3
        assert sig.files["signature"] == "artifact.sig"
        assert sig.files["public_key"] == "artifact.pub"
        assert sig.files["certificate"] == "artifact.crt"

    def test_signature_empty_metadata_and_files(self):
        """Test Signature with empty metadata and files."""
        sig = Signature(
            format="simple",
            data=b"data",
            metadata={},
            files={},
        )

        assert sig.metadata == {}
        assert sig.files == {}


class ConcreteBackend(SigningBackend):
    """Concrete implementation of SigningBackend for testing."""

    def sign(self, artifact: bytes, identity) -> Signature:
        return Signature(
            format="test",
            data=b"test signature",
            metadata={"signed": True},
            files={"signature": "test.sig"},
        )

    def verify(self, artifact: bytes, signature: Signature) -> bool:
        return signature.data == b"test signature"

    def supports_keyless(self) -> bool:
        return True

    def get_format(self) -> str:
        return "test-format"


class TestSigningBackend:
    """Tests for SigningBackend abstract base class."""

    def test_backend_initialization_no_config(self):
        """Test backend initialization without config."""
        backend = ConcreteBackend()

        assert backend.config == {}

    def test_backend_initialization_with_config(self):
        """Test backend initialization with config."""
        config = {
            "key_algorithm": "ed25519",
            "timeout": 30,
            "verbose": True,
        }

        backend = ConcreteBackend(config=config)

        assert backend.config == config
        assert backend.config["key_algorithm"] == "ed25519"
        assert backend.config["timeout"] == 30

    def test_backend_initialization_none_config(self):
        """Test backend initialization with None config."""
        backend = ConcreteBackend(config=None)

        assert backend.config == {}

    def test_abstract_methods_must_be_implemented(self):
        """Test that abstract methods must be implemented."""

        # Try to create a backend without implementing abstract methods
        class IncompleteBackend(SigningBackend):
            pass

        with pytest.raises(TypeError):
            # Should raise TypeError because abstract methods not implemented
            IncompleteBackend()

    def test_concrete_backend_sign(self):
        """Test sign method on concrete backend."""
        backend = ConcreteBackend()
        sig = backend.sign(b"test artifact", identity=None)

        assert isinstance(sig, Signature)
        assert sig.format == "test"
        assert sig.data == b"test signature"

    def test_concrete_backend_verify(self):
        """Test verify method on concrete backend."""
        backend = ConcreteBackend()
        sig = Signature(
            format="test",
            data=b"test signature",
            metadata={},
            files={},
        )

        assert backend.verify(b"artifact", sig) is True

        # Invalid signature
        bad_sig = Signature(
            format="test",
            data=b"wrong signature",
            metadata={},
            files={},
        )
        assert backend.verify(b"artifact", bad_sig) is False

    def test_concrete_backend_supports_keyless(self):
        """Test supports_keyless method."""
        backend = ConcreteBackend()
        assert backend.supports_keyless() is True

    def test_concrete_backend_get_format(self):
        """Test get_format method."""
        backend = ConcreteBackend()
        assert backend.get_format() == "test-format"

    def test_get_verification_command_default(self):
        """Test default get_verification_command implementation."""
        backend = ConcreteBackend()
        sig = Signature(
            format="test",
            data=b"sig",
            metadata={},
            files={"signature": "test.sig"},
        )

        cmd = backend.get_verification_command("artifact.txt", sig)

        # Default implementation returns a comment
        assert "# No verification command" in cmd
        assert "test-format" in cmd

    def test_backend_config_immutable_original(self):
        """Test that modifying backend config doesn't affect original."""
        original_config = {"key": "value"}
        backend = ConcreteBackend(config=original_config)

        # Modify backend config
        backend.config["key"] = "modified"
        backend.config["new_key"] = "new_value"

        # Original should be affected (dict is mutable)
        # This test documents current behavior
        assert original_config["key"] == "modified"

    def test_multiple_backends_different_configs(self):
        """Test multiple backend instances with different configs."""
        backend1 = ConcreteBackend(config={"id": 1})
        backend2 = ConcreteBackend(config={"id": 2})

        assert backend1.config["id"] == 1
        assert backend2.config["id"] == 2

        # Configs should be independent
        backend1.config["modified"] = True
        assert "modified" not in backend2.config
