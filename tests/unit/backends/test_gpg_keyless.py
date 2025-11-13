"""Unit tests for backends/gpg_keyless.py module."""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, mock_open, patch

from signer.backends.gpg_keyless import GPGKeylessBackend
from signer.backends.base import Signature
from signer.identity import OIDCIdentity, StaticKeyIdentity


class TestGPGKeylessBackend:
    """Tests for GPGKeylessBackend class."""

    @pytest.fixture
    def sample_identity(self, mock_oidc_token):
        """Create sample OIDC identity."""
        token, payload = mock_oidc_token
        return OIDCIdentity(
            token=token,
            issuer=payload["iss"],
            subject=payload["sub"],
            claims=payload,
        )

    def test_init_default_config(self):
        """Test initialization with default configuration."""
        backend = GPGKeylessBackend()

        assert backend.key_type == "Ed25519"
        assert backend.keyless_mode is True
        assert backend.public_key_export is True

    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            "key_type": "RSA",
            "keyless_mode": False,
            "public_key_export": False,
        }

        backend = GPGKeylessBackend(config=config)

        assert backend.key_type == "RSA"
        assert backend.keyless_mode is False
        assert backend.public_key_export is False

    def test_supports_keyless(self):
        """Test supports_keyless returns True."""
        backend = GPGKeylessBackend()
        assert backend.supports_keyless() is True

    def test_get_format(self):
        """Test get_format returns 'gpg'."""
        backend = GPGKeylessBackend()
        assert backend.get_format() == "gpg"

    def test_sign_invalid_identity_type(self):
        """Test sign raises error with non-OIDC identity."""
        backend = GPGKeylessBackend()
        static_identity = StaticKeyIdentity(key_id="KEY123", key_type="gpg")

        with pytest.raises(ValueError, match="requires OIDCIdentity"):
            backend.sign(b"artifact data", static_identity)

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    @patch("signer.backends.gpg_keyless.tempfile.NamedTemporaryFile")
    @patch("signer.backends.gpg_keyless.Path")
    def test_sign_success(
        self,
        mock_path_class,
        mock_named_temp,
        mock_temp_dir,
        mock_gpg_class,
        sample_identity,
    ):
        """Test successful signing with ephemeral GPG key."""
        # Mock temporary directory
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        # Mock GPG instance
        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        # Mock key generation
        mock_key = Mock()
        mock_key.__str__ = Mock(return_value="ABCD1234EFGH5678")
        mock_gpg.gen_key.return_value = mock_key

        # Mock signing
        mock_signed = Mock()
        mock_signed.__bool__ = Mock(return_value=True)
        mock_gpg.sign_file.return_value = mock_signed

        # Mock public key export
        mock_gpg.export_keys.return_value = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmock key\n-----END PGP PUBLIC KEY BLOCK-----\n"

        # Mock temporary artifact file
        mock_temp_file = Mock()
        mock_temp_file.name = "/tmp/artifact.bin"
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        # Mock file operations
        mock_path = Mock()
        mock_path.name = "artifact.bin.asc"
        mock_path_class.return_value = mock_path

        # Mock reading signature file
        with patch("builtins.open", mock_open(read_data=b"mock signature data")):
            backend = GPGKeylessBackend()
            signature = backend.sign(b"test artifact", sample_identity)

        # Verify signature
        assert isinstance(signature, Signature)
        assert signature.format == "gpg"
        assert signature.data == b"mock signature data"
        assert signature.metadata["keyless"] is True
        assert signature.metadata["algorithm"] == "EdDSA"
        assert signature.metadata["key_fingerprint"] == "ABCD1234EFGH5678"
        assert signature.metadata["subject"] == sample_identity.subject
        assert "signature" in signature.files
        assert "public_key" in signature.files

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    def test_sign_key_generation_failure(
        self, mock_temp_dir, mock_gpg_class, sample_identity
    ):
        """Test sign raises error when key generation fails."""
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        # Mock failed key generation (returns empty string)
        mock_key = Mock()
        mock_key.__str__ = Mock(return_value="")
        mock_key.stderr = "Key generation error"
        mock_gpg.gen_key.return_value = mock_key

        backend = GPGKeylessBackend()

        with pytest.raises(RuntimeError, match="Failed to generate GPG key"):
            backend.sign(b"artifact", sample_identity)

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    @patch("signer.backends.gpg_keyless.tempfile.NamedTemporaryFile")
    def test_sign_signing_failure(
        self, mock_named_temp, mock_temp_dir, mock_gpg_class, sample_identity
    ):
        """Test sign raises error when signing fails."""
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        # Mock successful key generation
        mock_key = Mock()
        mock_key.__str__ = Mock(return_value="KEY123")
        mock_gpg.gen_key.return_value = mock_key

        # Mock failed signing
        mock_signed = Mock()
        mock_signed.__bool__ = Mock(return_value=False)
        mock_signed.stderr = "Signing failed"
        mock_gpg.sign_file.return_value = mock_signed

        # Mock temporary file
        mock_temp_file = Mock()
        mock_temp_file.name = "/tmp/artifact.bin"
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        with patch("builtins.open", mock_open()):
            backend = GPGKeylessBackend()

            with pytest.raises(RuntimeError, match="GPG signing failed"):
                backend.sign(b"artifact", sample_identity)

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    def test_verify_success(self, mock_temp_dir, mock_gpg_class, tmp_path):
        """Test successful signature verification."""
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        # Mock key import
        mock_import = Mock()
        mock_import.count = 1
        mock_gpg.import_keys.return_value = mock_import

        # Mock verification
        mock_verified = Mock()
        mock_verified.valid = True
        mock_gpg.verify_file.return_value = mock_verified

        # Create temporary signature files
        sig_file = tmp_path / "artifact.sig"
        sig_file.write_bytes(b"signature data")

        pub_file = tmp_path / "artifact.pub"
        pub_file.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----\n")

        signature = Signature(
            format="gpg",
            data=b"signature data",
            metadata={"keyless": True},
            files={
                "signature": str(sig_file),
                "public_key": str(pub_file),
            },
        )

        backend = GPGKeylessBackend()
        result = backend.verify(b"test artifact", signature)

        assert result is True

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    def test_verify_missing_public_key(self, mock_temp_dir, mock_gpg_class):
        """Test verification fails when public key is missing."""
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        signature = Signature(
            format="gpg",
            data=b"signature data",
            metadata={},
            files={
                "signature": "/nonexistent/artifact.sig",
                # No public_key
            },
        )

        backend = GPGKeylessBackend()
        result = backend.verify(b"artifact", signature)

        assert result is False

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    def test_verify_key_import_failure(self, mock_temp_dir, mock_gpg_class, tmp_path):
        """Test verification fails when key import fails."""
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        # Mock failed key import
        mock_import = Mock()
        mock_import.count = 0  # No keys imported
        mock_gpg.import_keys.return_value = mock_import

        # Create public key file
        pub_file = tmp_path / "artifact.pub"
        pub_file.write_text("invalid key")

        signature = Signature(
            format="gpg",
            data=b"sig",
            metadata={},
            files={
                "signature": "/tmp/artifact.sig",
                "public_key": str(pub_file),
            },
        )

        backend = GPGKeylessBackend()
        result = backend.verify(b"artifact", signature)

        assert result is False

    @patch("signer.backends.gpg_keyless.gnupg.GPG")
    @patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory")
    def test_verify_invalid_signature(self, mock_temp_dir, mock_gpg_class, tmp_path):
        """Test verification fails for invalid signature."""
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        # Mock successful key import
        mock_import = Mock()
        mock_import.count = 1
        mock_gpg.import_keys.return_value = mock_import

        # Mock failed verification
        mock_verified = Mock()
        mock_verified.valid = False
        mock_verified.status = "signature bad"
        mock_verified.stderr = "verification failed"
        mock_verified.trust_level = None
        mock_verified.trust_text = None
        mock_gpg.verify_file.return_value = mock_verified

        # Create files
        sig_file = tmp_path / "artifact.sig"
        sig_file.write_bytes(b"bad signature")

        pub_file = tmp_path / "artifact.pub"
        pub_file.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----\n")

        signature = Signature(
            format="gpg",
            data=b"bad signature",
            metadata={},
            files={
                "signature": str(sig_file),
                "public_key": str(pub_file),
            },
        )

        backend = GPGKeylessBackend()
        result = backend.verify(b"artifact", signature)

        assert result is False

    def test_get_verification_command(self, tmp_path):
        """Test get_verification_command generates correct command."""
        sig_file = tmp_path / "artifact.sig"
        pub_file = tmp_path / "artifact.pub"

        signature = Signature(
            format="gpg",
            data=b"sig",
            metadata={},
            files={
                "signature": str(sig_file),
                "public_key": str(pub_file),
            },
        )

        backend = GPGKeylessBackend()
        cmd = backend.get_verification_command("artifact.txt", signature)

        assert "gpg --import" in cmd
        assert "artifact.pub" in cmd
        assert "gpg --verify" in cmd
        assert "artifact.sig" in cmd
        assert "artifact.txt" in cmd

    def test_sign_metadata_structure(self, sample_identity):
        """Test sign creates correct metadata structure."""
        with patch("signer.backends.gpg_keyless.gnupg.GPG") as mock_gpg_class:
            with patch("signer.backends.gpg_keyless.tempfile.TemporaryDirectory") as mock_temp_dir:
                with patch("signer.backends.gpg_keyless.tempfile.NamedTemporaryFile") as mock_named_temp:
                    # Setup mocks
                    mock_temp_dir.return_value.__enter__.return_value = "/tmp/gpghome"
                    mock_gpg = MagicMock()
                    mock_gpg_class.return_value = mock_gpg

                    mock_key = Mock()
                    mock_key.__str__ = Mock(return_value="FINGERPRINT123")
                    mock_gpg.gen_key.return_value = mock_key

                    mock_signed = Mock()
                    mock_signed.__bool__ = Mock(return_value=True)
                    mock_gpg.sign_file.return_value = mock_signed

                    mock_gpg.export_keys.return_value = "public key"

                    mock_temp_file = Mock()
                    mock_temp_file.name = "/tmp/artifact.bin"
                    mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
                    mock_temp_file.__exit__ = Mock(return_value=None)
                    mock_named_temp.return_value = mock_temp_file

                    with patch("builtins.open", mock_open(read_data=b"sig")):
                        with patch("signer.backends.gpg_keyless.Path"):
                            backend = GPGKeylessBackend()
                            sig = backend.sign(b"artifact", sample_identity)

                    # Check metadata fields
                    assert sig.metadata["keyless"] is True
                    assert sig.metadata["algorithm"] == "EdDSA"
                    assert sig.metadata["key_type"] == "Ed25519"
                    assert sig.metadata["key_fingerprint"] == "FINGERPRINT123"
                    assert sig.metadata["key_id"] == "ephemeral:FINGERPRINT123"
                    assert sig.metadata["subject"] == sample_identity.subject
                    assert sig.metadata["subject_hash"] == sample_identity.subject_hash
                    assert sig.metadata["issuer"] == sample_identity.issuer
                    assert "verification_command" in sig.metadata
