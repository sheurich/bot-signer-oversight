"""Unit tests for backends/sigstore.py module."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from signer.backends.sigstore import SigstoreBackend
from signer.backends.base import Signature
from signer.identity import OIDCIdentity, StaticKeyIdentity


class TestSigstoreBackend:
    """Tests for SigstoreBackend class."""

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

    @pytest.fixture
    def sample_bundle(self):
        """Create sample Cosign bundle."""
        return {
            "base64Signature": "base64_encoded_signature_data",
            "cert": "-----BEGIN CERTIFICATE-----\ncert_data\n-----END CERTIFICATE-----",
            "rekorBundle": {
                "Payload": {
                    "logIndex": 123456789,
                    "integratedTime": 1234567890,
                }
            },
        }

    def test_init_default_config(self):
        """Test initialization with default configuration."""
        backend = SigstoreBackend()

        assert backend.fulcio_url == "https://fulcio.sigstore.dev"
        assert backend.rekor_url == "https://rekor.sigstore.dev"
        assert backend.keyless_mode is True

    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            "fulcio_url": "https://custom-fulcio.example.com",
            "rekor_url": "https://custom-rekor.example.com",
            "keyless_mode": False,
        }

        backend = SigstoreBackend(config=config)

        assert backend.fulcio_url == "https://custom-fulcio.example.com"
        assert backend.rekor_url == "https://custom-rekor.example.com"
        assert backend.keyless_mode is False

    def test_supports_keyless(self):
        """Test supports_keyless returns True."""
        backend = SigstoreBackend()
        assert backend.supports_keyless() is True

    def test_get_format(self):
        """Test get_format returns 'cosign'."""
        backend = SigstoreBackend()
        assert backend.get_format() == "cosign"

    def test_sign_invalid_identity_type(self):
        """Test sign raises error with non-OIDC identity."""
        backend = SigstoreBackend()
        static_identity = StaticKeyIdentity(key_id="KEY123", key_type="cosign")

        with pytest.raises(ValueError, match="requires OIDCIdentity"):
            backend.sign(b"artifact data", static_identity)

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    @patch("signer.backends.sigstore.Path")
    def test_sign_success(
        self,
        mock_path_class,
        mock_named_temp,
        mock_subprocess,
        sample_identity,
        sample_bundle,
        tmp_path,
    ):
        """Test successful signing with Cosign."""
        # Mock temporary file
        artifact_file = tmp_path / "artifact.bin"
        mock_temp_file = Mock()
        mock_temp_file.name = str(artifact_file)
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        # Mock subprocess.run
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        # Mock bundle file reading
        bundle_json = json.dumps(sample_bundle)
        with patch("builtins.open", mock_open(read_data=bundle_json)):
            # Mock Path for cleanup
            mock_path = Mock()
            mock_path.unlink = Mock()
            mock_path_class.return_value = mock_path

            backend = SigstoreBackend()
            signature = backend.sign(b"test artifact", sample_identity)

        # Verify signature
        assert isinstance(signature, Signature)
        assert signature.format == "cosign"
        assert signature.data == b"base64_encoded_signature_data"
        assert signature.metadata["keyless"] is True
        assert signature.metadata["algorithm"] == "ECDSA"
        assert signature.metadata["key_type"] == "P-256"
        assert signature.metadata["subject"] == sample_identity.subject
        assert signature.metadata["issuer"] == sample_identity.issuer
        assert "bundle" in signature.files

        # Verify subprocess was called correctly
        mock_subprocess.assert_called_once()
        cmd = mock_subprocess.call_args[0][0]
        assert "cosign" in cmd
        assert "sign-blob" in cmd
        assert "--identity-token" in cmd
        assert sample_identity.token in cmd

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_sign_cosign_failure(
        self, mock_named_temp, mock_subprocess, sample_identity
    ):
        """Test sign raises error when cosign command fails."""
        # Mock temporary file
        mock_temp_file = Mock()
        mock_temp_file.name = "/tmp/artifact.bin"
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        # Mock failed subprocess
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["cosign", "sign-blob"],
            stderr="cosign error",
        )

        with patch("signer.backends.sigstore.Path"):
            backend = SigstoreBackend()

            with pytest.raises(subprocess.CalledProcessError):
                backend.sign(b"artifact", sample_identity)

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_sign_bundle_metadata_extraction(
        self, mock_named_temp, mock_subprocess, sample_identity, sample_bundle
    ):
        """Test metadata extraction from bundle."""
        # Setup mocks
        mock_temp_file = Mock()
        mock_temp_file.name = "/tmp/artifact.bin"
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        bundle_json = json.dumps(sample_bundle)
        with patch("builtins.open", mock_open(read_data=bundle_json)):
            with patch("signer.backends.sigstore.Path"):
                backend = SigstoreBackend()
                sig = backend.sign(b"artifact", sample_identity)

        # Check metadata extraction
        assert sig.metadata["certificate"] == sample_bundle["cert"]
        assert sig.metadata["rekor_index"] == 123456789
        assert sig.metadata["rekor_integrated_time"] == 1234567890

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_verify_success(self, mock_named_temp, mock_subprocess, tmp_path):
        """Test successful signature verification."""
        # Create bundle file
        bundle_file = tmp_path / "artifact.bundle"
        bundle_file.write_text('{"test": "bundle"}')

        # Mock temporary artifact file
        mock_temp_file = Mock()
        mock_temp_file.name = str(tmp_path / "artifact.bin")
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        # Mock successful verification
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Verified OK"
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result

        signature = Signature(
            format="cosign",
            data=b"signature",
            metadata={
                "issuer": "https://token.actions.githubusercontent.com",
            },
            files={"bundle": str(bundle_file)},
        )

        with patch("signer.backends.sigstore.Path"):
            backend = SigstoreBackend()
            result = backend.verify(b"test artifact", signature)

        assert result is True

        # Verify subprocess was called with correct args
        cmd = mock_subprocess.call_args[0][0]
        assert "cosign" in cmd
        assert "verify-blob" in cmd
        assert "--bundle" in cmd
        assert "--certificate-identity-regexp" in cmd
        assert "--certificate-oidc-issuer" in cmd

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_verify_missing_bundle(self, mock_named_temp, mock_subprocess):
        """Test verification fails when bundle file is missing."""
        signature = Signature(
            format="cosign",
            data=b"sig",
            metadata={"issuer": "https://issuer.example.com"},
            files={"bundle": "/nonexistent/bundle.json"},
        )

        backend = SigstoreBackend()
        result = backend.verify(b"artifact", signature)

        assert result is False
        mock_subprocess.assert_not_called()

    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_verify_missing_issuer(self, mock_named_temp):
        """Test verification fails when issuer is missing from metadata."""
        signature = Signature(
            format="cosign",
            data=b"sig",
            metadata={},  # No issuer
            files={"bundle": "/tmp/bundle.json"},
        )

        backend = SigstoreBackend()
        result = backend.verify(b"artifact", signature)

        assert result is False

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_verify_invalid_signature(self, mock_named_temp, mock_subprocess, tmp_path):
        """Test verification fails for invalid signature."""
        # Create bundle file
        bundle_file = tmp_path / "artifact.bundle"
        bundle_file.write_text('{"test": "bundle"}')

        # Mock temporary file
        mock_temp_file = Mock()
        mock_temp_file.name = str(tmp_path / "artifact.bin")
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        # Mock failed verification
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "verification failed"
        mock_subprocess.return_value = mock_result

        signature = Signature(
            format="cosign",
            data=b"bad signature",
            metadata={"issuer": "https://issuer.example.com"},
            files={"bundle": str(bundle_file)},
        )

        with patch("signer.backends.sigstore.Path"):
            backend = SigstoreBackend()
            result = backend.verify(b"artifact", signature)

        assert result is False

    def test_get_verification_command(self, tmp_path):
        """Test get_verification_command generates correct command."""
        bundle_file = tmp_path / "artifact.bundle"

        signature = Signature(
            format="cosign",
            data=b"sig",
            metadata={},
            files={"bundle": str(bundle_file)},
        )

        backend = SigstoreBackend()
        cmd = backend.get_verification_command("artifact.txt", signature)

        assert "cosign verify-blob" in cmd
        assert "--bundle" in cmd
        assert "artifact.bundle" in cmd
        assert "artifact.txt" in cmd

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_sign_verification_command_generation(
        self, mock_named_temp, mock_subprocess, sample_identity, sample_bundle
    ):
        """Test sign generates correct verification command."""
        # Setup mocks
        mock_temp_file = Mock()
        mock_temp_file.name = "/tmp/artifact.bin"
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        bundle_json = json.dumps(sample_bundle)
        with patch("builtins.open", mock_open(read_data=bundle_json)):
            with patch("signer.backends.sigstore.Path"):
                backend = SigstoreBackend()
                sig = backend.sign(b"artifact", sample_identity)

        # Check verification command
        cmd = sig.metadata["verification_command"]
        assert "cosign verify-blob" in cmd
        assert "--bundle" in cmd
        assert "--certificate-identity-regexp" in cmd
        assert "--certificate-oidc-issuer" in cmd
        assert sample_identity.issuer in cmd

    @patch("signer.backends.sigstore.subprocess.run")
    @patch("signer.backends.sigstore.tempfile.NamedTemporaryFile")
    def test_sign_with_minimal_bundle(
        self, mock_named_temp, mock_subprocess, sample_identity
    ):
        """Test sign handles bundle with minimal fields."""
        # Setup mocks
        mock_temp_file = Mock()
        mock_temp_file.name = "/tmp/artifact.bin"
        mock_temp_file.__enter__ = Mock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = Mock(return_value=None)
        mock_named_temp.return_value = mock_temp_file

        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        # Minimal bundle without cert and rekorBundle
        minimal_bundle = {
            "base64Signature": "sig_data",
        }

        bundle_json = json.dumps(minimal_bundle)
        with patch("builtins.open", mock_open(read_data=bundle_json)):
            with patch("signer.backends.sigstore.Path"):
                backend = SigstoreBackend()
                sig = backend.sign(b"artifact", sample_identity)

        # Should still create signature
        assert sig.format == "cosign"
        assert sig.data == b"sig_data"
        assert "certificate" not in sig.metadata
        assert "rekor_index" not in sig.metadata


# Import subprocess for the test that uses CalledProcessError
import subprocess
