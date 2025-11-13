"""Unit tests for orchestrator.py module."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open

from signer.orchestrator import SigningOrchestrator
from signer.backends.base import SigningBackend, Signature
from signer.identity import OIDCIdentity
from signer.ceremony import CeremonyLog


class MockBackend(SigningBackend):
    """Mock backend for testing."""

    def __init__(self, format_name="mock", should_fail=False):
        super().__init__()
        self.format_name = format_name
        self.should_fail = should_fail

    def sign(self, artifact: bytes, identity) -> Signature:
        if self.should_fail:
            raise RuntimeError(f"{self.format_name} signing failed")

        return Signature(
            format=self.format_name,
            data=b"signature data",
            metadata={"verification_command": f"verify_{self.format_name} artifact.txt"},
            files={"signature": f"/tmp/{self.format_name}.sig"},
        )

    def verify(self, artifact: bytes, signature: Signature) -> bool:
        return not self.should_fail

    def supports_keyless(self) -> bool:
        return True

    def get_format(self) -> str:
        return self.format_name


class TestSigningOrchestrator:
    """Tests for SigningOrchestrator class."""

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

    def test_init(self):
        """Test orchestrator initialization."""
        backend1 = MockBackend("gpg")
        backend2 = MockBackend("cosign")

        orchestrator = SigningOrchestrator([backend1, backend2])

        assert len(orchestrator.backends) == 2
        assert orchestrator.backends[0] == backend1
        assert orchestrator.backends[1] == backend2

    def test_init_empty_backends(self):
        """Test orchestrator with no backends."""
        orchestrator = SigningOrchestrator([])

        assert orchestrator.backends == []

    def test_save_signature_files(self, tmp_path):
        """Test saving signature files to permanent locations."""
        # Create artifact
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test")

        # Create temporary signature file
        temp_sig = tmp_path / "temp_sig.asc"
        temp_sig.write_bytes(b"signature data")

        signature = Signature(
            format="gpg",
            data=b"sig",
            metadata={"verification_command": f"gpg --verify {temp_sig.name} artifact.txt"},
            files={"signature": str(temp_sig)},
        )

        orchestrator = SigningOrchestrator([])
        orchestrator._save_signature_files(str(artifact), [signature])

        # Check that file was copied
        permanent_path = tmp_path / "artifact.txt.gpg.asc"
        assert permanent_path.exists()
        assert permanent_path.read_bytes() == b"signature data"

        # Check that signature object was updated
        assert signature.files["signature"] == "artifact.txt.gpg.asc"

        # Check that verification command was updated
        assert "artifact.txt.gpg.asc" in signature.metadata["verification_command"]
        assert temp_sig.name not in signature.metadata["verification_command"]

    def test_save_signature_files_multiple_files(self, tmp_path):
        """Test saving multiple signature files."""
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test")

        # Create temporary files
        temp_sig = tmp_path / "temp.sig"
        temp_sig.write_bytes(b"sig")

        temp_pub = tmp_path / "temp.pub"
        temp_pub.write_text("public key")

        signature = Signature(
            format="gpg",
            data=b"sig",
            metadata={"verification_command": f"gpg --import {temp_pub.name} && gpg --verify {temp_sig.name} artifact.txt"},
            files={
                "signature": str(temp_sig),
                "public_key": str(temp_pub),
            },
        )

        orchestrator = SigningOrchestrator([])
        orchestrator._save_signature_files(str(artifact), [signature])

        # Check both files were copied
        assert (tmp_path / "artifact.txt.gpg.sig").exists()
        assert (tmp_path / "artifact.txt.gpg.pub").exists()

        # Check verification command was updated
        cmd = signature.metadata["verification_command"]
        assert "artifact.txt.gpg.pub" in cmd
        assert "artifact.txt.gpg.sig" in cmd

    @patch("builtins.open", new_callable=mock_open, read_data=b"test artifact")
    @patch("signer.orchestrator.CeremonyLog")
    def test_sign_artifact_sequential(
        self, mock_ceremony_class, mock_file, sample_identity, tmp_path
    ):
        """Test signing artifact sequentially."""
        backend1 = MockBackend("gpg")
        backend2 = MockBackend("cosign")

        orchestrator = SigningOrchestrator([backend1, backend2])

        artifact_path = tmp_path / "artifact.txt"
        artifact_path.write_text("test")

        # Mock ceremony log
        mock_ceremony = Mock()
        mock_ceremony.save.return_value = str(tmp_path / "ceremony.json")
        mock_ceremony.generate_verification_script.return_value = str(tmp_path / "verify.sh")
        mock_ceremony_class.return_value = mock_ceremony

        with patch.object(orchestrator, "_save_signature_files"):
            ceremony = orchestrator.sign_artifact(
                str(artifact_path),
                sample_identity,
                parallel=False,
            )

        assert ceremony == mock_ceremony
        mock_ceremony.save.assert_called_once()
        mock_ceremony.generate_verification_script.assert_called_once()

    @patch("builtins.open", new_callable=mock_open, read_data=b"test artifact")
    @patch("signer.orchestrator.CeremonyLog")
    def test_sign_artifact_parallel(
        self, mock_ceremony_class, mock_file, sample_identity, tmp_path
    ):
        """Test signing artifact in parallel."""
        backend1 = MockBackend("gpg")
        backend2 = MockBackend("cosign")

        orchestrator = SigningOrchestrator([backend1, backend2])

        artifact_path = tmp_path / "artifact.txt"
        artifact_path.write_text("test")

        # Mock ceremony log
        mock_ceremony = Mock()
        mock_ceremony.save.return_value = str(tmp_path / "ceremony.json")
        mock_ceremony.generate_verification_script.return_value = str(tmp_path / "verify.sh")
        mock_ceremony_class.return_value = mock_ceremony

        with patch.object(orchestrator, "_save_signature_files"):
            ceremony = orchestrator.sign_artifact(
                str(artifact_path),
                sample_identity,
                parallel=True,
            )

        assert ceremony == mock_ceremony

    @patch("builtins.open", new_callable=mock_open, read_data=b"test artifact")
    def test_sign_artifact_backend_failure_sequential(
        self, mock_file, sample_identity, tmp_path
    ):
        """Test signing failure in sequential mode."""
        backend1 = MockBackend("gpg")
        backend2 = MockBackend("cosign", should_fail=True)

        orchestrator = SigningOrchestrator([backend1, backend2])

        artifact_path = tmp_path / "artifact.txt"
        artifact_path.write_text("test")

        with pytest.raises(RuntimeError, match="cosign signing failed"):
            orchestrator.sign_artifact(str(artifact_path), sample_identity, parallel=False)

    @patch("builtins.open", new_callable=mock_open, read_data=b"test artifact")
    def test_sign_artifact_backend_failure_parallel(
        self, mock_file, sample_identity, tmp_path
    ):
        """Test signing failure in parallel mode."""
        backend1 = MockBackend("gpg")
        backend2 = MockBackend("cosign", should_fail=True)

        orchestrator = SigningOrchestrator([backend1, backend2])

        artifact_path = tmp_path / "artifact.txt"
        artifact_path.write_text("test")

        with pytest.raises(RuntimeError, match="cosign signing failed"):
            orchestrator.sign_artifact(str(artifact_path), sample_identity, parallel=True)

    @patch("builtins.open", new_callable=mock_open, read_data=b"test artifact")
    @patch("signer.orchestrator.CeremonyLog")
    def test_sign_artifact_skip_ceremony_log(
        self, mock_ceremony_class, mock_file, sample_identity, tmp_path
    ):
        """Test signing without generating ceremony log."""
        backend = MockBackend("gpg")
        orchestrator = SigningOrchestrator([backend])

        artifact_path = tmp_path / "artifact.txt"
        artifact_path.write_text("test")

        mock_ceremony = Mock()
        mock_ceremony_class.return_value = mock_ceremony

        with patch.object(orchestrator, "_save_signature_files"):
            orchestrator.sign_artifact(
                str(artifact_path),
                sample_identity,
                generate_ceremony_log=False,
                generate_verification_script=False,
            )

        mock_ceremony.save.assert_not_called()
        mock_ceremony.generate_verification_script.assert_not_called()

    def test_verify_artifact_success(self, tmp_path):
        """Test successful artifact verification."""
        # Create artifact and signature files
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test content")

        sig_file = tmp_path / "artifact.txt.gpg.sig"
        sig_file.write_bytes(b"signature")

        # Create ceremony log
        ceremony_log = {
            "signatures": [
                {
                    "format": "gpg",
                    "files": {"signature": "artifact.txt.gpg.sig"},
                }
            ]
        }

        ceremony_path = tmp_path / "ceremony.json"
        ceremony_path.write_text(json.dumps(ceremony_log))

        backend = MockBackend("gpg")
        orchestrator = SigningOrchestrator([backend])

        result = orchestrator.verify_artifact(str(artifact), str(ceremony_path))

        assert result is True

    def test_verify_artifact_failure(self, tmp_path):
        """Test artifact verification failure."""
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test")

        sig_file = tmp_path / "artifact.txt.gpg.sig"
        sig_file.write_bytes(b"bad signature")

        ceremony_log = {
            "signatures": [
                {
                    "format": "gpg",
                    "files": {"signature": "artifact.txt.gpg.sig"},
                }
            ]
        }

        ceremony_path = tmp_path / "ceremony.json"
        ceremony_path.write_text(json.dumps(ceremony_log))

        backend = MockBackend("gpg", should_fail=True)
        orchestrator = SigningOrchestrator([backend])

        result = orchestrator.verify_artifact(str(artifact), str(ceremony_path))

        assert result is False

    def test_verify_artifact_missing_backend(self, tmp_path):
        """Test verification when backend is not available."""
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test")

        ceremony_log = {
            "signatures": [
                {
                    "format": "unknown-format",
                    "files": {},
                }
            ]
        }

        ceremony_path = tmp_path / "ceremony.json"
        ceremony_path.write_text(json.dumps(ceremony_log))

        backend = MockBackend("gpg")
        orchestrator = SigningOrchestrator([backend])

        result = orchestrator.verify_artifact(str(artifact), str(ceremony_path))

        # Should continue but return True since no signatures were checked
        assert result is True

    def test_from_config_gpg_enabled(self):
        """Test creating orchestrator from config with GPG enabled."""
        config = {
            "backends": {
                "gpg": {"enabled": True, "key_type": "Ed25519"},
                "cosign": {"enabled": False},
            }
        }

        orchestrator = SigningOrchestrator.from_config(config)

        assert len(orchestrator.backends) == 1
        assert orchestrator.backends[0].get_format() == "gpg"

    def test_from_config_cosign_enabled(self):
        """Test creating orchestrator from config with Cosign enabled."""
        config = {
            "backends": {
                "gpg": {"enabled": False},
                "cosign": {"enabled": True},
            }
        }

        orchestrator = SigningOrchestrator.from_config(config)

        assert len(orchestrator.backends) == 1
        assert orchestrator.backends[0].get_format() == "cosign"

    def test_from_config_both_enabled(self):
        """Test creating orchestrator with both backends enabled."""
        config = {
            "backends": {
                "gpg": {"enabled": True},
                "cosign": {"enabled": True},
            }
        }

        orchestrator = SigningOrchestrator.from_config(config)

        assert len(orchestrator.backends) == 2
        formats = [b.get_format() for b in orchestrator.backends]
        assert "gpg" in formats
        assert "cosign" in formats

    def test_from_config_none_enabled(self):
        """Test creating orchestrator with no backends enabled."""
        config = {
            "backends": {
                "gpg": {"enabled": False},
                "cosign": {"enabled": False},
            }
        }

        orchestrator = SigningOrchestrator.from_config(config)

        assert len(orchestrator.backends) == 0
