"""Unit tests for ceremony.py module."""

import json
import os
import hashlib
import stat
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from freezegun import freeze_time

from signer.ceremony import CeremonyLog
from signer.identity import OIDCIdentity, StaticKeyIdentity
from signer.backends.base import Signature


class TestCeremonyLog:
    """Tests for CeremonyLog class."""

    @pytest.fixture
    def sample_identity(self, mock_oidc_token):
        """Create a sample OIDC identity."""
        token, payload = mock_oidc_token
        return OIDCIdentity(
            token=token,
            issuer=payload["iss"],
            subject=payload["sub"],
            claims=payload,
        )

    @pytest.fixture
    def sample_signatures(self):
        """Create sample signature objects."""
        return [
            Signature(
                format="gpg-keyless",
                data=b"gpg signature data",
                files={
                    "signature": "artifact.sig",
                    "public_key": "artifact.pub",
                },
                metadata={
                    "key_algorithm": "ed25519",
                    "verification_command": "gpg --verify artifact.sig artifact.txt",
                },
            ),
            Signature(
                format="sigstore",
                data=b"sigstore signature data",
                files={"bundle": "artifact.bundle"},
                metadata={
                    "rekor_log_index": 123456,
                    "verification_command": "cosign verify-blob --bundle artifact.bundle artifact.txt",
                },
            ),
        ]

    @freeze_time("2025-11-13 12:00:00")
    def test_init_default_workflow_run(
        self, sample_artifact, sample_identity, sample_signatures, monkeypatch
    ):
        """Test initialization with default workflow_run from environment."""
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
        monkeypatch.setenv("GITHUB_RUN_ID", "123456789")

        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        assert log.artifact_path == str(sample_artifact)
        assert log.identity == sample_identity
        assert log.signatures == sample_signatures
        assert (
            log.workflow_run == "https://github.com/owner/repo/actions/runs/123456789"
        )
        assert log.timestamp == datetime(2025, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

    def test_init_custom_workflow_run(
        self, sample_artifact, sample_identity, sample_signatures
    ):
        """Test initialization with custom workflow_run."""
        custom_url = "https://custom.com/workflow/run/999"

        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
            workflow_run=custom_url,
        )

        assert log.workflow_run == custom_url

    def test_init_empty_environment(
        self, sample_artifact, sample_identity, sample_signatures, monkeypatch
    ):
        """Test initialization when GitHub environment variables are missing."""
        monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.delenv("GITHUB_RUN_ID", raising=False)

        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        # Should construct with empty strings
        assert log.workflow_run == "//actions/runs/"

    def test_compute_artifact_hashes(self, sample_artifact, sample_identity):
        """Test hash computation for artifact."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        hashes = log._compute_artifact_hashes()

        # Compute expected hashes
        with open(sample_artifact, "rb") as f:
            data = f.read()

        expected_sha256 = hashlib.sha256(data).hexdigest()
        expected_sha512 = hashlib.sha512(data).hexdigest()

        assert hashes["sha256"] == expected_sha256
        assert hashes["sha512"] == expected_sha512
        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha512"]) == 128

    def test_compute_artifact_hashes_binary(
        self, sample_binary_artifact, sample_identity
    ):
        """Test hash computation for binary artifact."""
        log = CeremonyLog(
            artifact_path=str(sample_binary_artifact),
            identity=sample_identity,
            signatures=[],
        )

        hashes = log._compute_artifact_hashes()

        with open(sample_binary_artifact, "rb") as f:
            data = f.read()

        assert hashes["sha256"] == hashlib.sha256(data).hexdigest()
        assert hashes["sha512"] == hashlib.sha512(data).hexdigest()

    def test_compute_artifact_hashes_empty(self, empty_artifact, sample_identity):
        """Test hash computation for empty artifact."""
        log = CeremonyLog(
            artifact_path=str(empty_artifact),
            identity=sample_identity,
            signatures=[],
        )

        hashes = log._compute_artifact_hashes()

        # Hash of empty string
        assert hashes["sha256"] == hashlib.sha256(b"").hexdigest()
        assert hashes["sha512"] == hashlib.sha512(b"").hexdigest()

    def test_get_artifact_size(self, sample_artifact, sample_identity):
        """Test artifact size retrieval."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        size = log._get_artifact_size()

        expected_size = Path(sample_artifact).stat().st_size
        assert size == expected_size
        assert size > 0

    def test_get_artifact_size_empty(self, empty_artifact, sample_identity):
        """Test size of empty artifact."""
        log = CeremonyLog(
            artifact_path=str(empty_artifact),
            identity=sample_identity,
            signatures=[],
        )

        size = log._get_artifact_size()
        assert size == 0

    @freeze_time("2025-11-13 15:30:45")
    def test_to_dict_structure(
        self, sample_artifact, sample_identity, sample_signatures
    ):
        """Test to_dict() returns correct structure."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
            workflow_run="https://github.com/owner/repo/actions/runs/123",
        )

        result = log.to_dict()

        # Verify top-level structure
        assert result["ceremony_version"] == "1.0"
        assert result["ceremony_type"] == "artifact_signing"
        assert result["timestamp"] == "2025-11-13T15:30:45+00:00"
        assert result["workflow_run"] == "https://github.com/owner/repo/actions/runs/123"

        # Verify identity section
        assert "identity" in result
        assert result["identity"]["type"] == "oidc"

        # Verify artifact section
        assert "artifact" in result
        assert result["artifact"]["path"] == str(sample_artifact)
        assert "sha256" in result["artifact"]
        assert "sha512" in result["artifact"]
        assert "size" in result["artifact"]

        # Verify signatures section
        assert "signatures" in result
        assert len(result["signatures"]) == 2

    def test_to_dict_signature_details(
        self, sample_artifact, sample_identity, sample_signatures
    ):
        """Test to_dict() includes signature details."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        result = log.to_dict()

        # Check first signature (GPG)
        gpg_sig = result["signatures"][0]
        assert gpg_sig["backend"] == "gpg-keyless"
        assert gpg_sig["format"] == "gpg-keyless"
        assert gpg_sig["files"]["signature"] == "artifact.sig"
        assert gpg_sig["files"]["public_key"] == "artifact.pub"
        assert gpg_sig["key_algorithm"] == "ed25519"
        assert "gpg --verify" in gpg_sig["verification_command"]

        # Check second signature (Sigstore)
        sigstore_sig = result["signatures"][1]
        assert sigstore_sig["backend"] == "sigstore"
        assert sigstore_sig["format"] == "sigstore"
        assert sigstore_sig["files"]["bundle"] == "artifact.bundle"
        assert sigstore_sig["rekor_log_index"] == 123456
        assert "cosign verify-blob" in sigstore_sig["verification_command"]

    def test_to_dict_no_signatures(self, sample_artifact, sample_identity):
        """Test to_dict() with no signatures."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        result = log.to_dict()

        assert result["signatures"] == []
        assert "artifact" in result
        assert "identity" in result

    def test_to_json_formatting(self, sample_artifact, sample_identity):
        """Test to_json() produces valid JSON."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        json_str = log.to_json()

        # Verify valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)
        assert parsed["ceremony_version"] == "1.0"

    def test_to_json_custom_indent(self, sample_artifact, sample_identity):
        """Test to_json() with custom indentation."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        json_str = log.to_json(indent=4)

        # Should contain indentation
        assert "    " in json_str
        parsed = json.loads(json_str)
        assert parsed["ceremony_version"] == "1.0"

    def test_save_default_path(self, sample_artifact, sample_identity, tmp_path):
        """Test save() with default output path."""
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test content")

        log = CeremonyLog(
            artifact_path=str(artifact),
            identity=sample_identity,
            signatures=[],
        )

        output_path = log.save()

        expected_path = f"{artifact}.ceremony.json"
        assert output_path == expected_path
        assert Path(output_path).exists()

        # Verify content
        with open(output_path, "r") as f:
            content = json.load(f)
        assert content["ceremony_version"] == "1.0"

    def test_save_custom_path(self, sample_artifact, sample_identity, tmp_path):
        """Test save() with custom output path."""
        custom_path = tmp_path / "custom_ceremony.json"

        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        output_path = log.save(output_path=str(custom_path))

        assert output_path == str(custom_path)
        assert custom_path.exists()

        with open(custom_path, "r") as f:
            content = json.load(f)
        assert content["ceremony_version"] == "1.0"

    def test_generate_verification_script_default_path(
        self, sample_artifact, sample_identity, sample_signatures, tmp_path
    ):
        """Test generate_verification_script() with default path."""
        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test content")

        log = CeremonyLog(
            artifact_path=str(artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        script_path = log.generate_verification_script()

        expected_path = f"{artifact}.verify.sh"
        assert script_path == expected_path
        assert Path(script_path).exists()

    def test_generate_verification_script_content(
        self, sample_artifact, sample_identity, sample_signatures
    ):
        """Test verification script contains correct content."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        script_path = log.generate_verification_script()

        with open(script_path, "r") as f:
            content = f.read()

        # Check script structure
        assert content.startswith("#!/bin/bash")
        assert "set -euo pipefail" in content
        assert f'ARTIFACT="{Path(sample_artifact).name}"' in content

        # Check signature verifications
        assert "Checking gpg-keyless signature" in content
        assert "gpg --verify artifact.sig artifact.txt" in content
        assert "Checking sigstore signature" in content
        assert "cosign verify-blob --bundle artifact.bundle artifact.txt" in content

        # Check result messages
        assert "All signatures verified successfully" in content
        assert "One or more signatures failed" in content

    def test_generate_verification_script_executable(
        self, sample_artifact, sample_identity, sample_signatures
    ):
        """Test verification script has executable permissions."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        script_path = log.generate_verification_script()

        # Check file permissions
        file_stat = os.stat(script_path)
        assert file_stat.st_mode & stat.S_IXUSR  # Owner can execute
        assert file_stat.st_mode & stat.S_IRUSR  # Owner can read

    def test_generate_verification_script_custom_path(
        self, sample_artifact, sample_identity, sample_signatures, tmp_path
    ):
        """Test generate_verification_script() with custom path."""
        custom_path = tmp_path / "custom_verify.sh"

        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=sample_signatures,
        )

        script_path = log.generate_verification_script(output_path=str(custom_path))

        assert script_path == str(custom_path)
        assert custom_path.exists()

    def test_generate_verification_script_no_signatures(
        self, sample_artifact, sample_identity
    ):
        """Test verification script with no signatures."""
        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=sample_identity,
            signatures=[],
        )

        script_path = log.generate_verification_script()

        with open(script_path, "r") as f:
            content = f.read()

        # Should still have basic structure
        assert "#!/bin/bash" in content
        assert "set -euo pipefail" in content
        # But no signature checks
        assert "Checking" not in content or "signature" not in content.lower()

    def test_static_key_identity(self, sample_artifact, sample_signatures):
        """Test CeremonyLog with StaticKeyIdentity."""
        identity = StaticKeyIdentity(key_id="GPG_KEY_123", key_type="gpg")

        log = CeremonyLog(
            artifact_path=str(sample_artifact),
            identity=identity,
            signatures=sample_signatures,
        )

        result = log.to_dict()

        assert result["identity"]["type"] == "static_key"
        assert result["identity"]["key_id"] == "GPG_KEY_123"
        assert result["identity"]["key_type"] == "gpg"
