"""Shared pytest fixtures for all tests."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock

import jwt
import pytest


@pytest.fixture
def sample_artifact(tmp_path):
    """Create a temporary test artifact file."""
    artifact = tmp_path / "test-artifact.txt"
    artifact.write_text("Test artifact content for signing\n")
    return artifact


@pytest.fixture
def sample_binary_artifact(tmp_path):
    """Create a temporary binary test artifact."""
    artifact = tmp_path / "test-artifact.bin"
    artifact.write_bytes(b"\x00\x01\x02\x03\x04\x05")
    return artifact


@pytest.fixture
def empty_artifact(tmp_path):
    """Create an empty test artifact."""
    artifact = tmp_path / "empty-artifact.txt"
    artifact.write_text("")
    return artifact


@pytest.fixture
def mock_oidc_token():
    """Generate a mock GitHub Actions OIDC JWT token."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=1)

    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "sub": "repo:owner/repo:ref:refs/heads/main",
        "aud": "sigstore",
        "exp": int(exp.timestamp()),
        "iat": int(now.timestamp()),
        "repository": "owner/repo",
        "repository_owner": "owner",
        "repository_id": "123456",
        "workflow": ".github/workflows/sign.yml",
        "workflow_ref": "owner/repo/.github/workflows/sign.yml@refs/heads/main",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "sha": "abc123def456789",
        "run_id": "987654321",
        "run_number": "42",
        "run_attempt": "1",
        "job_workflow_ref": "owner/repo/.github/workflows/sign.yml@refs/heads/main",
        "actor": "bot-user",
        "actor_id": "789012",
    }

    # Create a JWT token (unsigned for testing)
    token = jwt.encode(payload, "secret", algorithm="HS256")
    return token, payload


@pytest.fixture
def mock_github_env(monkeypatch, mock_oidc_token):
    """Set up GitHub Actions environment variables."""
    token, _ = mock_oidc_token

    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token-123")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_WORKFLOW", ".github/workflows/sign.yml")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", "abc123def456789")
    monkeypatch.setenv("GITHUB_RUN_ID", "987654321")
    monkeypatch.setenv("GITHUB_ACTOR", "bot-user")

    return token


@pytest.fixture
def mock_requests_get(mocker, mock_oidc_token):
    """Mock requests.get for OIDC token acquisition."""
    token, _ = mock_oidc_token

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"value": token}
    mock_response.raise_for_status = Mock()

    return mocker.patch("requests.get", return_value=mock_response)


@pytest.fixture
def mock_gpg():
    """Mock gnupg.GPG instance."""
    mock = MagicMock()

    # Mock key generation
    mock_key_data = Mock()
    mock_key_data.fingerprint = "ABCD1234EFGH5678"
    mock.gen_key.return_value = mock_key_data

    # Mock signing
    mock_sign_result = Mock()
    mock_sign_result.data = b"mock signature data"
    mock_sign_result.status = "signature created"
    mock.sign.return_value = mock_sign_result

    # Mock verification
    mock_verify_result = Mock()
    mock_verify_result.valid = True
    mock_verify_result.status = "signature valid"
    mock.verify_data.return_value = mock_verify_result

    # Mock key export
    mock.export_keys.return_value = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmock public key\n-----END PGP PUBLIC KEY BLOCK-----\n"

    return mock


@pytest.fixture
def sample_gpg_signature():
    """Sample GPG detached signature (ASCII armored)."""
    return """-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEEtest+fingerprint+hereAAKCRBtest123
signature data goes here in base64 format
more signature data
-----END PGP SIGNATURE-----
"""


@pytest.fixture
def sample_gpg_pubkey():
    """Sample GPG public key (ASCII armored)."""
    return """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGTest1234EABC123456789/public+key+data+here
more public key data
-----END PGP PUBLIC KEY BLOCK-----
"""


@pytest.fixture
def mock_cosign_sign(mocker, tmp_path):
    """Mock subprocess.run for cosign sign-blob command."""
    bundle_data = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {
                        "rawBytes": "base64_encoded_cert_data_here"
                    }
                ]
            },
            "tlogEntries": [
                {
                    "logIndex": 123456789,
                    "logId": {
                        "keyId": "rekor_key_id"
                    },
                    "kindVersion": {
                        "kind": "hashedrekord",
                        "version": "0.0.1"
                    },
                    "integratedTime": 1234567890,
                    "inclusionPromise": {
                        "signedEntryTimestamp": "base64_timestamp"
                    }
                }
            ]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": "base64_digest"
            },
            "signature": "base64_signature_data"
        }
    }

    bundle_file = tmp_path / "test.bundle"
    bundle_file.write_text(json.dumps(bundle_data, indent=2))

    def mock_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", [])
        result = Mock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        # If this is a sign-blob command, create the bundle file
        if "sign-blob" in cmd:
            if "--bundle" in cmd:
                bundle_idx = cmd.index("--bundle") + 1
                output_path = cmd[bundle_idx]
                Path(output_path).write_text(json.dumps(bundle_data, indent=2))

        return result

    return mocker.patch("subprocess.run", side_effect=mock_run)


@pytest.fixture
def mock_cosign_verify(mocker):
    """Mock subprocess.run for cosign verify-blob command."""
    def mock_run(*args, **kwargs):
        result = Mock()
        result.returncode = 0
        result.stdout = "Verified OK\n"
        result.stderr = ""
        return result

    return mocker.patch("subprocess.run", side_effect=mock_run)


@pytest.fixture
def sample_cosign_bundle():
    """Sample Cosign bundle JSON."""
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {
                        "rawBytes": "base64_encoded_certificate_data"
                    }
                ]
            },
            "tlogEntries": [
                {
                    "logIndex": 123456789,
                    "logId": {
                        "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
                    },
                    "kindVersion": {
                        "kind": "hashedrekord",
                        "version": "0.0.1"
                    },
                    "integratedTime": 1234567890,
                    "inclusionPromise": {
                        "signedEntryTimestamp": "base64_timestamp_sig"
                    },
                    "inclusionProof": {
                        "logIndex": 123456789,
                        "rootHash": "base64_root_hash",
                        "treeSize": 987654321,
                        "hashes": ["hash1", "hash2"]
                    }
                }
            ]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": "base64_artifact_digest"
            },
            "signature": "base64_signature_bytes"
        }
    }


@pytest.fixture
def sample_ceremony_log(sample_artifact, mock_oidc_token):
    """Sample ceremony log dictionary."""
    _, payload = mock_oidc_token

    return {
        "version": "1.0",
        "timestamp": "2025-11-13T00:00:00Z",
        "artifact": {
            "path": str(sample_artifact),
            "size": 35,
            "hashes": {
                "sha256": "abc123",
                "sha512": "def456"
            }
        },
        "identity": {
            "type": "oidc",
            "subject": payload["sub"],
            "issuer": payload["iss"],
            "claims": payload
        },
        "signatures": [
            {
                "backend": "gpg-keyless",
                "format": "gpg",
                "files": {
                    "signature": "test-artifact.txt.sig",
                    "public_key": "test-artifact.txt.pub"
                },
                "metadata": {
                    "key_algorithm": "ed25519",
                    "created_at": "2025-11-13T00:00:00Z"
                },
                "verification_command": "gpg --verify test-artifact.txt.sig test-artifact.txt"
            }
        ]
    }


@pytest.fixture
def fixtures_dir():
    """Return the fixtures directory path."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_environment(monkeypatch):
    """Reset environment variables before each test."""
    # Store original env vars
    original_env = dict(os.environ)

    yield

    # Restore original env vars after test
    os.environ.clear()
    os.environ.update(original_env)
