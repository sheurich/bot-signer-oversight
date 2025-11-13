"""Unit tests for backends/intoto.py module."""

import json
import pytest
import base64
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from signer.backends.intoto import IntotoBackend
from signer.backends.base import Signature
from signer.identity import OIDCIdentity, StaticKeyIdentity


class TestIntotoBackend:
    """Tests for IntotoBackend class."""

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
    def mock_github_env_full(self, monkeypatch):
        """Set up full GitHub Actions environment."""
        monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
        monkeypatch.setenv("GITHUB_WORKFLOW", ".github/workflows/sign.yml")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
        monkeypatch.setenv("GITHUB_SHA", "abc123def456")
        monkeypatch.setenv("GITHUB_RUN_ID", "123456")
        monkeypatch.setenv("GITHUB_RUN_NUMBER", "42")
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
        monkeypatch.setenv("GITHUB_ACTOR", "test-user")
        monkeypatch.setenv("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/sign.yml@refs/heads/main")
        monkeypatch.setenv("GITHUB_REPOSITORY_OWNER", "owner")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")

    def test_init_default_config(self):
        """Test initialization with default configuration."""
        backend = IntotoBackend()

        assert backend.key_type == "ed25519"
        assert backend.keyless_mode is True
        assert backend.predicate_type == "https://slsa.dev/provenance/v1.0"

    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            "key_type": "rsa",
            "keyless_mode": False,
            "predicate_type": "https://example.com/predicate/v1",
        }

        backend = IntotoBackend(config=config)

        assert backend.key_type == "rsa"
        assert backend.keyless_mode is False
        assert backend.predicate_type == "https://example.com/predicate/v1"

    def test_supports_keyless(self):
        """Test supports_keyless returns True."""
        backend = IntotoBackend()
        assert backend.supports_keyless() is True

    def test_get_format(self):
        """Test get_format returns 'intoto'."""
        backend = IntotoBackend()
        assert backend.get_format() == "intoto"

    def test_extract_github_context(self, mock_github_env_full):
        """Test GitHub context extraction from environment."""
        backend = IntotoBackend()
        ctx = backend._extract_github_context()

        assert ctx["repository"] == "owner/repo"
        assert ctx["workflow"] == ".github/workflows/sign.yml"
        assert ctx["ref"] == "refs/heads/main"
        assert ctx["sha"] == "abc123def456"
        assert ctx["run_id"] == "123456"
        assert ctx["run_number"] == "42"
        assert ctx["run_attempt"] == "1"
        assert ctx["actor"] == "test-user"
        assert ctx["server_url"] == "https://github.com"

    def test_extract_github_context_defaults(self):
        """Test GitHub context extraction with missing env vars."""
        backend = IntotoBackend()
        ctx = backend._extract_github_context()

        assert ctx["repository"] == "unknown/unknown"
        assert ctx["workflow"] == "unknown"
        assert ctx["ref"] == "refs/heads/main"
        assert ctx["sha"] == "0" * 40
        assert ctx["run_id"] == "0"
        assert ctx["actor"] == "unknown"

    def test_compute_artifact_digest(self):
        """Test artifact digest computation."""
        backend = IntotoBackend()
        artifact = b"test artifact content"

        digests = backend._compute_artifact_digest(artifact)

        assert "sha256" in digests
        assert "sha512" in digests
        assert len(digests["sha256"]) == 64  # SHA256 hex length
        assert len(digests["sha512"]) == 128  # SHA512 hex length

    def test_build_slsa_provenance_with_oidc(self, sample_identity, mock_github_env_full):
        """Test SLSA provenance building with OIDC identity."""
        backend = IntotoBackend()
        artifact = b"test artifact"
        github_ctx = backend._extract_github_context()

        provenance = backend._build_slsa_provenance(artifact, sample_identity, github_ctx)

        assert "buildDefinition" in provenance
        assert "runDetails" in provenance

        # Check buildDefinition
        build_def = provenance["buildDefinition"]
        assert build_def["buildType"] == "https://slsa.dev/github-actions-workflow/v1"
        assert "externalParameters" in build_def
        assert build_def["externalParameters"]["workflow"]["repository"] == "owner/repo"

        # Check runDetails
        run_details = provenance["runDetails"]
        assert "builder" in run_details
        assert "metadata" in run_details
        assert "identity" in run_details["metadata"]
        assert run_details["metadata"]["identity"]["issuer"] == sample_identity.issuer
        assert run_details["metadata"]["identity"]["subject"] == sample_identity.subject

    def test_build_slsa_provenance_without_oidc(self, mock_github_env_full):
        """Test SLSA provenance building without OIDC identity."""
        backend = IntotoBackend()
        artifact = b"test artifact"
        static_identity = StaticKeyIdentity(key_id="KEY123", key_type="ed25519")
        github_ctx = backend._extract_github_context()

        provenance = backend._build_slsa_provenance(artifact, static_identity, github_ctx)

        assert "buildDefinition" in provenance
        assert "runDetails" in provenance
        assert "identity" not in provenance["runDetails"]["metadata"]

    def test_build_intoto_statement(self, sample_identity, mock_github_env_full):
        """Test in-toto statement building."""
        backend = IntotoBackend()
        artifact = b"test artifact"
        github_ctx = backend._extract_github_context()

        statement = backend._build_intoto_statement(artifact, sample_identity, github_ctx)

        assert statement["_type"] == "https://in-toto.io/Statement/v1"
        assert "subject" in statement
        assert len(statement["subject"]) == 1
        assert "digest" in statement["subject"][0]
        assert "sha256" in statement["subject"][0]["digest"]
        assert statement["predicateType"] == "https://slsa.dev/provenance/v1.0"
        assert "predicate" in statement

    def test_compute_pae(self):
        """Test PAE (Pre-Authentication Encoding) computation."""
        backend = IntotoBackend()
        payload_type = "application/vnd.in-toto+json"
        payload = b'{"test": "payload"}'

        pae = backend._compute_pae(payload_type, payload)

        # PAE format: "DSSEv1" + SP + LEN(payloadType) + SP + payloadType + SP + LEN(payload) + SP + payload
        # "application/vnd.in-toto+json" is 28 bytes, '{"test": "payload"}' is 19 bytes
        expected_pae = (
            b"DSSEv1 28 application/vnd.in-toto+json 19 {\"test\": \"payload\"}"
        )
        assert pae == expected_pae

    def test_compute_key_id(self):
        """Test key ID computation from public key."""
        backend = IntotoBackend()

        # Generate a test key
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        key_id = backend._compute_key_id(public_key)

        # Should be first 16 chars of SHA256 hash of public key bytes
        assert len(key_id) == 16
        assert all(c in "0123456789abcdef" for c in key_id)

    def test_export_public_key_pem(self):
        """Test public key export in PEM format."""
        backend = IntotoBackend()

        # Generate a test key
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        pem_str = backend._export_public_key_pem(public_key)

        # Check PEM format
        assert pem_str.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem_str.strip().endswith("-----END PUBLIC KEY-----")
        assert "PUBLIC KEY" in pem_str

    def test_create_dsse_envelope(self):
        """Test DSSE envelope creation with real Ed25519 signing."""
        backend = IntotoBackend()
        payload = b'{"test": "payload"}'

        # Generate real key
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_id = "test-key-id"

        envelope = backend._create_dsse_envelope(payload, private_key, key_id)

        # Verify envelope structure
        assert "payload" in envelope
        assert "payloadType" in envelope
        assert envelope["payloadType"] == "application/vnd.in-toto+json"
        assert "signatures" in envelope
        assert len(envelope["signatures"]) == 1
        assert envelope["signatures"][0]["keyid"] == key_id

        # Verify payload is base64 encoded
        decoded_payload = base64.b64decode(envelope["payload"])
        assert decoded_payload == payload

        # Verify signature is base64 encoded
        sig_b64 = envelope["signatures"][0]["sig"]
        signature_bytes = base64.b64decode(sig_b64)
        assert len(signature_bytes) == 64  # Ed25519 signature length

    def test_sign_with_oidc_identity(self, sample_identity, mock_github_env_full):
        """Test signing with OIDC identity using real cryptography."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        signature = backend.sign(artifact, sample_identity)

        # Verify signature structure
        assert signature.format == "intoto"
        assert signature.metadata["keyless"] is True
        assert signature.metadata["algorithm"] == "Ed25519"
        assert signature.metadata["predicate_type"] == "https://slsa.dev/provenance/v1.0"
        assert signature.metadata["subject"] == sample_identity.subject
        assert signature.metadata["issuer"] == sample_identity.issuer
        assert "attestation" in signature.files
        assert "public_key" in signature.files
        assert "statement" in signature.metadata
        assert "github_context" in signature.metadata

        # Verify attestation file exists and contains valid DSSE envelope
        attestation_path = signature.files["attestation"]
        assert Path(attestation_path).exists()
        with open(attestation_path, "r") as f:
            envelope = json.load(f)
        assert "payload" in envelope
        assert "payloadType" in envelope
        assert "signatures" in envelope

        # Verify public key file exists and is valid PEM
        pubkey_path = signature.files["public_key"]
        assert Path(pubkey_path).exists()
        assert pubkey_path.endswith(".pub.pem")
        with open(pubkey_path, "r") as f:
            pem_content = f.read()
        assert "-----BEGIN PUBLIC KEY-----" in pem_content
        assert "-----END PUBLIC KEY-----" in pem_content

    def test_sign_with_static_identity(self, mock_github_env_full):
        """Test signing with static key identity."""
        static_identity = StaticKeyIdentity(key_id="KEY123", key_type="ed25519")

        backend = IntotoBackend()
        artifact = b"test artifact"

        signature = backend.sign(artifact, static_identity)

        # Verify signature structure
        assert signature.format == "intoto"
        assert signature.metadata["key_id"] == "KEY123"
        assert signature.metadata["keyless"] is False
        assert "subject" not in signature.metadata

        # Verify files exist
        assert Path(signature.files["attestation"]).exists()
        assert Path(signature.files["public_key"]).exists()

    def test_verify_success(self, tmp_path, mock_github_env_full):
        """Test successful attestation verification with real cryptography."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        # Create a real signature
        identity = StaticKeyIdentity(key_id="test-key", key_type="ed25519")
        signature = backend.sign(artifact, identity)

        # Verify it
        result = backend.verify(artifact, signature)
        assert result is True

    def test_verify_with_oidc_identity(self, sample_identity, mock_github_env_full):
        """Test verification with OIDC identity."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        # Create a real signature
        signature = backend.sign(artifact, sample_identity)

        # Verify it
        result = backend.verify(artifact, signature)
        assert result is True

    def test_verify_missing_attestation(self):
        """Test verification fails when attestation file is missing."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        signature = Signature(
            format="intoto",
            data=b"",
            metadata={},
            files={"attestation": "/nonexistent/file.jsonl"},
        )

        result = backend.verify(artifact, signature)
        assert result is False

    def test_verify_missing_public_key(self, tmp_path):
        """Test verification fails when public key is missing."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        attestation_path = tmp_path / "test.intoto.jsonl"
        attestation_path.write_text('{"payload": "test"}')

        signature = Signature(
            format="intoto",
            data=b"",
            metadata={},
            files={
                "attestation": str(attestation_path),
                "public_key": "/nonexistent/pubkey.pem",
            },
        )

        result = backend.verify(artifact, signature)
        assert result is False

    def test_verify_invalid_statement_type(self, tmp_path):
        """Test verification fails with invalid statement type."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        # Create real key for signing
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Create envelope with wrong statement type
        statement = {"_type": "https://invalid.type/v1", "subject": []}
        payload = json.dumps(statement).encode()

        # Create proper DSSE envelope
        pae = backend._compute_pae("application/vnd.in-toto+json", payload)
        signature_bytes = private_key.sign(pae)

        envelope = {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"keyid": "test", "sig": base64.b64encode(signature_bytes).decode()}],
        }

        attestation_path = tmp_path / "test.intoto.jsonl"
        attestation_path.write_text(json.dumps(envelope))

        # Export public key in PEM format
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pubkey_path = tmp_path / "test.pub.pem"
        pubkey_path.write_bytes(pem_bytes)

        signature = Signature(
            format="intoto",
            data=b"",
            metadata={},
            files={
                "attestation": str(attestation_path),
                "public_key": str(pubkey_path),
            },
        )

        result = backend.verify(artifact, signature)
        assert result is False

    def test_verify_digest_mismatch(self, tmp_path):
        """Test verification fails when artifact digest doesn't match."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        # Create real key for signing
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Create envelope with wrong digest
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact", "digest": {"sha256": "wrong-digest"}}],
        }
        payload = json.dumps(statement).encode()

        # Create proper DSSE envelope
        pae = backend._compute_pae("application/vnd.in-toto+json", payload)
        signature_bytes = private_key.sign(pae)

        envelope = {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"keyid": "test", "sig": base64.b64encode(signature_bytes).decode()}],
        }

        attestation_path = tmp_path / "test.intoto.jsonl"
        attestation_path.write_text(json.dumps(envelope))

        # Export public key in PEM format
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pubkey_path = tmp_path / "test.pub.pem"
        pubkey_path.write_bytes(pem_bytes)

        signature = Signature(
            format="intoto",
            data=b"",
            metadata={},
            files={
                "attestation": str(attestation_path),
                "public_key": str(pubkey_path),
            },
        )

        result = backend.verify(artifact, signature)
        assert result is False

    def test_verify_signature_verification_fails(self, tmp_path):
        """Test verification fails when signature is invalid."""
        backend = IntotoBackend()
        artifact = b"test artifact"

        # Compute correct digest
        digest = hashlib.sha256(artifact).hexdigest()

        # Create one key for signing
        signing_key = ed25519.Ed25519PrivateKey.generate()

        # Create different key for verification (should fail)
        verifying_key = ed25519.Ed25519PrivateKey.generate()
        public_key = verifying_key.public_key()

        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact", "digest": {"sha256": digest}}],
        }
        payload = json.dumps(statement).encode()

        # Sign with one key
        pae = backend._compute_pae("application/vnd.in-toto+json", payload)
        signature_bytes = signing_key.sign(pae)

        envelope = {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"keyid": "test", "sig": base64.b64encode(signature_bytes).decode()}],
        }

        attestation_path = tmp_path / "test.intoto.jsonl"
        attestation_path.write_text(json.dumps(envelope))

        # Export different public key (verification should fail)
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pubkey_path = tmp_path / "test.pub.pem"
        pubkey_path.write_bytes(pem_bytes)

        signature = Signature(
            format="intoto",
            data=b"",
            metadata={},
            files={
                "attestation": str(attestation_path),
                "public_key": str(pubkey_path),
            },
        )

        result = backend.verify(artifact, signature)
        assert result is False

    def test_get_verification_command(self, tmp_path):
        """Test get_verification_command generates correct command."""
        attestation_path = tmp_path / "test.intoto.jsonl"
        pubkey_path = tmp_path / "test.pub.pem"

        signature = Signature(
            format="intoto",
            data=b"",
            metadata={},
            files={
                "attestation": str(attestation_path),
                "public_key": str(pubkey_path),
            },
        )

        backend = IntotoBackend()
        cmd = backend.get_verification_command("artifact.txt", signature)

        assert "test.intoto.jsonl" in cmd
        assert "test.pub.pem" in cmd
        assert "artifact.txt" in cmd
        assert "DSSE" in cmd or "attestation" in cmd

    def test_sign_creates_valid_jsonl_structure(self, sample_identity, mock_github_env_full):
        """Test sign creates valid JSONL structure."""
        backend = IntotoBackend()
        artifact = b"test"

        signature = backend.sign(artifact, sample_identity)

        # Check that attestation file exists and is valid JSON
        attestation_path = signature.files["attestation"]
        with open(attestation_path, "r") as f:
            envelope = json.load(f)

        assert "payload" in envelope
        assert "payloadType" in envelope
        assert "signatures" in envelope

        # Verify payload can be decoded
        payload = base64.b64decode(envelope["payload"])
        statement = json.loads(payload)
        assert statement["_type"] == "https://in-toto.io/Statement/v1"

    def test_statement_contains_slsa_provenance(self, sample_identity, mock_github_env_full):
        """Test in-toto statement contains SLSA provenance."""
        backend = IntotoBackend()
        artifact = b"test"
        github_ctx = backend._extract_github_context()

        statement = backend._build_intoto_statement(artifact, sample_identity, github_ctx)

        assert "predicate" in statement
        predicate = statement["predicate"]
        assert "buildDefinition" in predicate
        assert "runDetails" in predicate
        assert predicate["buildDefinition"]["buildType"] == "https://slsa.dev/github-actions-workflow/v1"

    def test_verify_round_trip(self, sample_identity, mock_github_env_full):
        """Test sign and verify round trip with real cryptography."""
        backend = IntotoBackend()
        artifact = b"test artifact for round trip"

        # Sign
        signature = backend.sign(artifact, sample_identity)

        # Verify with same artifact
        assert backend.verify(artifact, signature) is True

        # Verify with different artifact should fail
        wrong_artifact = b"different artifact"
        assert backend.verify(wrong_artifact, signature) is False
