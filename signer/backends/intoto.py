"""In-toto/SLSA attestation backend using cryptography library."""

import json
import os
import tempfile
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError as e:
    raise ImportError(
        "cryptography library not found. Install with: pip install cryptography>=41.0.0"
    ) from e

from .base import SigningBackend, Signature
from ..identity import OIDCIdentity, StaticKeyIdentity


class IntotoBackend(SigningBackend):
    """In-toto attestation with SLSA v1.0 provenance."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize In-toto backend."""
        super().__init__(config)
        self.key_type = self.config.get("key_type", "ed25519")
        self.keyless_mode = self.config.get("keyless_mode", True)
        self.predicate_type = self.config.get(
            "predicate_type",
            "https://slsa.dev/provenance/v1.0"
        )

    def _extract_github_context(self) -> Dict[str, Any]:
        """
        Extract GitHub Actions context from environment variables.

        Returns:
            Dictionary with GitHub Actions context
        """
        return {
            "repository": os.getenv("GITHUB_REPOSITORY", "unknown/unknown"),
            "workflow": os.getenv("GITHUB_WORKFLOW", "unknown"),
            "ref": os.getenv("GITHUB_REF", "refs/heads/main"),
            "sha": os.getenv("GITHUB_SHA", "0" * 40),
            "run_id": os.getenv("GITHUB_RUN_ID", "0"),
            "run_number": os.getenv("GITHUB_RUN_NUMBER", "0"),
            "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT", "1"),
            "actor": os.getenv("GITHUB_ACTOR", "unknown"),
            "workflow_ref": os.getenv("GITHUB_WORKFLOW_REF", ""),
            "repository_owner": os.getenv("GITHUB_REPOSITORY_OWNER", "unknown"),
            "server_url": os.getenv("GITHUB_SERVER_URL", "https://github.com"),
        }

    def _compute_artifact_digest(self, artifact: bytes) -> Dict[str, str]:
        """
        Compute artifact digests.

        Args:
            artifact: Artifact bytes

        Returns:
            Dictionary with algorithm: digest pairs
        """
        return {
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "sha512": hashlib.sha512(artifact).hexdigest(),
        }

    def _build_slsa_provenance(
        self, artifact: bytes, identity: Any, github_ctx: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build SLSA v1.0 provenance predicate.

        Args:
            artifact: Artifact bytes
            identity: Identity object
            github_ctx: GitHub Actions context

        Returns:
            SLSA v1.0 provenance dictionary
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build builder info
        builder_id = f"{github_ctx['server_url']}/{github_ctx['repository']}/actions/runs/{github_ctx['run_id']}"

        provenance = {
            "buildDefinition": {
                "buildType": "https://slsa.dev/github-actions-workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "ref": github_ctx["ref"],
                        "repository": github_ctx["repository"],
                        "path": github_ctx["workflow"],
                    },
                },
                "internalParameters": {
                    "github": {
                        "actor": github_ctx["actor"],
                        "run_id": github_ctx["run_id"],
                        "run_number": github_ctx["run_number"],
                        "run_attempt": github_ctx["run_attempt"],
                        "sha": github_ctx["sha"],
                    }
                },
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {
                    "id": builder_id,
                },
                "metadata": {
                    "invocationId": f"{github_ctx['server_url']}/{github_ctx['repository']}/actions/runs/{github_ctx['run_id']}/attempts/{github_ctx['run_attempt']}",
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
            },
        }

        # Add identity information if OIDC
        if isinstance(identity, OIDCIdentity):
            provenance["runDetails"]["metadata"]["identity"] = {
                "issuer": identity.issuer,
                "subject": identity.subject,
            }

        return provenance

    def _build_intoto_statement(
        self, artifact: bytes, identity: Any, github_ctx: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build in-toto statement with SLSA provenance.

        Args:
            artifact: Artifact bytes
            identity: Identity object
            github_ctx: GitHub Actions context

        Returns:
            In-toto statement dictionary
        """
        digests = self._compute_artifact_digest(artifact)

        # Build SLSA provenance
        predicate = self._build_slsa_provenance(artifact, identity, github_ctx)

        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "artifact",
                    "digest": digests,
                }
            ],
            "predicateType": self.predicate_type,
            "predicate": predicate,
        }

        return statement

    def _compute_pae(self, payload_type: str, payload: bytes) -> bytes:
        """
        Compute DSSE Pre-Authentication Encoding.

        PAE format: "DSSEv1" + SP + LEN(payloadType) + SP + payloadType + SP + LEN(payload) + SP + payload

        Args:
            payload_type: DSSE payload type
            payload: Payload bytes

        Returns:
            PAE bytes
        """
        payload_type_bytes = payload_type.encode("utf-8")

        pae_parts = [
            b"DSSEv1",
            b" ",
            str(len(payload_type_bytes)).encode("ascii"),
            b" ",
            payload_type_bytes,
            b" ",
            str(len(payload)).encode("ascii"),
            b" ",
            payload,
        ]

        return b"".join(pae_parts)

    def _create_dsse_envelope(
        self, payload: bytes, private_key: ed25519.Ed25519PrivateKey, key_id: str
    ) -> Dict[str, Any]:
        """
        Create DSSE envelope with signature.

        Args:
            payload: Payload bytes to sign
            private_key: Ed25519 private key
            key_id: Key identifier

        Returns:
            DSSE envelope dictionary
        """
        payload_type = "application/vnd.in-toto+json"

        # Compute PAE for signing
        pae = self._compute_pae(payload_type, payload)

        # Sign the PAE
        signature_bytes = private_key.sign(pae)

        # Encode signature as base64
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        # Create DSSE envelope
        envelope = {
            "payload": base64.b64encode(payload).decode("utf-8"),
            "payloadType": payload_type,
            "signatures": [
                {
                    "keyid": key_id,
                    "sig": signature_b64,
                }
            ],
        }

        return envelope

    def _export_public_key_pem(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """
        Export public key in PEM format.

        Args:
            public_key: Ed25519 public key

        Returns:
            PEM-encoded public key string
        """
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode("utf-8")

    def _compute_key_id(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """
        Compute key ID from public key.

        Args:
            public_key: Ed25519 public key

        Returns:
            Key ID (SHA256 hash of public key bytes)
        """
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        key_hash = hashlib.sha256(public_key_bytes).hexdigest()
        return key_hash[:16]  # First 16 chars for shorter ID

    def sign(self, artifact: bytes, identity: Any) -> Signature:
        """
        Sign artifact with in-toto attestation.

        Args:
            artifact: Artifact bytes to sign
            identity: Identity object (OIDCIdentity or StaticKeyIdentity)

        Returns:
            Signature with in-toto attestation
        """
        # Extract GitHub Actions context
        github_ctx = self._extract_github_context()

        # Build in-toto statement
        statement = self._build_intoto_statement(artifact, identity, github_ctx)

        # Serialize statement to JSON bytes (canonical form)
        statement_json = json.dumps(statement, separators=(",", ":"), sort_keys=True)
        payload = statement_json.encode("utf-8")

        # Generate Ed25519 key
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Compute key ID
        key_id_base = self._compute_key_id(public_key)

        # Determine key ID based on identity
        if self.keyless_mode and isinstance(identity, OIDCIdentity):
            key_id = f"ephemeral:{identity.subject_hash}"
        elif isinstance(identity, StaticKeyIdentity):
            key_id = identity.key_id
        else:
            key_id = f"ephemeral:{key_id_base}"

        # Create DSSE envelope
        envelope = self._create_dsse_envelope(payload, private_key, key_id)

        # Write to temporary .intoto.jsonl file
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".intoto.jsonl"
        ) as f:
            attestation_path = f.name
            # Write as JSONL (each line is a JSON object)
            json.dump(envelope, f)
            f.write("\n")

        # Export public key in PEM format
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".pub.pem"
        ) as f:
            pubkey_path = f.name
            f.write(self._export_public_key_pem(public_key))

        # Build metadata
        metadata = {
            "keyless": self.keyless_mode and isinstance(identity, OIDCIdentity),
            "algorithm": "Ed25519",
            "key_type": self.key_type,
            "key_id": key_id,
            "predicate_type": self.predicate_type,
            "statement": statement,
            "github_context": github_ctx,
        }

        # Add identity information
        if isinstance(identity, OIDCIdentity):
            metadata["subject"] = identity.subject
            metadata["subject_hash"] = identity.subject_hash
            metadata["issuer"] = identity.issuer

        return Signature(
            format="intoto",
            data=envelope["payload"].encode("utf-8"),
            metadata=metadata,
            files={
                "attestation": attestation_path,
                "public_key": pubkey_path,
            },
        )

    def verify(self, artifact: bytes, signature: Signature) -> bool:
        """
        Verify in-toto attestation.

        Args:
            artifact: Original artifact bytes
            signature: Signature to verify

        Returns:
            True if valid
        """
        try:
            # Load attestation file
            attestation_path = signature.files.get("attestation")
            if not attestation_path or not Path(attestation_path).exists():
                print(f"In-toto: Attestation file not found: {attestation_path}")
                return False

            with open(attestation_path, "r") as f:
                envelope = json.load(f)

            # Load public key from PEM file
            pubkey_path = signature.files.get("public_key")
            if not pubkey_path or not Path(pubkey_path).exists():
                print(f"In-toto: Public key file not found: {pubkey_path}")
                return False

            with open(pubkey_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                print("In-toto: Invalid public key type (expected Ed25519)")
                return False

            # Decode payload from base64
            payload = base64.b64decode(envelope["payload"])

            # Parse statement from payload
            statement = json.loads(payload.decode("utf-8"))

            # Verify statement structure
            if statement.get("_type") != "https://in-toto.io/Statement/v1":
                print("In-toto: Invalid statement type")
                return False

            # Verify artifact digest matches subject
            artifact_digests = self._compute_artifact_digest(artifact)
            statement_subject = statement.get("subject", [])

            if not statement_subject:
                print("In-toto: No subject in statement")
                return False

            subject_digest = statement_subject[0].get("digest", {})
            if subject_digest.get("sha256") != artifact_digests["sha256"]:
                print("In-toto: Artifact digest mismatch")
                print(f"  Expected: {artifact_digests['sha256']}")
                print(f"  Got: {subject_digest.get('sha256')}")
                return False

            # Verify signature
            sig_dict = envelope["signatures"][0]
            signature_bytes = base64.b64decode(sig_dict["sig"])

            # Compute PAE for verification
            payload_type = envelope["payloadType"]
            pae = self._compute_pae(payload_type, payload)

            # Verify signature using Ed25519
            try:
                public_key.verify(signature_bytes, pae)
            except Exception as e:
                print(f"In-toto: Signature verification failed: {e}")
                return False

            return True

        except Exception as e:
            print(f"In-toto verification error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def supports_keyless(self) -> bool:
        """In-toto backend supports keyless signing."""
        return True

    def get_format(self) -> str:
        """Get format identifier."""
        return "intoto"

    def get_verification_command(
        self, artifact_path: str, signature: Signature
    ) -> str:
        """Get verification command."""
        attestation_file = Path(signature.files.get("attestation", "")).name
        pubkey_file = Path(signature.files.get("public_key", "")).name

        # Note: in-toto CLI verification would be:
        # in-toto-verify --layout <layout> --layout-keys <keys>
        # For SLSA, verification is more complex and typically done via policy engine
        return (
            f"# Verify in-toto attestation for {artifact_path}\n"
            f"# Attestation: {attestation_file}\n"
            f"# Public key: {pubkey_file}\n"
            f"# Manual verification requires parsing DSSE envelope and validating signatures"
        )
