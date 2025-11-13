"""GPG keyless signing backend using ephemeral keys."""

import gnupg
import tempfile
from pathlib import Path
from typing import Dict, Any
from .base import SigningBackend, Signature
from ..identity import OIDCIdentity


class GPGKeylessBackend(SigningBackend):
    """GPG signing with ephemeral keys bound to OIDC identity."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize GPG keyless backend."""
        super().__init__(config)
        self.key_type = self.config.get("key_type", "Ed25519")
        self.keyless_mode = self.config.get("keyless_mode", True)
        self.public_key_export = self.config.get("public_key_export", True)

    def sign(self, artifact: bytes, identity: OIDCIdentity) -> Signature:
        """
        Sign artifact using ephemeral GPG key.

        Args:
            artifact: Artifact bytes to sign
            identity: OIDC identity

        Returns:
            Signature with GPG detached signature and public key
        """
        if not isinstance(identity, OIDCIdentity):
            raise ValueError("GPG keyless backend requires OIDCIdentity")

        # Create temporary GPG home directory
        with tempfile.TemporaryDirectory() as gnupghome:
            # Configure GPG for non-interactive use
            gpg_conf_path = Path(gnupghome) / "gpg.conf"
            gpg_conf_path.write_text("pinentry-mode loopback\n")

            gpg_agent_conf_path = Path(gnupghome) / "gpg-agent.conf"
            gpg_agent_conf_path.write_text("allow-loopback-pinentry\n")

            gpg = gnupg.GPG(gnupghome=gnupghome)
            gpg.encoding = 'utf-8'

            # Generate batch key generation parameters
            batch_params = f"""
                %no-protection
                Key-Type: eddsa
                Key-Curve: ed25519
                Key-Usage: sign
                Name-Real: {identity.subject}
                Name-Email: {identity.subject_hash}@oidc.sigstore.dev
                Expire-Date: 7d
                %commit
            """

            key = gpg.gen_key(batch_params)
            key_fingerprint = str(key)

            if not key_fingerprint:
                # Get error details from GPG
                stderr = getattr(key, 'stderr', 'No error details')
                raise RuntimeError(f"Failed to generate GPG key: {stderr}")

            # Write artifact to temporary file
            with tempfile.NamedTemporaryFile(
                mode="wb", delete=False, suffix=".bin"
            ) as f:
                artifact_path = f.name
                f.write(artifact)

            try:
                # Create detached signature
                signature_path = f"{artifact_path}.asc"
                with open(artifact_path, "rb") as f:
                    signed = gpg.sign_file(
                        f,
                        keyid=key_fingerprint,
                        detach=True,
                        output=signature_path,
                    )

                if not signed:
                    raise RuntimeError(f"GPG signing failed: {signed.stderr}")

                # Export public key
                public_key_path = f"{artifact_path}.pub"
                public_key = gpg.export_keys(key_fingerprint)

                with open(public_key_path, "w") as f:
                    f.write(public_key)

                # Read signature data
                with open(signature_path, "rb") as f:
                    signature_data = f.read()

                # Build metadata
                metadata = {
                    "keyless": True,
                    "algorithm": "EdDSA" if self.key_type == "Ed25519" else "RSA",
                    "key_type": self.key_type,
                    "key_fingerprint": key_fingerprint,
                    "key_id": f"ephemeral:{key_fingerprint}",
                    "subject": identity.subject,
                    "subject_hash": identity.subject_hash,
                    "issuer": identity.issuer,
                    "verification_command": f"gpg --import {Path(public_key_path).name} && gpg --verify {Path(signature_path).name} ARTIFACT",
                }

                return Signature(
                    format="gpg",
                    data=signature_data,
                    metadata=metadata,
                    files={
                        "signature": signature_path,
                        "public_key": public_key_path,
                    },
                )

            finally:
                # Clean up temporary artifact file
                Path(artifact_path).unlink(missing_ok=True)

    def verify(self, artifact: bytes, signature: Signature) -> bool:
        """
        Verify GPG signature.

        Args:
            artifact: Original artifact bytes
            signature: Signature to verify

        Returns:
            True if valid
        """
        # Create temporary GPG home directory
        with tempfile.TemporaryDirectory() as gnupghome:
            gpg = gnupg.GPG(gnupghome=gnupghome)

            # Import public key
            public_key_path = signature.files.get("public_key")
            if not public_key_path or not Path(public_key_path).exists():
                return False

            with open(public_key_path, "r") as f:
                import_result = gpg.import_keys(f.read())

            if not import_result.count:
                return False

            # Write artifact to temporary file
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
                artifact_path = f.name
                f.write(artifact)

            try:
                # Get signature path
                signature_path = signature.files.get("signature")
                if not signature_path or not Path(signature_path).exists():
                    print(f"GPG: Signature file not found: {signature_path}")
                    return False

                # Verify signature
                # For detached signatures, pass signature path as data_filename parameter
                with open(signature_path, "rb") as sig_file:
                    verified = gpg.verify_file(sig_file, data_filename=artifact_path)

                if not verified.valid:
                    print(f"GPG verification failed:")
                    print(f"  Status: {verified.status}")
                    print(f"  Stderr: {verified.stderr}")
                    print(f"  Trust level: {verified.trust_level}")
                    print(f"  Trust text: {verified.trust_text}")

                return verified.valid

            finally:
                Path(artifact_path).unlink(missing_ok=True)

    def supports_keyless(self) -> bool:
        """GPG keyless backend supports keyless signing."""
        return True

    def get_format(self) -> str:
        """Get format identifier."""
        return "gpg"

    def get_verification_command(self, artifact_path: str, signature: Signature) -> str:
        """Get verification command."""
        sig_file = Path(signature.files.get("signature", "")).name
        pub_file = Path(signature.files.get("public_key", "")).name
        return f"gpg --import {pub_file} && gpg --verify {sig_file} {artifact_path}"
