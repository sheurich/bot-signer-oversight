"""Sigstore/Cosign keyless signing backend."""

import subprocess
import tempfile
import json
from pathlib import Path
from typing import Dict, Any
from .base import SigningBackend, Signature
from ..identity import OIDCIdentity


class SigstoreBackend(SigningBackend):
    """Cosign keyless signing using Fulcio and Rekor."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Sigstore backend."""
        super().__init__(config)
        self.fulcio_url = self.config.get(
            "fulcio_url", "https://fulcio.sigstore.dev"
        )
        self.rekor_url = self.config.get("rekor_url", "https://rekor.sigstore.dev")
        self.keyless_mode = self.config.get("keyless_mode", True)

    def sign(self, artifact: bytes, identity: OIDCIdentity) -> Signature:
        """
        Sign artifact using Cosign with OIDC identity.

        Args:
            artifact: Artifact bytes to sign
            identity: OIDC identity

        Returns:
            Signature with Cosign bundle
        """
        if not isinstance(identity, OIDCIdentity):
            raise ValueError("Sigstore backend requires OIDCIdentity")

        # Write artifact to temporary file
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            artifact_path = f.name
            f.write(artifact)

        try:
            # Create bundle output path
            bundle_path = f"{artifact_path}.bundle"

            # Sign with Cosign using OIDC token
            cmd = [
                "cosign",
                "sign-blob",
                "--yes",
                "--identity-token",
                identity.token,
                "--bundle",
                bundle_path,
                artifact_path,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )

            # Read bundle
            with open(bundle_path, "r") as f:
                bundle_data = json.load(f)

            # Extract metadata from bundle
            metadata = {
                "keyless": True,
                "algorithm": "ECDSA",
                "key_type": "P-256",
                "bundle_file": bundle_path,
                "fulcio_url": self.fulcio_url,
                "rekor_url": self.rekor_url,
                "subject": identity.subject,
                "issuer": identity.issuer,
            }

            # Extract certificate and Rekor info if available
            if "cert" in bundle_data:
                metadata["certificate"] = bundle_data["cert"]

            if "rekorBundle" in bundle_data:
                rekor_bundle = bundle_data["rekorBundle"]
                if "Payload" in rekor_bundle:
                    payload = rekor_bundle["Payload"]
                    metadata["rekor_index"] = payload.get("logIndex")
                    metadata["rekor_integrated_time"] = payload.get("integratedTime")

            # Verification command
            verification_cmd = (
                f"cosign verify-blob "
                f"--bundle {Path(bundle_path).name} "
                f"--certificate-identity {identity.subject} "
                f"--certificate-oidc-issuer {identity.issuer} "
                f"ARTIFACT"
            )

            metadata["verification_command"] = verification_cmd

            return Signature(
                format="cosign",
                data=bundle_data.get("base64Signature", "").encode(),
                metadata=metadata,
                files={"bundle": bundle_path},
            )

        finally:
            # Clean up temporary artifact file
            Path(artifact_path).unlink(missing_ok=True)

    def verify(self, artifact: bytes, signature: Signature) -> bool:
        """
        Verify Cosign signature.

        Args:
            artifact: Original artifact bytes
            signature: Signature to verify

        Returns:
            True if valid
        """
        # Write artifact to temporary file
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            artifact_path = f.name
            f.write(artifact)

        try:
            bundle_path = signature.files.get("bundle")
            if not bundle_path or not Path(bundle_path).exists():
                return False

            # Extract identity from metadata
            subject = signature.metadata.get("subject")
            issuer = signature.metadata.get("issuer")

            if not subject or not issuer:
                return False

            # Verify with Cosign
            cmd = [
                "cosign",
                "verify-blob",
                "--bundle",
                bundle_path,
                "--certificate-identity",
                subject,
                "--certificate-oidc-issuer",
                issuer,
                artifact_path,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                print(f"Cosign verification failed:")
                print(f"  Command: {' '.join(cmd)}")
                print(f"  Return code: {result.returncode}")
                print(f"  Stdout: {result.stdout}")
                print(f"  Stderr: {result.stderr}")

            return result.returncode == 0

        finally:
            Path(artifact_path).unlink(missing_ok=True)

    def supports_keyless(self) -> bool:
        """Sigstore supports keyless signing."""
        return True

    def get_format(self) -> str:
        """Get format identifier."""
        return "cosign"

    def get_verification_command(self, artifact_path: str, signature: Signature) -> str:
        """Get verification command."""
        bundle_file = Path(signature.files.get("bundle", "")).name
        return f"cosign verify-blob --bundle {bundle_file} {artifact_path}"
