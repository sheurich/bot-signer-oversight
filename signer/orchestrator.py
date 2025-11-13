"""Signing orchestrator for coordinating multiple backends."""

import concurrent.futures
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from .backends.base import SigningBackend, Signature
from .ceremony import CeremonyLog
from .identity import OIDCIdentity, StaticKeyIdentity


class SigningOrchestrator:
    """Coordinates signing operations across multiple backends."""

    def __init__(self, backends: List[SigningBackend]):
        """
        Initialize orchestrator with backends.

        Args:
            backends: List of signing backend instances
        """
        self.backends = backends

    def _save_signature_files(
        self, artifact_path: str, signatures: List[Signature]
    ) -> None:
        """
        Copy signature files from temporary locations to permanent locations.

        Updates signature objects with new file paths.

        Args:
            artifact_path: Path to the artifact being signed
            signatures: List of signatures to update
        """
        artifact_dir = Path(artifact_path).parent
        artifact_name = Path(artifact_path).name

        for sig in signatures:
            updated_files = {}

            for file_key, temp_path in sig.files.items():
                if not temp_path or not Path(temp_path).exists():
                    continue

                # Determine permanent file path
                temp_file = Path(temp_path)
                suffix = temp_file.suffix  # e.g., .asc, .pub, .bundle

                # Generate permanent filename
                permanent_filename = f"{artifact_name}.{sig.format}{suffix}"
                permanent_path = artifact_dir / permanent_filename

                # Copy file to permanent location
                shutil.copy2(temp_path, permanent_path)
                updated_files[file_key] = str(permanent_path)

                print(f"  Saved {file_key}: {permanent_filename}")

            # Update signature object with permanent paths
            sig.files = updated_files

    def sign_artifact(
        self,
        artifact_path: str,
        identity: Any,
        parallel: bool = True,
        generate_ceremony_log: bool = True,
        generate_verification_script: bool = True,
    ) -> CeremonyLog:
        """
        Sign artifact with all configured backends.

        Args:
            artifact_path: Path to artifact to sign
            identity: Identity to use for signing
            parallel: Run backends in parallel (default: True)
            generate_ceremony_log: Generate ceremony log (default: True)
            generate_verification_script: Generate verification script (default: True)

        Returns:
            CeremonyLog with all signatures

        Raises:
            RuntimeError: If signing fails
        """
        # Read artifact
        with open(artifact_path, "rb") as f:
            artifact_data = f.read()

        # Sign with each backend
        signatures: List[Signature] = []

        if parallel:
            # Sign in parallel for speed
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(self.backends)
            ) as executor:
                future_to_backend = {
                    executor.submit(backend.sign, artifact_data, identity): backend
                    for backend in self.backends
                }

                for future in concurrent.futures.as_completed(future_to_backend):
                    backend = future_to_backend[future]
                    try:
                        sig = future.result()
                        signatures.append(sig)
                        print(f"✅ Signed with {backend.get_format()}")
                    except Exception as e:
                        print(f"❌ Failed to sign with {backend.get_format()}: {e}")
                        raise
        else:
            # Sign sequentially
            for backend in self.backends:
                try:
                    sig = backend.sign(artifact_data, identity)
                    signatures.append(sig)
                    print(f"✅ Signed with {backend.get_format()}")
                except Exception as e:
                    print(f"❌ Failed to sign with {backend.get_format()}: {e}")
                    raise

        # Copy signature files to permanent locations
        self._save_signature_files(artifact_path, signatures)

        # Create ceremony log
        ceremony = CeremonyLog(artifact_path, identity, signatures)

        if generate_ceremony_log:
            log_path = ceremony.save()
            print(f"✅ Ceremony log saved: {log_path}")

        if generate_verification_script:
            script_path = ceremony.generate_verification_script()
            print(f"✅ Verification script generated: {script_path}")

        return ceremony

    def verify_artifact(self, artifact_path: str, ceremony_log_path: str) -> bool:
        """
        Verify artifact using ceremony log.

        Args:
            artifact_path: Path to artifact
            ceremony_log_path: Path to ceremony log

        Returns:
            True if all signatures verify successfully

        Raises:
            RuntimeError: If verification fails
        """
        import json

        # Load ceremony log
        with open(ceremony_log_path, "r") as f:
            ceremony_data = json.load(f)

        # Read artifact
        with open(artifact_path, "rb") as f:
            artifact_data = f.read()

        # Get artifact directory for resolving relative paths
        artifact_dir = Path(artifact_path).parent

        # Verify each signature
        all_valid = True
        for sig_data in ceremony_data["signatures"]:
            backend_format = sig_data["format"]

            # Find matching backend
            backend = None
            for b in self.backends:
                if b.get_format() == backend_format:
                    backend = b
                    break

            if backend is None:
                print(f"⚠️  No backend found for format: {backend_format}")
                continue

            # Resolve signature file paths relative to artifact directory
            resolved_files = {}
            for file_key, file_path in sig_data.get("files", {}).items():
                if file_path:
                    # If path is relative, resolve it relative to artifact directory
                    path_obj = Path(file_path)
                    if not path_obj.is_absolute():
                        resolved_path = artifact_dir / file_path
                    else:
                        resolved_path = path_obj
                    resolved_files[file_key] = str(resolved_path)

            # Reconstruct signature object
            sig = Signature(
                format=sig_data["format"],
                data=b"",  # Not needed for verification
                metadata=sig_data,
                files=resolved_files,
            )

            try:
                if backend.verify(artifact_data, sig):
                    print(f"✅ {backend_format} signature valid")
                else:
                    print(f"❌ {backend_format} signature invalid")
                    all_valid = False
            except Exception as e:
                print(f"❌ {backend_format} verification failed: {e}")
                all_valid = False

        return all_valid

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "SigningOrchestrator":
        """
        Create orchestrator from configuration.

        Args:
            config: Configuration dictionary

        Returns:
            SigningOrchestrator instance with configured backends
        """
        backends = []

        # Import backends dynamically
        if config.get("backends", {}).get("gpg", {}).get("enabled"):
            from .backends.gpg_keyless import GPGKeylessBackend

            backends.append(GPGKeylessBackend(config.get("backends", {}).get("gpg")))

        if config.get("backends", {}).get("cosign", {}).get("enabled"):
            from .backends.sigstore import SigstoreBackend

            backends.append(
                SigstoreBackend(config.get("backends", {}).get("cosign"))
            )

        return cls(backends)
