"""Signing orchestrator for coordinating multiple backends."""

import concurrent.futures
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from .backends.base import SigningBackend, Signature
from .ceremony import CeremonyLog
from .identity import OIDCIdentity, StaticKeyIdentity
from .policy import PolicyEngine, Policy


class SigningOrchestrator:
    """Coordinates signing operations across multiple backends."""

    def __init__(
        self, backends: List[SigningBackend], policy_engine: Optional[PolicyEngine] = None
    ):
        """
        Initialize orchestrator with backends.

        Args:
            backends: List of signing backend instances
            policy_engine: Optional PolicyEngine for applying signing policies
        """
        self.backends = backends
        self.policy_engine = policy_engine

    def _save_signature_files(
        self, artifact_path: str, signatures: List[Signature]
    ) -> None:
        """
        Copy signature files from temporary locations to permanent locations.

        Updates signature objects with new file paths and verification commands.

        Args:
            artifact_path: Path to the artifact being signed
            signatures: List of signatures to update
        """
        artifact_dir = Path(artifact_path).parent
        artifact_name = Path(artifact_path).name

        for sig in signatures:
            updated_files = {}
            old_to_new_paths = {}

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
                updated_files[file_key] = permanent_filename  # Store relative path

                # Track path mapping for updating verification command
                old_to_new_paths[Path(temp_path).name] = permanent_filename

                print(f"  Saved {file_key}: {permanent_filename}")

            # Update signature object with permanent paths
            sig.files = updated_files

            # Update verification command in metadata to use new file paths
            if "verification_command" in sig.metadata:
                verification_cmd = sig.metadata["verification_command"]
                # Replace old temp filenames with new permanent filenames
                for old_name, new_name in old_to_new_paths.items():
                    verification_cmd = verification_cmd.replace(old_name, new_name)
                sig.metadata["verification_command"] = verification_cmd

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
            RuntimeError: If signing fails or policy validation fails
        """
        # Read artifact
        with open(artifact_path, "rb") as f:
            artifact_data = f.read()

        # Apply policy to filter backends if policy engine is configured
        backends_to_use = self.backends
        if self.policy_engine:
            required_formats = self.policy_engine.get_required_backends(artifact_path)
            if required_formats:
                # Filter backends to only those required by policy
                backends_to_use = [
                    b for b in self.backends if b.get_format() in required_formats
                ]
                print(f"Policy requires backends: {', '.join(required_formats)}")

                # Check if all required backends are available
                available_formats = {b.get_format() for b in backends_to_use}
                missing_formats = set(required_formats) - available_formats
                if missing_formats:
                    raise RuntimeError(
                        f"Policy requires backends that are not configured: {', '.join(missing_formats)}"
                    )

        # Sign with each backend
        signatures: List[Signature] = []

        if parallel:
            # Sign in parallel for speed
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(backends_to_use)
            ) as executor:
                future_to_backend = {
                    executor.submit(backend.sign, artifact_data, identity): backend
                    for backend in backends_to_use
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
            for backend in backends_to_use:
                try:
                    sig = backend.sign(artifact_data, identity)
                    signatures.append(sig)
                    print(f"✅ Signed with {backend.get_format()}")
                except Exception as e:
                    print(f"❌ Failed to sign with {backend.get_format()}: {e}")
                    raise

        # Copy signature files to permanent locations
        self._save_signature_files(artifact_path, signatures)

        # Validate signatures meet policy requirements
        if self.policy_engine:
            validation_result = self.policy_engine.validate_signatures(
                artifact_path, signatures
            )
            if not validation_result.compliant:
                violations = "\n".join(f"  - {v}" for v in validation_result.violations)
                raise RuntimeError(
                    f"Signatures do not meet policy requirements:\n{violations}"
                )
            print("✅ Signatures meet policy requirements")

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
        artifact_dir = Path(artifact_path).resolve().parent

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
                print(f"Verifying {backend_format} with files: {resolved_files}")
                if backend.verify(artifact_data, sig):
                    print(f"✅ {backend_format} signature valid")
                else:
                    print(f"❌ {backend_format} signature invalid")
                    all_valid = False
            except Exception as e:
                print(f"❌ {backend_format} verification failed: {e}")
                import traceback
                traceback.print_exc()
                all_valid = False

        return all_valid

    def generate_compliance_report(
        self, artifact_path: str, ceremony_log_path: str
    ) -> Dict[str, Any]:
        """
        Generate compliance report for an artifact and its signatures.

        Args:
            artifact_path: Path to artifact
            ceremony_log_path: Path to ceremony log

        Returns:
            Dictionary with compliance report details

        Raises:
            RuntimeError: If policy engine is not configured
        """
        if not self.policy_engine:
            raise RuntimeError("Policy engine not configured")

        import json

        # Load ceremony log
        with open(ceremony_log_path, "r") as f:
            ceremony_data = json.load(f)

        # Reconstruct signature objects
        signatures = []
        for sig_data in ceremony_data["signatures"]:
            sig = Signature(
                format=sig_data["format"],
                data=b"",
                metadata=sig_data,
                files=sig_data.get("files", {}),
            )
            signatures.append(sig)

        # Generate report
        return self.policy_engine.generate_compliance_report(artifact_path, signatures)

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

        if config.get("backends", {}).get("intoto", {}).get("enabled"):
            from .backends.intoto import IntotoBackend

            backends.append(
                IntotoBackend(config.get("backends", {}).get("intoto"))
            )

        # Create policy engine if policies are configured
        policy_engine = None
        if config.get("policies"):
            policies = [
                Policy(
                    match=p["match"],
                    require=p["require"],
                    min_signatures=p.get("min_signatures", 1),
                    allow_expired=p.get("allow_expired", False),
                )
                for p in config["policies"]
            ]
            policy_engine = PolicyEngine(policies)

        return cls(backends, policy_engine)
