"""Ceremony log generation for signing operations."""

import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from .backends.base import Signature
from .identity import OIDCIdentity, StaticKeyIdentity


class CeremonyLog:
    """Unified ceremony log for signing operations."""

    def __init__(
        self,
        artifact_path: str,
        identity: Any,
        signatures: List[Signature],
        workflow_run: Optional[str] = None,
    ):
        """
        Initialize ceremony log.

        Args:
            artifact_path: Path to signed artifact
            identity: Identity used for signing
            signatures: List of signatures created
            workflow_run: GitHub Actions workflow run URL
        """
        self.artifact_path = artifact_path
        self.identity = identity
        self.signatures = signatures
        self.workflow_run = workflow_run or os.getenv(
            "GITHUB_SERVER_URL", ""
        ) + "/" + os.getenv("GITHUB_REPOSITORY", "") + "/actions/runs/" + os.getenv(
            "GITHUB_RUN_ID", ""
        )
        self.timestamp = datetime.now(timezone.utc)

    def _compute_artifact_hashes(self) -> Dict[str, str]:
        """Compute SHA256 and SHA512 hashes of artifact."""
        with open(self.artifact_path, "rb") as f:
            data = f.read()

        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    def _get_artifact_size(self) -> int:
        """Get artifact file size in bytes."""
        return Path(self.artifact_path).stat().st_size

    def to_dict(self) -> Dict[str, Any]:
        """Convert ceremony log to dictionary."""
        artifact_hashes = self._compute_artifact_hashes()
        artifact_size = self._get_artifact_size()

        log = {
            "ceremony_version": "1.0",
            "ceremony_type": "artifact_signing",
            "timestamp": self.timestamp.isoformat(),
            "identity": self.identity.to_dict(),
            "artifact": {
                "path": self.artifact_path,
                "sha256": artifact_hashes["sha256"],
                "sha512": artifact_hashes["sha512"],
                "size": artifact_size,
            },
            "signatures": [],
            "workflow_run": self.workflow_run,
        }

        # Add signature details
        for sig in self.signatures:
            sig_entry = {
                "backend": sig.format,
                "format": sig.format,
                "files": sig.files,
                **sig.metadata,
            }
            log["signatures"].append(sig_entry)

        return log

    def to_json(self, indent: int = 2) -> str:
        """
        Convert ceremony log to JSON string.

        Args:
            indent: JSON indentation level

        Returns:
            JSON string
        """
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, output_path: Optional[str] = None) -> str:
        """
        Save ceremony log to file.

        Args:
            output_path: Path to save log (default: artifact_path + .ceremony.json)

        Returns:
            Path to saved file
        """
        if output_path is None:
            output_path = f"{self.artifact_path}.ceremony.json"

        with open(output_path, "w") as f:
            f.write(self.to_json())

        return output_path

    def generate_verification_script(self, output_path: Optional[str] = None) -> str:
        """
        Generate verification script for all signatures.

        Args:
            output_path: Path to save script (default: artifact_path + .verify.sh)

        Returns:
            Path to saved script
        """
        if output_path is None:
            output_path = f"{self.artifact_path}.verify.sh"

        artifact_name = Path(self.artifact_path).name

        script_lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "",
            f'ARTIFACT="{artifact_name}"',
            f'CEREMONY="{Path(output_path).with_suffix(".ceremony.json").name}"',
            "FAILED=0",
            "",
            'echo "Verifying signatures for $ARTIFACT"',
            'echo "Ceremony: $(jq -r .timestamp $CEREMONY)"',
            'echo "Identity: $(jq -r .identity.subject $CEREMONY)"',
            'echo "======================================"',
            "",
        ]

        # Add verification for each signature
        for sig in self.signatures:
            script_lines.append(f'echo "Checking {sig.format} signature..."')

            verify_cmd = sig.metadata.get("verification_command", "")
            if verify_cmd:
                script_lines.extend(
                    [
                        f"if {verify_cmd} 2>&1 | tee /tmp/verify-{sig.format}.log; then",
                        f'    echo "✅ {sig.format} signature valid"',
                        "else",
                        f'    echo "❌ {sig.format} signature FAILED"',
                        f"    cat /tmp/verify-{sig.format}.log",
                        "    FAILED=1",
                        "fi",
                        "",
                    ]
                )

        # Add final result
        script_lines.extend(
            [
                "if [ $FAILED -eq 0 ]; then",
                '    echo "======================================"',
                '    echo "✅ All signatures verified successfully"',
                '    echo "Artifact: $ARTIFACT"',
                '    echo "SHA256: $(sha256sum $ARTIFACT | cut -d\' \' -f1)"',
                "    exit 0",
                "else",
                '    echo "======================================"',
                '    echo "❌ One or more signatures failed"',
                "    exit 1",
                "fi",
            ]
        )

        with open(output_path, "w") as f:
            f.write("\n".join(script_lines))

        # Make script executable
        os.chmod(output_path, 0o755)

        return output_path
