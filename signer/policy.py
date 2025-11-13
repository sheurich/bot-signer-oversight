"""Policy engine for controlling signing requirements based on artifact patterns."""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .backends.base import Signature


@dataclass
class Policy:
    """Represents a signing policy for artifacts matching a pattern."""

    match: str  # glob pattern for artifact paths
    require: List[str]  # list of required backend formats
    min_signatures: int = 1  # minimum number of valid signatures required
    allow_expired: bool = False  # allow expired signatures


@dataclass
class PolicyResult:
    """Result of policy validation."""

    compliant: bool  # overall compliance status
    matched_policy: Optional[Policy]  # policy that matched
    required_backends: List[str]  # backends required by policy
    present_backends: List[str]  # backends found in signatures
    missing_backends: List[str]  # backends required but missing
    signature_count: int  # number of valid signatures
    violations: List[str]  # list of policy violations


class PolicyEngine:
    """Evaluates policies against artifacts and signatures."""

    def __init__(self, policies: List[Policy]):
        """
        Initialize policy engine with policies.

        Args:
            policies: List of Policy objects (evaluated in order, first match wins)
        """
        self.policies = policies

    def match_artifact(self, artifact_path: str, pattern: str) -> bool:
        """
        Check if artifact path matches a glob pattern.

        Args:
            artifact_path: Path to artifact (can be absolute or relative)
            pattern: Glob pattern to match (e.g., "*.tar.gz", "release-*")

        Returns:
            True if artifact matches pattern
        """
        # Use basename for matching to avoid path-specific patterns
        artifact_name = Path(artifact_path).name
        return fnmatch.fnmatch(artifact_name, pattern)

    def get_required_backends(self, artifact_path: str) -> List[str]:
        """
        Get list of required backends for an artifact based on policies.

        Args:
            artifact_path: Path to artifact

        Returns:
            List of backend format names required by matching policy
            Returns empty list if no policy matches
        """
        policy = self._find_matching_policy(artifact_path)
        if policy:
            return policy.require
        return []

    def validate_signatures(
        self, artifact_path: str, signatures: List["Signature"]
    ) -> PolicyResult:
        """
        Validate that signatures meet policy requirements.

        Args:
            artifact_path: Path to artifact
            signatures: List of Signature objects

        Returns:
            PolicyResult with compliance status and details
        """
        policy = self._find_matching_policy(artifact_path)

        if not policy:
            # No policy matches - allow any signatures
            return PolicyResult(
                compliant=True,
                matched_policy=None,
                required_backends=[],
                present_backends=[sig.format for sig in signatures],
                missing_backends=[],
                signature_count=len(signatures),
                violations=[],
            )

        # Check signature count
        violations = []
        if len(signatures) < policy.min_signatures:
            violations.append(
                f"Expected at least {policy.min_signatures} signatures, got {len(signatures)}"
            )

        # Check required backends are present
        present_formats = {sig.format for sig in signatures}
        required_formats = set(policy.require)
        missing_formats = required_formats - present_formats

        if missing_formats:
            violations.append(
                f"Missing required backends: {', '.join(sorted(missing_formats))}"
            )

        # Check for expired signatures if not allowed
        if not policy.allow_expired:
            for sig in signatures:
                if sig.metadata.get("expired", False):
                    violations.append(
                        f"Expired signature not allowed: {sig.format}"
                    )

        compliant = len(violations) == 0

        return PolicyResult(
            compliant=compliant,
            matched_policy=policy,
            required_backends=policy.require,
            present_backends=list(present_formats),
            missing_backends=list(missing_formats),
            signature_count=len(signatures),
            violations=violations,
        )

    def _find_matching_policy(self, artifact_path: str) -> Optional[Policy]:
        """
        Find first policy matching artifact path.

        Args:
            artifact_path: Path to artifact

        Returns:
            First matching Policy or None if no match
        """
        for policy in self.policies:
            if self.match_artifact(artifact_path, policy.match):
                return policy
        return None

    def generate_compliance_report(
        self, artifact_path: str, signatures: List["Signature"]
    ) -> Dict[str, Any]:
        """
        Generate detailed compliance report for artifact and signatures.

        Args:
            artifact_path: Path to artifact
            signatures: List of Signature objects

        Returns:
            Dictionary with compliance report details
        """
        result = self.validate_signatures(artifact_path, signatures)

        report = {
            "artifact": artifact_path,
            "compliant": result.compliant,
            "policy_matched": result.matched_policy is not None,
            "signature_count": result.signature_count,
            "signatures": [
                {
                    "format": sig.format,
                    "metadata": sig.metadata,
                }
                for sig in signatures
            ],
        }

        if result.matched_policy:
            report["policy"] = {
                "match": result.matched_policy.match,
                "require": result.matched_policy.require,
                "min_signatures": result.matched_policy.min_signatures,
                "allow_expired": result.matched_policy.allow_expired,
            }
            report["required_backends"] = result.required_backends
            report["present_backends"] = result.present_backends
            report["missing_backends"] = result.missing_backends

        if result.violations:
            report["violations"] = result.violations

        return report
