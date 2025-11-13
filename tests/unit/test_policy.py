"""Unit tests for policy.py module."""

import pytest
from pathlib import Path

from signer.policy import Policy, PolicyEngine, PolicyResult
from signer.backends.base import Signature  # Import directly from base


class TestPolicy:
    """Tests for Policy dataclass."""

    def test_policy_creation(self):
        """Test creating a policy with required fields."""
        policy = Policy(match="*.tar.gz", require=["gpg", "cosign"])

        assert policy.match == "*.tar.gz"
        assert policy.require == ["gpg", "cosign"]
        assert policy.min_signatures == 1
        assert policy.allow_expired is False

    def test_policy_with_optional_fields(self):
        """Test creating a policy with optional fields."""
        policy = Policy(
            match="release-*",
            require=["gpg"],
            min_signatures=2,
            allow_expired=True,
        )

        assert policy.match == "release-*"
        assert policy.require == ["gpg"]
        assert policy.min_signatures == 2
        assert policy.allow_expired is True


class TestPolicyEngine:
    """Tests for PolicyEngine class."""

    def test_init_empty(self):
        """Test initializing with no policies."""
        engine = PolicyEngine([])

        assert engine.policies == []

    def test_init_with_policies(self):
        """Test initializing with policies."""
        policies = [
            Policy(match="*.tar.gz", require=["gpg"]),
            Policy(match="*.zip", require=["cosign"]),
        ]
        engine = PolicyEngine(policies)

        assert len(engine.policies) == 2
        assert engine.policies[0].match == "*.tar.gz"
        assert engine.policies[1].match == "*.zip"


class TestMatchArtifact:
    """Tests for match_artifact method."""

    def test_match_simple_extension(self):
        """Test matching simple file extension."""
        engine = PolicyEngine([])

        assert engine.match_artifact("file.tar.gz", "*.tar.gz")
        assert engine.match_artifact("release.tar.gz", "*.tar.gz")
        assert not engine.match_artifact("file.zip", "*.tar.gz")

    def test_match_prefix(self):
        """Test matching file prefix."""
        engine = PolicyEngine([])

        assert engine.match_artifact("release-1.0.tar.gz", "release-*")
        assert engine.match_artifact("release-v2.tar.gz", "release-*")
        assert not engine.match_artifact("artifact-1.0.tar.gz", "release-*")

    def test_match_exact(self):
        """Test matching exact filename."""
        engine = PolicyEngine([])

        assert engine.match_artifact("important.tar.gz", "important.tar.gz")
        assert not engine.match_artifact("important2.tar.gz", "important.tar.gz")

    def test_match_wildcard(self):
        """Test matching with wildcard."""
        engine = PolicyEngine([])

        assert engine.match_artifact("file.txt", "*")
        assert engine.match_artifact("any-file.tar.gz", "*")

    def test_match_with_path(self):
        """Test matching works with full paths."""
        engine = PolicyEngine([])

        assert engine.match_artifact("/path/to/file.tar.gz", "*.tar.gz")
        assert engine.match_artifact("relative/path/file.tar.gz", "*.tar.gz")
        assert engine.match_artifact("file.tar.gz", "*.tar.gz")

    def test_match_multiple_extensions(self):
        """Test matching multiple extensions."""
        engine = PolicyEngine([])

        assert engine.match_artifact("file.tar.gz", "*.tar.gz")
        assert engine.match_artifact("file.tar.bz2", "*.tar.bz2")
        assert not engine.match_artifact("file.tar.gz", "*.tar.bz2")

    def test_match_question_mark_wildcard(self):
        """Test matching with ? wildcard."""
        engine = PolicyEngine([])

        assert engine.match_artifact("file1.txt", "file?.txt")
        assert engine.match_artifact("fileA.txt", "file?.txt")
        assert not engine.match_artifact("file12.txt", "file?.txt")


class TestGetRequiredBackends:
    """Tests for get_required_backends method."""

    def test_no_policies(self):
        """Test with no policies configured."""
        engine = PolicyEngine([])

        result = engine.get_required_backends("file.tar.gz")

        assert result == []

    def test_single_policy_match(self):
        """Test single matching policy."""
        policies = [Policy(match="*.tar.gz", require=["gpg", "cosign"])]
        engine = PolicyEngine(policies)

        result = engine.get_required_backends("release.tar.gz")

        assert result == ["gpg", "cosign"]

    def test_single_policy_no_match(self):
        """Test no matching policy."""
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        engine = PolicyEngine(policies)

        result = engine.get_required_backends("release.zip")

        assert result == []

    def test_first_match_wins(self):
        """Test that first matching policy wins."""
        policies = [
            Policy(match="release-*", require=["gpg"]),
            Policy(match="*.tar.gz", require=["cosign"]),
            Policy(match="*", require=["gpg", "cosign"]),
        ]
        engine = PolicyEngine(policies)

        # Matches first policy
        result = engine.get_required_backends("release-1.0.tar.gz")
        assert result == ["gpg"]

        # Matches second policy
        result = engine.get_required_backends("artifact.tar.gz")
        assert result == ["cosign"]

        # Matches third policy
        result = engine.get_required_backends("something.zip")
        assert result == ["gpg", "cosign"]

    def test_policy_ordering_matters(self):
        """Test that policy order affects which one matches."""
        # Order 1: specific pattern first
        policies1 = [
            Policy(match="release-*", require=["gpg"]),
            Policy(match="*", require=["cosign"]),
        ]
        engine1 = PolicyEngine(policies1)

        # Order 2: wildcard first
        policies2 = [
            Policy(match="*", require=["cosign"]),
            Policy(match="release-*", require=["gpg"]),
        ]
        engine2 = PolicyEngine(policies2)

        artifact = "release-1.0.tar.gz"

        # First engine returns gpg (specific match)
        assert engine1.get_required_backends(artifact) == ["gpg"]

        # Second engine returns cosign (wildcard matches first)
        assert engine2.get_required_backends(artifact) == ["cosign"]


class TestValidateSignatures:
    """Tests for validate_signatures method."""

    def test_no_policy_always_valid(self):
        """Test validation succeeds when no policy matches."""
        engine = PolicyEngine([])

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})
        result = engine.validate_signatures("file.txt", [sig1])

        assert result.compliant is True
        assert result.matched_policy is None
        assert result.required_backends == []
        assert result.violations == []

    def test_policy_match_valid_signatures(self):
        """Test validation succeeds when signatures meet policy."""
        policies = [Policy(match="*.tar.gz", require=["gpg", "cosign"])]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})
        sig2 = Signature(format="cosign", data=b"", metadata={}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1, sig2])

        assert result.compliant is True
        assert result.matched_policy is not None
        assert result.required_backends == ["gpg", "cosign"]
        assert set(result.present_backends) == {"gpg", "cosign"}
        assert result.missing_backends == []
        assert result.signature_count == 2
        assert result.violations == []

    def test_policy_match_missing_backend(self):
        """Test validation fails when required backend is missing."""
        policies = [Policy(match="*.tar.gz", require=["gpg", "cosign"])]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1])

        assert result.compliant is False
        assert result.required_backends == ["gpg", "cosign"]
        assert result.present_backends == ["gpg"]
        assert result.missing_backends == ["cosign"]
        assert "Missing required backends: cosign" in result.violations

    def test_policy_match_insufficient_signatures(self):
        """Test validation fails when signature count is insufficient."""
        policies = [Policy(match="*.tar.gz", require=["gpg"], min_signatures=2)]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1])

        assert result.compliant is False
        assert result.signature_count == 1
        assert "Expected at least 2 signatures, got 1" in result.violations

    def test_policy_expired_signatures_not_allowed(self):
        """Test validation fails when expired signatures are present and not allowed."""
        policies = [Policy(match="*.tar.gz", require=["gpg"], allow_expired=False)]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={"expired": True}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1])

        assert result.compliant is False
        assert "Expired signature not allowed: gpg" in result.violations

    def test_policy_expired_signatures_allowed(self):
        """Test validation succeeds when expired signatures are allowed."""
        policies = [Policy(match="*.tar.gz", require=["gpg"], allow_expired=True)]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={"expired": True}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1])

        assert result.compliant is True
        assert result.violations == []

    def test_multiple_violations(self):
        """Test multiple violations are reported."""
        policies = [
            Policy(
                match="*.tar.gz",
                require=["gpg", "cosign"],
                min_signatures=3,
                allow_expired=False,
            )
        ]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={"expired": True}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1])

        assert result.compliant is False
        assert len(result.violations) == 3
        assert any("at least 3 signatures" in v for v in result.violations)
        assert any("Missing required backends: cosign" in v for v in result.violations)
        assert any("Expired signature not allowed" in v for v in result.violations)

    def test_extra_backends_allowed(self):
        """Test validation succeeds with extra backends beyond requirements."""
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})
        sig2 = Signature(format="cosign", data=b"", metadata={}, files={})
        sig3 = Signature(format="intoto", data=b"", metadata={}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1, sig2, sig3])

        assert result.compliant is True
        assert result.required_backends == ["gpg"]
        assert set(result.present_backends) == {"gpg", "cosign", "intoto"}
        assert result.missing_backends == []


class TestGenerateComplianceReport:
    """Tests for generate_compliance_report method."""

    def test_report_no_policy(self):
        """Test compliance report when no policy matches."""
        engine = PolicyEngine([])

        sig1 = Signature(format="gpg", data=b"", metadata={"key": "value"}, files={})

        report = engine.generate_compliance_report("file.txt", [sig1])

        assert report["artifact"] == "file.txt"
        assert report["compliant"] is True
        assert report["policy_matched"] is False
        assert report["signature_count"] == 1
        assert len(report["signatures"]) == 1
        assert "violations" not in report

    def test_report_with_policy_compliant(self):
        """Test compliance report with matching policy and compliance."""
        policies = [Policy(match="*.tar.gz", require=["gpg"], min_signatures=1)]
        engine = PolicyEngine(policies)

        sig1 = Signature(
            format="gpg",
            data=b"",
            metadata={"key": "value"},
            files={},
        )

        report = engine.generate_compliance_report("release.tar.gz", [sig1])

        assert report["artifact"] == "release.tar.gz"
        assert report["compliant"] is True
        assert report["policy_matched"] is True
        assert report["policy"]["match"] == "*.tar.gz"
        assert report["policy"]["require"] == ["gpg"]
        assert report["policy"]["min_signatures"] == 1
        assert report["required_backends"] == ["gpg"]
        assert report["present_backends"] == ["gpg"]
        assert report["missing_backends"] == []
        assert "violations" not in report

    def test_report_with_policy_non_compliant(self):
        """Test compliance report with violations."""
        policies = [Policy(match="*.tar.gz", require=["gpg", "cosign"])]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})

        report = engine.generate_compliance_report("release.tar.gz", [sig1])

        assert report["artifact"] == "release.tar.gz"
        assert report["compliant"] is False
        assert report["policy_matched"] is True
        assert report["missing_backends"] == ["cosign"]
        assert len(report["violations"]) > 0
        assert any("Missing required backends" in v for v in report["violations"])

    def test_report_includes_signature_metadata(self):
        """Test that report includes signature metadata."""
        policies = [Policy(match="*", require=["gpg"])]
        engine = PolicyEngine(policies)

        sig1 = Signature(
            format="gpg",
            data=b"",
            metadata={"issuer": "test@example.com", "timestamp": "2024-01-01"},
            files={},
        )

        report = engine.generate_compliance_report("file.txt", [sig1])

        assert len(report["signatures"]) == 1
        assert report["signatures"][0]["format"] == "gpg"
        assert report["signatures"][0]["metadata"]["issuer"] == "test@example.com"
        assert report["signatures"][0]["metadata"]["timestamp"] == "2024-01-01"


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_signatures_list(self):
        """Test validation with no signatures."""
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        engine = PolicyEngine(policies)

        result = engine.validate_signatures("release.tar.gz", [])

        assert result.compliant is False
        assert result.signature_count == 0
        assert "Missing required backends: gpg" in result.violations

    def test_empty_required_backends(self):
        """Test policy with no required backends."""
        policies = [Policy(match="*.tar.gz", require=[])]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})
        result = engine.validate_signatures("release.tar.gz", [sig1])

        assert result.compliant is True
        assert result.required_backends == []

    def test_case_sensitive_pattern_matching(self):
        """Test that pattern matching is case-sensitive."""
        engine = PolicyEngine([])

        # fnmatch is case-sensitive on Unix-like systems
        assert engine.match_artifact("FILE.TXT", "file.txt") is False
        assert engine.match_artifact("file.txt", "file.txt") is True

    def test_duplicate_backend_signatures(self):
        """Test handling of duplicate backend signatures."""
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"sig1", metadata={}, files={})
        sig2 = Signature(format="gpg", data=b"sig2", metadata={}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1, sig2])

        # Both signatures count toward total
        assert result.signature_count == 2
        # But only one backend format is present
        assert result.present_backends == ["gpg"]
        assert result.compliant is True

    def test_min_signatures_with_multiple_backends(self):
        """Test min_signatures requirement with multiple backend types."""
        policies = [
            Policy(match="*.tar.gz", require=["gpg", "cosign"], min_signatures=3)
        ]
        engine = PolicyEngine(policies)

        sig1 = Signature(format="gpg", data=b"", metadata={}, files={})
        sig2 = Signature(format="cosign", data=b"", metadata={}, files={})

        result = engine.validate_signatures("release.tar.gz", [sig1, sig2])

        # Has all required backends but not enough total signatures
        assert result.compliant is False
        assert result.missing_backends == []
        assert "Expected at least 3 signatures, got 2" in result.violations

    def test_special_characters_in_pattern(self):
        """Test patterns with special characters."""
        engine = PolicyEngine([])

        assert engine.match_artifact("file-v1.0.tar.gz", "file-v*.tar.gz")
        assert engine.match_artifact("my_file.tar.gz", "my_*.tar.gz")
        # fnmatch treats [] as character class, so file[1].txt matches file1.txt
        assert engine.match_artifact("file1.txt", "file[1].txt")
