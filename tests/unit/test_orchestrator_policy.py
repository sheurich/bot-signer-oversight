"""Integration tests for orchestrator with policy engine."""

import pytest
from unittest.mock import Mock, patch, mock_open

from signer.orchestrator import SigningOrchestrator
from signer.backends.base import SigningBackend, Signature
from signer.policy import Policy, PolicyEngine
from signer.identity import OIDCIdentity


class MockBackend(SigningBackend):
    """Mock backend for testing."""

    def __init__(self, format_name="mock"):
        super().__init__()
        self.format_name = format_name
        self.sign_called = False

    def sign(self, artifact: bytes, identity) -> Signature:
        self.sign_called = True
        return Signature(
            format=self.format_name,
            data=b"signature data",
            metadata={"verification_command": f"verify_{self.format_name}"},
            files={"signature": f"/tmp/{self.format_name}.sig"},
        )

    def verify(self, artifact: bytes, signature: Signature) -> bool:
        return True

    def supports_keyless(self) -> bool:
        return True

    def get_format(self) -> str:
        return self.format_name


class TestOrchestratorWithPolicy:
    """Tests for SigningOrchestrator with PolicyEngine."""

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

    def test_orchestrator_without_policy(self, tmp_path, sample_identity):
        """Test orchestrator signs with all backends when no policy configured."""
        gpg_backend = MockBackend("gpg")
        cosign_backend = MockBackend("cosign")

        orchestrator = SigningOrchestrator([gpg_backend, cosign_backend])

        artifact = tmp_path / "artifact.txt"
        artifact.write_text("test")

        with patch("signer.orchestrator.CeremonyLog"):
            with patch.object(orchestrator, "_save_signature_files"):
                orchestrator.sign_artifact(
                    str(artifact),
                    sample_identity,
                    parallel=False,
                    generate_ceremony_log=False,
                    generate_verification_script=False,
                )

        assert gpg_backend.sign_called
        assert cosign_backend.sign_called

    def test_orchestrator_filters_backends_by_policy(self, tmp_path, sample_identity):
        """Test orchestrator only uses backends required by policy."""
        gpg_backend = MockBackend("gpg")
        cosign_backend = MockBackend("cosign")
        intoto_backend = MockBackend("intoto")

        # Policy requires only gpg for .tar.gz files
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        policy_engine = PolicyEngine(policies)

        orchestrator = SigningOrchestrator(
            [gpg_backend, cosign_backend, intoto_backend], policy_engine
        )

        artifact = tmp_path / "release.tar.gz"
        artifact.write_text("test")

        with patch("signer.orchestrator.CeremonyLog"):
            with patch.object(orchestrator, "_save_signature_files"):
                orchestrator.sign_artifact(
                    str(artifact),
                    sample_identity,
                    parallel=False,
                    generate_ceremony_log=False,
                    generate_verification_script=False,
                )

        assert gpg_backend.sign_called
        assert not cosign_backend.sign_called
        assert not intoto_backend.sign_called

    def test_orchestrator_requires_all_policy_backends(
        self, tmp_path, sample_identity
    ):
        """Test orchestrator fails if required backend is not configured."""
        gpg_backend = MockBackend("gpg")

        # Policy requires both gpg and cosign
        policies = [Policy(match="*.tar.gz", require=["gpg", "cosign"])]
        policy_engine = PolicyEngine(policies)

        orchestrator = SigningOrchestrator([gpg_backend], policy_engine)

        artifact = tmp_path / "release.tar.gz"
        artifact.write_text("test")

        with pytest.raises(
            RuntimeError,
            match="Policy requires backends that are not configured: cosign",
        ):
            orchestrator.sign_artifact(
                str(artifact),
                sample_identity,
                parallel=False,
                generate_ceremony_log=False,
                generate_verification_script=False,
            )

    def test_orchestrator_validates_policy_after_signing(
        self, tmp_path, sample_identity
    ):
        """Test orchestrator validates signatures meet policy requirements."""
        gpg_backend = MockBackend("gpg")
        cosign_backend = MockBackend("cosign")

        # Policy requires 3 signatures but we only have 2 backends
        policies = [Policy(match="*.tar.gz", require=["gpg", "cosign"], min_signatures=3)]
        policy_engine = PolicyEngine(policies)

        orchestrator = SigningOrchestrator([gpg_backend, cosign_backend], policy_engine)

        artifact = tmp_path / "release.tar.gz"
        artifact.write_text("test")

        with patch("signer.orchestrator.CeremonyLog"):
            with patch.object(orchestrator, "_save_signature_files"):
                with pytest.raises(
                    RuntimeError,
                    match="Signatures do not meet policy requirements",
                ):
                    orchestrator.sign_artifact(
                        str(artifact),
                        sample_identity,
                        parallel=False,
                        generate_ceremony_log=False,
                        generate_verification_script=False,
                    )

    def test_orchestrator_uses_all_backends_when_no_policy_matches(
        self, tmp_path, sample_identity
    ):
        """Test orchestrator uses all backends when no policy matches."""
        gpg_backend = MockBackend("gpg")
        cosign_backend = MockBackend("cosign")

        # Policy only for .tar.gz files
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        policy_engine = PolicyEngine(policies)

        orchestrator = SigningOrchestrator([gpg_backend, cosign_backend], policy_engine)

        # Sign a .zip file (no policy match)
        artifact = tmp_path / "release.zip"
        artifact.write_text("test")

        with patch("signer.orchestrator.CeremonyLog"):
            with patch.object(orchestrator, "_save_signature_files"):
                orchestrator.sign_artifact(
                    str(artifact),
                    sample_identity,
                    parallel=False,
                    generate_ceremony_log=False,
                    generate_verification_script=False,
                )

        # Both backends should be used
        assert gpg_backend.sign_called
        assert cosign_backend.sign_called

    def test_from_config_with_policies(self):
        """Test creating orchestrator from config with policies."""
        config = {
            "backends": {
                "gpg": {"enabled": True},
                "cosign": {"enabled": True},
            },
            "policies": [
                {
                    "match": "*.tar.gz",
                    "require": ["gpg", "cosign"],
                    "min_signatures": 2,
                    "allow_expired": False,
                },
                {
                    "match": "*",
                    "require": ["gpg"],
                },
            ],
        }

        orchestrator = SigningOrchestrator.from_config(config)

        assert orchestrator.policy_engine is not None
        assert len(orchestrator.policy_engine.policies) == 2
        assert orchestrator.policy_engine.policies[0].match == "*.tar.gz"
        assert orchestrator.policy_engine.policies[0].require == ["gpg", "cosign"]
        assert orchestrator.policy_engine.policies[0].min_signatures == 2
        assert orchestrator.policy_engine.policies[1].match == "*"

    def test_from_config_without_policies(self):
        """Test creating orchestrator from config without policies."""
        config = {
            "backends": {
                "gpg": {"enabled": True},
            },
        }

        orchestrator = SigningOrchestrator.from_config(config)

        assert orchestrator.policy_engine is None

    def test_generate_compliance_report(self, tmp_path):
        """Test generating compliance report."""
        import json

        gpg_backend = MockBackend("gpg")
        policies = [Policy(match="*.tar.gz", require=["gpg"])]
        policy_engine = PolicyEngine(policies)

        orchestrator = SigningOrchestrator([gpg_backend], policy_engine)

        artifact = tmp_path / "release.tar.gz"
        artifact.write_text("test")

        # Create mock ceremony log
        ceremony_log = {
            "signatures": [
                {
                    "format": "gpg",
                    "files": {"signature": "release.tar.gz.gpg.sig"},
                }
            ]
        }

        ceremony_path = tmp_path / "ceremony.json"
        ceremony_path.write_text(json.dumps(ceremony_log))

        report = orchestrator.generate_compliance_report(
            str(artifact), str(ceremony_path)
        )

        assert report["artifact"] == str(artifact)
        assert report["compliant"] is True
        assert report["policy_matched"] is True
        assert report["signature_count"] == 1

    def test_generate_compliance_report_without_policy_engine(self):
        """Test compliance report fails without policy engine."""
        orchestrator = SigningOrchestrator([])

        with pytest.raises(RuntimeError, match="Policy engine not configured"):
            orchestrator.generate_compliance_report("artifact.txt", "ceremony.json")
