"""Unit tests for identity.py module."""

import hashlib
import json
import base64
import pytest
import responses
from unittest.mock import Mock

from signer.identity import OIDCIdentity, StaticKeyIdentity


class TestOIDCIdentity:
    """Tests for OIDCIdentity class."""

    def test_subject_hash(self):
        """Test subject_hash property generates correct hash."""
        identity = OIDCIdentity(
            token="test.token.here",
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:owner/repo:ref:refs/heads/main",
            claims={},
        )

        expected_hash = hashlib.sha256(
            "repo:owner/repo:ref:refs/heads/main".encode()
        ).hexdigest()[:16]

        assert identity.subject_hash == expected_hash
        assert len(identity.subject_hash) == 16

    def test_subject_hash_consistency(self):
        """Test subject_hash is consistent for same subject."""
        subject = "repo:test/repo:ref:refs/heads/main"

        identity1 = OIDCIdentity(
            token="token1", issuer="issuer", subject=subject, claims={}
        )
        identity2 = OIDCIdentity(
            token="token2", issuer="issuer", subject=subject, claims={}
        )

        assert identity1.subject_hash == identity2.subject_hash

    @responses.activate
    def test_from_github_actions_success(self, monkeypatch, mock_oidc_token):
        """Test successful OIDC token acquisition from GitHub Actions."""
        token, payload = mock_oidc_token

        # Set up environment
        monkeypatch.setenv(
            "ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token?param=value"
        )
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token-123")

        # Mock the API response
        responses.add(
            responses.GET,
            "https://example.com/token?param=value&audience=sigstore",
            json={"value": token},
            status=200,
        )

        # Create identity
        identity = OIDCIdentity.from_github_actions(audience="sigstore")

        # Verify identity
        assert identity.token == token
        assert identity.issuer == payload["iss"]
        assert identity.subject == payload["sub"]
        assert identity.claims["repository"] == payload["repository"]
        assert identity.claims["workflow"] == payload["workflow"]

    @responses.activate
    def test_from_github_actions_custom_audience(self, monkeypatch, mock_oidc_token):
        """Test OIDC token acquisition with custom audience."""
        token, payload = mock_oidc_token

        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

        responses.add(
            responses.GET,
            "https://example.com/token&audience=custom-audience",
            json={"value": token},
            status=200,
        )

        identity = OIDCIdentity.from_github_actions(audience="custom-audience")

        assert identity.token == token
        assert len(responses.calls) == 1
        assert "audience=custom-audience" in responses.calls[0].request.url

    def test_from_github_actions_missing_url(self, monkeypatch):
        """Test error when ACTIONS_ID_TOKEN_REQUEST_URL is missing."""
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "token")

        with pytest.raises(RuntimeError) as exc_info:
            OIDCIdentity.from_github_actions()

        assert "Not running in GitHub Actions" in str(exc_info.value)

    def test_from_github_actions_missing_token(self, monkeypatch):
        """Test error when ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing."""
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)

        with pytest.raises(RuntimeError) as exc_info:
            OIDCIdentity.from_github_actions()

        assert "Not running in GitHub Actions" in str(exc_info.value)

    def test_from_github_actions_missing_both(self, monkeypatch):
        """Test error when both environment variables are missing."""
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)

        with pytest.raises(RuntimeError) as exc_info:
            OIDCIdentity.from_github_actions()

        assert "Not running in GitHub Actions" in str(exc_info.value)

    @responses.activate
    def test_from_github_actions_http_error(self, monkeypatch):
        """Test error handling when API request fails."""
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

        responses.add(
            responses.GET,
            "https://example.com/token&audience=sigstore",
            json={"error": "unauthorized"},
            status=403,
        )

        with pytest.raises(Exception):  # requests.HTTPError
            OIDCIdentity.from_github_actions()

    @responses.activate
    def test_from_github_actions_invalid_json(self, monkeypatch):
        """Test error handling when API returns invalid JSON."""
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

        responses.add(
            responses.GET,
            "https://example.com/token&audience=sigstore",
            body="invalid json",
            status=200,
        )

        with pytest.raises(Exception):  # json.JSONDecodeError
            OIDCIdentity.from_github_actions()

    @responses.activate
    def test_from_github_actions_missing_value_field(self, monkeypatch):
        """Test error handling when API response missing 'value' field."""
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

        responses.add(
            responses.GET,
            "https://example.com/token&audience=sigstore",
            json={"token": "wrong_field"},
            status=200,
        )

        with pytest.raises(KeyError):
            OIDCIdentity.from_github_actions()

    def test_to_dict_filters_ephemeral_claims(self, mock_oidc_token):
        """Test to_dict() filters out ephemeral claims."""
        token, payload = mock_oidc_token

        # Add ephemeral claims
        payload_with_ephemeral = payload.copy()
        payload_with_ephemeral["iat"] = 1234567890
        payload_with_ephemeral["nbf"] = 1234567890
        payload_with_ephemeral["exp"] = 1234567890
        payload_with_ephemeral["jti"] = "unique-token-id"

        identity = OIDCIdentity(
            token=token,
            issuer=payload["iss"],
            subject=payload["sub"],
            claims=payload_with_ephemeral,
        )

        result = identity.to_dict()

        # Verify structure
        assert result["type"] == "oidc"
        assert result["issuer"] == payload["iss"]
        assert result["subject"] == payload["sub"]

        # Verify ephemeral claims are filtered
        assert "iat" not in result["claims"]
        assert "nbf" not in result["claims"]
        assert "exp" not in result["claims"]
        assert "jti" not in result["claims"]

        # Verify stable claims are present
        assert result["claims"]["repository"] == payload["repository"]
        assert result["claims"]["workflow"] == payload["workflow"]
        assert result["claims"]["ref"] == payload["ref"]

    def test_to_dict_structure(self):
        """Test to_dict() returns correct structure."""
        identity = OIDCIdentity(
            token="test.token",
            issuer="https://issuer.example.com",
            subject="sub:test",
            claims={
                "repository": "owner/repo",
                "workflow": "test.yml",
                "iat": 1234567890,  # Should be filtered
            },
        )

        result = identity.to_dict()

        assert isinstance(result, dict)
        assert result["type"] == "oidc"
        assert result["issuer"] == "https://issuer.example.com"
        assert result["subject"] == "sub:test"
        assert isinstance(result["claims"], dict)
        assert result["claims"]["repository"] == "owner/repo"
        assert result["claims"]["workflow"] == "test.yml"
        assert "iat" not in result["claims"]

    def test_to_dict_empty_claims(self):
        """Test to_dict() handles empty claims."""
        identity = OIDCIdentity(
            token="test.token",
            issuer="https://issuer.example.com",
            subject="sub:test",
            claims={},
        )

        result = identity.to_dict()

        assert result["type"] == "oidc"
        assert result["claims"] == {}


class TestStaticKeyIdentity:
    """Tests for StaticKeyIdentity class."""

    def test_to_dict_basic(self):
        """Test to_dict() returns correct structure."""
        identity = StaticKeyIdentity(
            key_id="ABCD1234",
            key_type="gpg",
        )

        result = identity.to_dict()

        assert result["type"] == "static_key"
        assert result["key_type"] == "gpg"
        assert result["key_id"] == "ABCD1234"

    def test_to_dict_with_key_data(self):
        """Test to_dict() with key_data (should not be included in output)."""
        identity = StaticKeyIdentity(
            key_id="EFGH5678",
            key_type="cosign",
            key_data=b"secret key bytes",
        )

        result = identity.to_dict()

        assert result["type"] == "static_key"
        assert result["key_type"] == "cosign"
        assert result["key_id"] == "EFGH5678"
        assert "key_data" not in result  # Should not leak key data

    def test_to_dict_different_key_types(self):
        """Test to_dict() with various key types."""
        key_types = ["gpg", "cosign", "ssh", "x509"]

        for key_type in key_types:
            identity = StaticKeyIdentity(
                key_id=f"KEY_{key_type}",
                key_type=key_type,
            )

            result = identity.to_dict()

            assert result["key_type"] == key_type
            assert result["key_id"] == f"KEY_{key_type}"
