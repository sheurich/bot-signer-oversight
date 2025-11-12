"""Identity models for signing operations."""

import hashlib
import json
import os
import base64
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import requests


@dataclass
class OIDCIdentity:
    """OIDC-based identity for keyless signing."""

    token: str
    issuer: str
    subject: str
    claims: Dict[str, Any] = field(default_factory=dict)

    @property
    def subject_hash(self) -> str:
        """Get hash of subject for key generation."""
        return hashlib.sha256(self.subject.encode()).hexdigest()[:16]

    @classmethod
    def from_github_actions(cls, audience: str = "sigstore") -> "OIDCIdentity":
        """
        Create OIDC identity from GitHub Actions environment.

        Args:
            audience: OIDC token audience (default: "sigstore")

        Returns:
            OIDCIdentity with token and claims

        Raises:
            RuntimeError: If not running in GitHub Actions or token unavailable
        """
        token_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
        token_bearer = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

        if not token_url or not token_bearer:
            raise RuntimeError(
                "Not running in GitHub Actions or id-token permission not granted"
            )

        # Request OIDC token from GitHub Actions
        response = requests.get(
            f"{token_url}&audience={audience}",
            headers={"Authorization": f"bearer {token_bearer}"},
            timeout=10,
        )
        response.raise_for_status()

        token = response.json()["value"]

        # Decode JWT claims (without verification - Fulcio will verify)
        claims_b64 = token.split(".")[1]
        # Add padding if needed
        claims_b64 += "=" * (4 - len(claims_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(claims_b64))

        return cls(
            token=token,
            issuer=claims.get("iss", ""),
            subject=claims.get("sub", ""),
            claims=claims,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for ceremony log."""
        return {
            "type": "oidc",
            "issuer": self.issuer,
            "subject": self.subject,
            "claims": {
                k: v
                for k, v in self.claims.items()
                if k
                not in ["iat", "nbf", "exp", "jti"]  # Exclude ephemeral claim values
            },
        }


@dataclass
class StaticKeyIdentity:
    """Static key-based identity (for compatibility)."""

    key_id: str
    key_type: str  # gpg, cosign, etc.
    key_data: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for ceremony log."""
        return {
            "type": "static_key",
            "key_type": self.key_type,
            "key_id": self.key_id,
        }
