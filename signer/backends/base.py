"""Base signing backend interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class Signature:
    """Represents a cryptographic signature."""

    format: str  # gpg, cosign, intoto, github
    data: bytes  # signature bytes
    metadata: Dict[str, Any]  # format-specific metadata
    files: Dict[str, str]  # signature files created (e.g., {"signature": "file.sig"})


class SigningBackend(ABC):
    """Abstract base class for signing backends."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize backend with configuration."""
        self.config = config or {}

    @abstractmethod
    def sign(self, artifact: bytes, identity: Any) -> Signature:
        """
        Sign artifact with given identity.

        Args:
            artifact: Artifact bytes to sign
            identity: Identity object (OIDCIdentity, HSMIdentity, etc.)

        Returns:
            Signature object with signature data and metadata
        """
        pass

    @abstractmethod
    def verify(self, artifact: bytes, signature: Signature) -> bool:
        """
        Verify signature for artifact.

        Args:
            artifact: Original artifact bytes
            signature: Signature object to verify

        Returns:
            True if signature is valid, False otherwise
        """
        pass

    @abstractmethod
    def supports_keyless(self) -> bool:
        """
        Check if backend supports keyless signing.

        Returns:
            True if backend supports OIDC/keyless mode
        """
        pass

    @abstractmethod
    def get_format(self) -> str:
        """
        Get signature format identifier.

        Returns:
            Format name (e.g., "gpg", "cosign", "intoto")
        """
        pass

    def get_verification_command(self, artifact_path: str, signature: Signature) -> str:
        """
        Get shell command for verifying signature.

        Args:
            artifact_path: Path to artifact file
            signature: Signature object

        Returns:
            Shell command string for verification
        """
        return f"# No verification command for {self.get_format()}"
