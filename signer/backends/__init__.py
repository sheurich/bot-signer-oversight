"""Signing backend plugins."""

from .base import SigningBackend, Signature

# Lazy imports for backends to avoid dependency issues
# Import backends explicitly when needed in orchestrator.from_config()
__all__ = [
    "SigningBackend",
    "Signature",
    "GPGKeylessBackend",
    "SigstoreBackend",
    "IntotoBackend",
]


def __getattr__(name):
    """Lazy import backends to avoid optional dependency issues."""
    if name == "GPGKeylessBackend":
        from .gpg_keyless import GPGKeylessBackend
        return GPGKeylessBackend
    elif name == "SigstoreBackend":
        from .sigstore import SigstoreBackend
        return SigstoreBackend
    elif name == "IntotoBackend":
        from .intoto import IntotoBackend
        return IntotoBackend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
