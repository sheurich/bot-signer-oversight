"""Key rotation utilities for signing operations."""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class KeyRotationProof:
    """Represents a key rotation event with cryptographic proof."""

    old_key_fingerprint: str
    new_key_fingerprint: str
    rotation_timestamp: str
    signed_statement: str  # Signature of rotation statement by old key
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyRotationProof":
        """Create from dictionary."""
        return cls(
            old_key_fingerprint=data["old_key_fingerprint"],
            new_key_fingerprint=data["new_key_fingerprint"],
            rotation_timestamp=data["rotation_timestamp"],
            signed_statement=data["signed_statement"],
            reason=data.get("reason"),
            metadata=data.get("metadata", {}),
        )


def generate_rotation_proof(
    old_key_id: str,
    new_key_id: str,
    timestamp: Optional[datetime] = None,
    signed_by: Optional[str] = None,
    reason: Optional[str] = None,
) -> KeyRotationProof:
    """
    Generate a key rotation proof.

    Args:
        old_key_id: Fingerprint/ID of old key being rotated out
        new_key_id: Fingerprint/ID of new key being rotated in
        timestamp: Rotation timestamp (defaults to current UTC time)
        signed_by: Subject/identity authorizing rotation
        reason: Optional reason for rotation

    Returns:
        KeyRotationProof object
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    rotation_timestamp = timestamp.isoformat()

    # Create rotation statement
    statement = f"Key rotation from {old_key_id} to {new_key_id} at {rotation_timestamp}"
    if signed_by:
        statement += f" authorized by {signed_by}"

    # Hash the statement to create signed_statement
    # In real use, this would be signed by the old key
    statement_hash = hashlib.sha256(statement.encode()).hexdigest()

    metadata = {}
    if signed_by:
        metadata["authorized_by"] = signed_by

    return KeyRotationProof(
        old_key_fingerprint=old_key_id,
        new_key_fingerprint=new_key_id,
        rotation_timestamp=rotation_timestamp,
        signed_statement=statement_hash,
        reason=reason,
        metadata=metadata,
    )


def verify_rotation_chain(proofs: List[KeyRotationProof]) -> bool:
    """
    Verify continuity of key rotation chain.

    Args:
        proofs: List of rotation proofs in chronological order

    Returns:
        True if chain is valid (each new key matches next old key)
    """
    if not proofs:
        return True

    if len(proofs) == 1:
        return True

    # Verify each rotation links to the next
    for i in range(len(proofs) - 1):
        current_proof = proofs[i]
        next_proof = proofs[i + 1]

        # New key from current rotation should match old key of next rotation
        if current_proof.new_key_fingerprint != next_proof.old_key_fingerprint:
            return False

    return True


def save_rotation_proof(proof: KeyRotationProof, output_path: str) -> str:
    """
    Save rotation proof to JSON file.

    Args:
        proof: KeyRotationProof to save
        output_path: Path to output file

    Returns:
        Path to saved file
    """
    proof_dict = proof.to_dict()

    with open(output_path, "w") as f:
        json.dump(proof_dict, f, indent=2)

    return output_path


def load_rotation_proof(input_path: str) -> KeyRotationProof:
    """
    Load rotation proof from JSON file.

    Args:
        input_path: Path to JSON file

    Returns:
        KeyRotationProof object
    """
    with open(input_path, "r") as f:
        data = json.load(f)

    return KeyRotationProof.from_dict(data)


def load_rotation_chain(directory: str) -> List[KeyRotationProof]:
    """
    Load all rotation proofs from directory.

    Args:
        directory: Directory containing rotation proof JSON files

    Returns:
        List of rotation proofs sorted by timestamp
    """
    dir_path = Path(directory)
    if not dir_path.exists():
        return []

    proofs = []
    for proof_file in dir_path.glob("*.rotation.json"):
        proof = load_rotation_proof(str(proof_file))
        proofs.append(proof)

    # Sort by timestamp
    proofs.sort(key=lambda p: p.rotation_timestamp)

    return proofs
