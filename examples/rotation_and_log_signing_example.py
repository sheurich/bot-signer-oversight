#!/usr/bin/env python3
"""Example usage of ceremony log signing and key rotation features."""

from datetime import datetime, timezone
from pathlib import Path
from signer.ceremony import CeremonyLog
from signer.rotation import (
    generate_rotation_proof,
    verify_rotation_chain,
    save_rotation_proof,
    load_rotation_chain,
)
from signer.identity import StaticKeyIdentity
from signer.backends.base import Signature

# Example 1: Key rotation proof generation
print("=== Key Rotation Example ===")

# Generate a rotation proof
rotation_proof = generate_rotation_proof(
    old_key_id="ABCD1234EFGH5678",
    new_key_id="IJKL9012MNOP3456",
    signed_by="admin@example.com",
    reason="Key expiration after 90 days",
)

print(f"Rotation from: {rotation_proof.old_key_fingerprint}")
print(f"Rotation to: {rotation_proof.new_key_fingerprint}")
print(f"Timestamp: {rotation_proof.rotation_timestamp}")
print(f"Reason: {rotation_proof.reason}")

# Save rotation proof to file
# save_rotation_proof(rotation_proof, "rotation_proof.json")

# Create a chain of rotations
rotation1 = generate_rotation_proof("KEY_A", "KEY_B", reason="Initial setup")
rotation2 = generate_rotation_proof("KEY_B", "KEY_C", reason="Scheduled rotation")
rotation3 = generate_rotation_proof("KEY_C", "KEY_D", reason="Security incident")

# Verify the chain is valid
chain = [rotation1, rotation2, rotation3]
is_valid = verify_rotation_chain(chain)
print(f"\nRotation chain valid: {is_valid}")

# Example 2: Ceremony log with chaining
print("\n=== Ceremony Log Signing Example ===")

# Create first ceremony log
identity = StaticKeyIdentity(key_id="GPG_KEY_123", key_type="gpg")

# Note: In real use, you would provide actual signatures
# For this example, we create a mock signature
mock_sig = Signature(
    format="gpg",
    data=b"mock signature data",
    metadata={"key_fingerprint": "ABCD1234"},
    files={"signature": "artifact.sig"},
)

# Create ceremony log (would use real artifact in production)
# log1 = CeremonyLog(
#     artifact_path="/path/to/artifact.bin",
#     identity=identity,
#     signatures=[mock_sig],
# )

# Get log fingerprint for chaining
# fingerprint1 = log1.get_log_fingerprint()
# print(f"Log 1 fingerprint: {fingerprint1}")

# Sign the log itself (in production, use real backend)
# from signer.backends.gpg_keyless import GPGKeylessBackend
# backend = GPGKeylessBackend()
# sig_path = log1.sign_log(backend, identity)
# print(f"Log signature saved to: {sig_path}")

# Verify log signature
# is_valid = log1.verify_log_signature(backend)
# print(f"Log signature valid: {is_valid}")

# Create second log chained to first
# log2 = CeremonyLog(
#     artifact_path="/path/to/artifact2.bin",
#     identity=identity,
#     signatures=[mock_sig],
#     chain_previous=fingerprint1,  # Chain to previous log
# )

# The chain_previous field creates an audit trail
# print(f"Log 2 chains to: {log2.chain_previous}")

print("\nExample complete!")
print("\nKey features:")
print("1. Rotation proofs track key lifecycle with cryptographic evidence")
print("2. Rotation chains verify continuity across multiple rotations")
print("3. Ceremony logs can be signed using any backend (GPG/Cosign)")
print("4. Log chaining creates tamper-evident audit trails")
print("5. Log fingerprints provide unique identification")
