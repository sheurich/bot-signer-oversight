"""Unit tests for rotation.py module."""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from signer.rotation import (
    KeyRotationProof,
    generate_rotation_proof,
    verify_rotation_chain,
    save_rotation_proof,
    load_rotation_proof,
    load_rotation_chain,
)


class TestKeyRotationProof:
    """Tests for KeyRotationProof class."""

    def test_init(self):
        """Test initialization of KeyRotationProof."""
        proof = KeyRotationProof(
            old_key_fingerprint="ABCD1234",
            new_key_fingerprint="EFGH5678",
            rotation_timestamp="2025-11-13T12:00:00+00:00",
            signed_statement="signature_data",
            reason="Key expiration",
            metadata={"authorized_by": "admin@example.com"},
        )

        assert proof.old_key_fingerprint == "ABCD1234"
        assert proof.new_key_fingerprint == "EFGH5678"
        assert proof.rotation_timestamp == "2025-11-13T12:00:00+00:00"
        assert proof.signed_statement == "signature_data"
        assert proof.reason == "Key expiration"
        assert proof.metadata["authorized_by"] == "admin@example.com"

    def test_init_minimal(self):
        """Test initialization with minimal fields."""
        proof = KeyRotationProof(
            old_key_fingerprint="ABCD1234",
            new_key_fingerprint="EFGH5678",
            rotation_timestamp="2025-11-13T12:00:00+00:00",
            signed_statement="signature_data",
        )

        assert proof.old_key_fingerprint == "ABCD1234"
        assert proof.new_key_fingerprint == "EFGH5678"
        assert proof.reason is None
        assert proof.metadata == {}

    def test_to_dict(self):
        """Test conversion to dictionary."""
        proof = KeyRotationProof(
            old_key_fingerprint="ABCD1234",
            new_key_fingerprint="EFGH5678",
            rotation_timestamp="2025-11-13T12:00:00+00:00",
            signed_statement="signature_data",
            reason="Key expiration",
            metadata={"authorized_by": "admin@example.com"},
        )

        result = proof.to_dict()

        assert result["old_key_fingerprint"] == "ABCD1234"
        assert result["new_key_fingerprint"] == "EFGH5678"
        assert result["rotation_timestamp"] == "2025-11-13T12:00:00+00:00"
        assert result["signed_statement"] == "signature_data"
        assert result["reason"] == "Key expiration"
        assert result["metadata"]["authorized_by"] == "admin@example.com"

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "old_key_fingerprint": "ABCD1234",
            "new_key_fingerprint": "EFGH5678",
            "rotation_timestamp": "2025-11-13T12:00:00+00:00",
            "signed_statement": "signature_data",
            "reason": "Key expiration",
            "metadata": {"authorized_by": "admin@example.com"},
        }

        proof = KeyRotationProof.from_dict(data)

        assert proof.old_key_fingerprint == "ABCD1234"
        assert proof.new_key_fingerprint == "EFGH5678"
        assert proof.rotation_timestamp == "2025-11-13T12:00:00+00:00"
        assert proof.signed_statement == "signature_data"
        assert proof.reason == "Key expiration"
        assert proof.metadata["authorized_by"] == "admin@example.com"

    def test_from_dict_minimal(self):
        """Test creation from dictionary with minimal fields."""
        data = {
            "old_key_fingerprint": "ABCD1234",
            "new_key_fingerprint": "EFGH5678",
            "rotation_timestamp": "2025-11-13T12:00:00+00:00",
            "signed_statement": "signature_data",
        }

        proof = KeyRotationProof.from_dict(data)

        assert proof.old_key_fingerprint == "ABCD1234"
        assert proof.new_key_fingerprint == "EFGH5678"
        assert proof.reason is None
        assert proof.metadata == {}


class TestGenerateRotationProof:
    """Tests for generate_rotation_proof function."""

    def test_generate_basic(self):
        """Test basic rotation proof generation."""
        proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
        )

        assert proof.old_key_fingerprint == "KEY_OLD_123"
        assert proof.new_key_fingerprint == "KEY_NEW_456"
        assert proof.rotation_timestamp is not None
        assert proof.signed_statement is not None
        assert len(proof.signed_statement) == 64  # SHA256 hex length

    def test_generate_with_timestamp(self):
        """Test rotation proof with custom timestamp."""
        timestamp = datetime(2025, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

        proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
            timestamp=timestamp,
        )

        assert proof.rotation_timestamp == "2025-11-13T12:00:00+00:00"

    def test_generate_with_signed_by(self):
        """Test rotation proof with signed_by."""
        proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
            signed_by="admin@example.com",
        )

        assert proof.metadata["authorized_by"] == "admin@example.com"
        assert "admin@example.com" in proof.signed_statement or "authorized_by" in proof.metadata

    def test_generate_with_reason(self):
        """Test rotation proof with reason."""
        proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
            reason="Key expiration",
        )

        assert proof.reason == "Key expiration"

    def test_generate_all_parameters(self):
        """Test rotation proof with all parameters."""
        timestamp = datetime(2025, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

        proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
            timestamp=timestamp,
            signed_by="admin@example.com",
            reason="Key expiration",
        )

        assert proof.old_key_fingerprint == "KEY_OLD_123"
        assert proof.new_key_fingerprint == "KEY_NEW_456"
        assert proof.rotation_timestamp == "2025-11-13T12:00:00+00:00"
        assert proof.reason == "Key expiration"
        assert proof.metadata["authorized_by"] == "admin@example.com"


class TestVerifyRotationChain:
    """Tests for verify_rotation_chain function."""

    def test_verify_empty_chain(self):
        """Test verification of empty chain."""
        assert verify_rotation_chain([]) is True

    def test_verify_single_proof(self):
        """Test verification of single proof."""
        proof = generate_rotation_proof("KEY_1", "KEY_2")
        assert verify_rotation_chain([proof]) is True

    def test_verify_valid_chain(self):
        """Test verification of valid rotation chain."""
        proof1 = generate_rotation_proof("KEY_1", "KEY_2")
        proof2 = generate_rotation_proof("KEY_2", "KEY_3")
        proof3 = generate_rotation_proof("KEY_3", "KEY_4")

        assert verify_rotation_chain([proof1, proof2, proof3]) is True

    def test_verify_broken_chain(self):
        """Test verification of broken chain."""
        proof1 = generate_rotation_proof("KEY_1", "KEY_2")
        proof2 = generate_rotation_proof("KEY_3", "KEY_4")  # Break: KEY_2 -> KEY_3

        assert verify_rotation_chain([proof1, proof2]) is False

    def test_verify_chain_out_of_order(self):
        """Test that out of order chain is detected as invalid."""
        proof1 = generate_rotation_proof("KEY_1", "KEY_2")
        proof2 = generate_rotation_proof("KEY_2", "KEY_3")
        proof3 = generate_rotation_proof("KEY_3", "KEY_4")

        # Out of order
        assert verify_rotation_chain([proof1, proof3, proof2]) is False


class TestSaveLoadRotationProof:
    """Tests for save and load functions."""

    def test_save_rotation_proof(self, tmp_path):
        """Test saving rotation proof to file."""
        proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
            reason="Key expiration",
        )

        output_path = tmp_path / "rotation.json"
        result_path = save_rotation_proof(proof, str(output_path))

        assert result_path == str(output_path)
        assert output_path.exists()

        # Verify file contents
        with open(output_path, "r") as f:
            data = json.load(f)

        assert data["old_key_fingerprint"] == "KEY_OLD_123"
        assert data["new_key_fingerprint"] == "KEY_NEW_456"
        assert data["reason"] == "Key expiration"

    def test_load_rotation_proof(self, tmp_path):
        """Test loading rotation proof from file."""
        proof_data = {
            "old_key_fingerprint": "KEY_OLD_123",
            "new_key_fingerprint": "KEY_NEW_456",
            "rotation_timestamp": "2025-11-13T12:00:00+00:00",
            "signed_statement": "signature_data",
            "reason": "Key expiration",
            "metadata": {"authorized_by": "admin@example.com"},
        }

        input_path = tmp_path / "rotation.json"
        with open(input_path, "w") as f:
            json.dump(proof_data, f)

        proof = load_rotation_proof(str(input_path))

        assert proof.old_key_fingerprint == "KEY_OLD_123"
        assert proof.new_key_fingerprint == "KEY_NEW_456"
        assert proof.rotation_timestamp == "2025-11-13T12:00:00+00:00"
        assert proof.signed_statement == "signature_data"
        assert proof.reason == "Key expiration"
        assert proof.metadata["authorized_by"] == "admin@example.com"

    def test_save_and_load_roundtrip(self, tmp_path):
        """Test save and load roundtrip."""
        original_proof = generate_rotation_proof(
            old_key_id="KEY_OLD_123",
            new_key_id="KEY_NEW_456",
            signed_by="admin@example.com",
            reason="Key expiration",
        )

        output_path = tmp_path / "rotation.json"
        save_rotation_proof(original_proof, str(output_path))

        loaded_proof = load_rotation_proof(str(output_path))

        assert loaded_proof.old_key_fingerprint == original_proof.old_key_fingerprint
        assert loaded_proof.new_key_fingerprint == original_proof.new_key_fingerprint
        assert loaded_proof.rotation_timestamp == original_proof.rotation_timestamp
        assert loaded_proof.signed_statement == original_proof.signed_statement
        assert loaded_proof.reason == original_proof.reason
        assert loaded_proof.metadata == original_proof.metadata


class TestLoadRotationChain:
    """Tests for load_rotation_chain function."""

    def test_load_from_empty_directory(self, tmp_path):
        """Test loading from empty directory."""
        result = load_rotation_chain(str(tmp_path))
        assert result == []

    def test_load_from_nonexistent_directory(self, tmp_path):
        """Test loading from nonexistent directory."""
        nonexistent = tmp_path / "nonexistent"
        result = load_rotation_chain(str(nonexistent))
        assert result == []

    def test_load_single_proof(self, tmp_path):
        """Test loading single rotation proof."""
        proof = generate_rotation_proof("KEY_1", "KEY_2")
        save_rotation_proof(proof, str(tmp_path / "rotation1.rotation.json"))

        result = load_rotation_chain(str(tmp_path))

        assert len(result) == 1
        assert result[0].old_key_fingerprint == "KEY_1"
        assert result[0].new_key_fingerprint == "KEY_2"

    def test_load_multiple_proofs_sorted(self, tmp_path):
        """Test loading multiple proofs sorted by timestamp."""
        # Create proofs with different timestamps
        timestamp1 = datetime(2025, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
        timestamp2 = datetime(2025, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
        timestamp3 = datetime(2025, 11, 13, 14, 0, 0, tzinfo=timezone.utc)

        proof1 = generate_rotation_proof("KEY_1", "KEY_2", timestamp=timestamp1)
        proof2 = generate_rotation_proof("KEY_2", "KEY_3", timestamp=timestamp2)
        proof3 = generate_rotation_proof("KEY_3", "KEY_4", timestamp=timestamp3)

        # Save in random order
        save_rotation_proof(proof2, str(tmp_path / "rotation2.rotation.json"))
        save_rotation_proof(proof1, str(tmp_path / "rotation1.rotation.json"))
        save_rotation_proof(proof3, str(tmp_path / "rotation3.rotation.json"))

        result = load_rotation_chain(str(tmp_path))

        # Should be sorted by timestamp
        assert len(result) == 3
        assert result[0].old_key_fingerprint == "KEY_1"
        assert result[1].old_key_fingerprint == "KEY_2"
        assert result[2].old_key_fingerprint == "KEY_3"

    def test_load_ignores_non_rotation_files(self, tmp_path):
        """Test that non-rotation files are ignored."""
        proof = generate_rotation_proof("KEY_1", "KEY_2")
        save_rotation_proof(proof, str(tmp_path / "rotation.rotation.json"))

        # Create other files
        (tmp_path / "other.json").write_text("{}")
        (tmp_path / "readme.txt").write_text("test")

        result = load_rotation_chain(str(tmp_path))

        # Should only load rotation.rotation.json
        assert len(result) == 1
        assert result[0].old_key_fingerprint == "KEY_1"
