# `SPEC.md`

## 1. Overview

This document outlines the technical specifications for the `bot-signer` GitHub Actions workflows. The project establishes and maintains a cryptographically verifiable identity for a bot account using GnuPG and Cosign. All operations are designed to be highly auditable through signed git commits, logs, and native GitHub attestations.

---

## 2. Security Considerations

### 2.1. Empty Cosign Password

The Cosign private key is generated **without a password** (empty string) for operational simplicity in CI/CD environments. This design decision represents a trade-off:

- **Benefit**: Eliminates the need to manage and secure an additional password secret in the workflow environment
- **Trade-off**: The private key security relies entirely on GitHub's secret management and the `COSIGN_PRIVATE_KEY` secret protection
- **Mitigation**: The key material is written to disk only long enough for Cosign to emit `cosign.key`; the workflow immediately uploads the value to GitHub Secrets and securely shreds the file

A similar pattern is used for the GPG key pair: `pgp.key` is exported temporarily so it can be stored as the `PGP_PRIVATE_KEY` secret, and the workflow shreds the file as soon as the upload completes. Continuous access control therefore depends on GitHub's secret storage guarantees.

### 2.2. GitHub API Authentication

Secret management requires a Personal Access Token (PAT) with repository admin access:

- `GITHUB_TOKEN` cannot write repository secrets (security limitation)
- Requires `ADMIN_TOKEN` secret with "Secrets" write permission
- Token is only used during initialization workflow

### 2.3. Error Handling Strategy

All workflows follow a **fail-fast** approach:

- Any command failure immediately stops workflow execution
- No error recovery or retry logic is implemented
- Failed runs must be manually investigated and re-run
- This ensures cryptographic ceremonies are never partially completed

---

## 3. Prerequisites

Before running the initialization workflow, the following setup must be completed:

### 3.1. Repository Requirements

- An empty or new repository
- GitHub Actions must be enabled for the repository
- Repository must allow workflow runs with write permissions

### 3.2. Required Workflow Permissions

The initialization workflow requires the following permissions in the workflow file:

```yaml
permissions:
  contents: write # To commit and push files
  attestations: write # To create attestations
  id-token: write # For OIDC token generation
```

### 3.3. Required Secrets

Create these repository secrets before running the initialization workflow:

1. **`ADMIN_TOKEN`** - PAT with repository admin access (Secrets write permission)
2. **`COSIGN_PRIVATE_KEY`** - Empty placeholder (will be populated by workflow)
3. **`PGP_PRIVATE_KEY`** - Empty placeholder (will be populated by workflow)

**Steps:**
1. Settings → Secrets and variables → Actions → New repository secret
2. Create `ADMIN_TOKEN` with your PAT
3. Create `COSIGN_PRIVATE_KEY` and `PGP_PRIVATE_KEY` with empty/placeholder values

---

## 4. Workflows

### 4.1. Initialization Workflow (`.github/workflows/init.yml`)

This workflow establishes the root of trust and should be triggered manually once via `workflow_dispatch`. The individual commands live in the workflow file; the summary below captures the intent of each phase.

- Guard & setup - Installs Cosign/Gitsign, aborts if `cosign.pub` already exists, and configures the bot identity used for commits.
- Cosign ceremony - Runs `cosign generate-key-pair`, uploads the private key to the `COSIGN_PRIVATE_KEY` secret, shreds `cosign.key`, appends a Cosign entry to `changelog.txt`, and creates the first commit signed via gitsign. That commit adds `cosign.pub` and the ceremony log.
- GnuPG ceremony - Generates an Ed25519 GPG key for `github-actions[bot]`, exports it temporarily to `pgp.key` so it can populate the `PGP_PRIVATE_KEY` secret, shreds the export, appends a GPG entry to `changelog.txt`, and creates a GPG-signed commit containing `pgp.pub` plus the updated log.
- Attestation & push - Uses `actions/attest@v1` to create a provenance attestation that links the ceremony log to the workflow run, then pushes the Cosign-signed and GPG-signed commits to `main`.

Expected artifacts after a successful run:

- `cosign.pub` (Cosign public key)
- `pgp.pub` (GnuPG public key)
- `changelog.txt` with two ceremony entries
- Provenance attestation referencing the final commit SHA

### 4.2. Test Workflow (`.github/workflows/test.yml`)

This workflow can run on a weekly schedule or manually. It verifies that both signing setups remain functional and auditable.

- Environment prep - Installs Cosign/Gitsign, imports the GPG private key from secrets, and configures git for signature enforcement.
- GPG signing - Regenerates `last_modified.txt`, produces `last_modified.txt.pgp.asc`, and creates a GPG-signed commit that stages both files.
- Cosign signing - Switches git to gitsign-based signing, generates `last_modified.txt.cosign` with `cosign sign-blob`, and commits the signature. The workflow relies on the `COSIGN_PRIVATE_KEY` secret injected at runtime.
- Push & reporting - Pushes the new commits to `main` and logs a short checklist of the produced artifacts.

Each run should leave the repository with fresher timestamp/signature files and a pair of verifiably signed commits that can be checked with `git log --show-signature`, Cosign verification tooling, or GitHub's attestation APIs.

## 5. Verification Steps

After successful initialization, verify the setup:

### 5.1. Verify Public Keys

```bash
# Check that public key files exist
ls -la cosign.pub pgp.pub changelog.txt

# Verify Cosign public key format
cat cosign.pub

# Verify GPG public key format
cat pgp.pub
```

### 5.2. Verify Commit Signatures

```bash
# Verify Cosign-signed commit (requires gitsign-verify or cosign verify)
git log --show-signature -1 <first-commit-sha>

# Verify GPG-signed commit
git log --show-signature -1 <second-commit-sha>
```

### 5.3. Verify Attestation

```bash
# Use GitHub CLI to view attestations
gh attestation verify <commit-sha> --repo <owner/repo>
```

### 5.4. Verify Secrets

Confirm that secrets are properly populated (cannot view actual values):

1. Navigate to **Settings** → **Secrets and variables** → **Actions**
2. Verify that both `COSIGN_PRIVATE_KEY` and `PGP_PRIVATE_KEY` show recent update timestamps

---

## 6. File Structure

After initialization, the repository will contain:

```
.github/
  workflows/
    init.yml          # Initialization workflow
    test.yml          # Test workflow
cosign.pub            # Cosign public key
pgp.pub               # GnuPG public key (Ed25519)
changelog.txt         # Ceremony logs
last_modified.txt     # Timestamp file (created by test workflow)
last_modified.txt.pgp.asc   # GPG signature (created by test workflow)
last_modified.txt.cosign    # Cosign signature (created by test workflow)
```

**Path Convention:** All file paths are relative to the repository root with no leading slash.

---

## 7. Ceremony Log Format

The `changelog.txt` file contains structured logs of all cryptographic ceremonies:

```
---
Ceremony: <Ceremony Name>
Date: <ISO 8601 UTC timestamp>
Workflow Run: <Full URL to GitHub Actions run>
Key Type: <Key algorithm and type>
[Additional ceremony-specific fields]
```

Each ceremony appends to this file, creating an auditable history of all key operations.

---

## 8. Dependencies

The workflows require the following tools:

- `cosign` (sigstore/cosign)
- `gitsign` (sigstore/gitsign) - for Cosign-signed git commits
- `gpg` (GnuPG 2.x)
- `gh` (GitHub CLI) - for secret management via API
- `git` (2.x or later)

All dependencies should be available in the GitHub Actions runner environment or installed during workflow setup.
