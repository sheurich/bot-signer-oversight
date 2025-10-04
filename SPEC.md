# `SPEC.md`

## 1. Overview

This document outlines the technical specifications for the `bot-signer` GitHub Actions workflows. The project establishes and maintains a cryptographically verifiable identity for a bot account using GnuPG and Cosign. All operations are designed to be highly auditable through signed git commits, logs, and native GitHub attestations.

---

## 2. Security Considerations

### 2.1. Empty Cosign Password

The Cosign private key is generated **without a password** (empty string) for operational simplicity in CI/CD environments. This design decision represents a trade-off:

- **Benefit**: Eliminates the need to manage and secure an additional password secret in the workflow environment
- **Trade-off**: The private key security relies entirely on GitHub's secret management and the `COSIGN_PRIVATE_KEY` secret protection
- **Mitigation**: The key is never written to disk in plain text, only loaded into memory via environment variables, and GitHub's secret scanning prevents accidental exposure

### 2.2. GitHub API Authentication

All GitHub API operations use the built-in `GITHUB_TOKEN` provided automatically to workflow runs. This token:

- Has workflow-scoped permissions (contents: write, secrets: write)
- Automatically expires after the workflow completes
- Requires no additional credential management

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

### 3.3. Manual Secret Creation

Two empty repository secrets must be created manually via the GitHub UI **before** the first workflow run:

1. **`COSIGN_PRIVATE_KEY`** - Will store the Cosign private key
2. **`PGP_PRIVATE_KEY`** - Will store the GnuPG private key

**Steps to create secrets:**

1. Navigate to your repository on GitHub
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. For the first secret:
   - Name: `COSIGN_PRIVATE_KEY`
   - Value: Leave empty (just a space character or any placeholder)
   - Click **Add secret**
5. Repeat for the second secret:
   - Name: `PGP_PRIVATE_KEY`
   - Value: Leave empty (just a space character or any placeholder)
   - Click **Add secret**

These empty secrets serve as placeholders and will be populated by the initialization workflow with the actual cryptographic keys.

---

## 4. Workflows

### 4.1. Initialization Workflow (`.github/workflows/init.yml`)

This workflow establishes the root of trust. It is triggered manually via `workflow_dispatch` and should only be run **once** to initialize the repository.

#### 4.1.1. Cosign Root of Trust Ceremony

This step generates the Cosign key pair and creates the initial commit.

**Initialization Check:**

Before generating keys, verify that `cosign.pub` does not already exist:

```bash
if [ -f cosign.pub ]; then
  echo "Error: cosign.pub already exists. Initialization has already been performed."
  exit 1
fi
```

**Key Generation:**

```bash
# Set empty password for CI environment
export COSIGN_PASSWORD=""

# Generate key pair (creates cosign.key and cosign.pub)
cosign generate-key-pair

# Load private key into environment variable
export COSIGN_PRIVATE_KEY=$(cat cosign.key)

# Securely delete the private key file from disk
shred -vfz -n 5 cosign.key
```

**Secret Population:**

Use the GitHub API to store the Cosign private key:

```bash
gh secret set COSIGN_PRIVATE_KEY --body "$COSIGN_PRIVATE_KEY"
```

**File Creation:**

```bash
# Public key is already written to cosign.pub by cosign generate-key-pair

# Create ceremony log
cat >> changelog.txt << 'EOF'
---
Ceremony: Cosign Root of Trust Initialization
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Workflow Run: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
Key Type: Cosign (sigstore)
Password: Empty (for CI simplicity)
Public Key: cosign.pub
EOF
```

**Git Configuration and Commit:**

This commit **MUST** be signed using Cosign (e.g., via gitsign):

```bash
# Configure git for Cosign signing
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.x509.program gitsign
git config --global gpg.format x509

# Configure bot identity
git config --global user.name "github-actions[bot]"
git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"

# Create the initial Cosign-signed commit
git add cosign.pub changelog.txt
git commit -m "Initialize Cosign root of trust

This commit establishes the Cosign key pair for the bot identity.
The commit itself is signed using the newly generated Cosign key."
```

#### 4.1.2. GnuPG Root of Trust Ceremony

This step generates the GnuPG key pair and creates a second commit.

**Key Generation:**

Generate an Ed25519 key with no expiration:

```bash
# Generate Ed25519 key non-interactively
gpg --batch --gen-key << 'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: github-actions[bot]
Name-Email: 41898282+github-actions[bot]@users.noreply.github.com
Expire-Date: 0
%no-protection
%commit
EOF

# Get the key fingerprint
KEY_FPR=$(gpg --list-secret-keys --keyid-format LONG "github-actions[bot]" | grep -A 1 "sec" | tail -1 | tr -d ' ')

# Export private key
gpg --armor --export-secret-keys "$KEY_FPR" > pgp.key

# Export public key
gpg --armor --export "$KEY_FPR" > pgp.pub
```

**Secret Population:**

```bash
# Store private key in GitHub secret
gh secret set PGP_PRIVATE_KEY --body "$(cat pgp.key)"

# Securely delete private key file
shred -vfz -n 5 pgp.key
```

**Ceremony Log:**

```bash
cat >> changelog.txt << 'EOF'
---
Ceremony: GnuPG Root of Trust Initialization
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Workflow Run: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
Key Type: Ed25519 (EdDSA)
Key ID: $KEY_FPR
Expiration: No expiration
Public Key: pgp.pub
EOF
```

**Git Configuration and Commit:**

```bash
# Configure git for GPG signing
git config --global commit.gpgsign true
git config --global user.signingkey "$KEY_FPR"
git config --global gpg.program gpg

# Create GPG-signed commit
git add pgp.pub changelog.txt
git commit -S -m "Initialize GnuPG root of trust

This commit establishes the GnuPG key pair for the bot identity.
The commit is signed using the newly generated GPG key."
```

#### 4.1.3. Attestation

Create a GitHub attestation linking the cryptographic keys to this workflow run.

**Subject:**

The attestation subject is the SHA256 hash of the **final GPG-signed commit** created in step 4.1.2:

```bash
# Get the commit SHA
COMMIT_SHA=$(git rev-parse HEAD)

# Use GitHub's attestation action
- uses: actions/attest@v1
  with:
    subject-digest: sha256:${{ env.COMMIT_SHA }}
    predicate-type: https://github.com/bot-signer/initialization/v1
    predicate: |
      {
        "workflow_run": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}",
        "initialization_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "cosign_public_key_path": "cosign.pub",
        "gpg_public_key_path": "pgp.pub",
        "ceremony_log": "changelog.txt"
      }
```

**Predicate Structure:**

- **Type**: Custom predicate type identifying this as a bot-signer initialization
- **Content**: JSON object with workflow run URL, initialization timestamp, and file paths
- **Purpose**: Creates a verifiable link between the keys and their creation context

#### 4.1.4. Push

Push both commits to the repository:

```bash
git push origin main
```

**Expected Result:**

- Two commits pushed to `main`
- First commit: Cosign-signed, contains `cosign.pub` and initial `changelog.txt`
- Second commit: GPG-signed, contains `pgp.pub` and updated `changelog.txt`
- One attestation created and linked to the final commit SHA

---

### 4.2. Test Workflow (`.github/workflows/test.yml`)

This workflow demonstrates the bot's ability to use its established keys. It can be triggered on a schedule (`schedule`) or manually (`workflow_dispatch`).

#### 4.2.1. GPG Signing Operation

**Environment Setup:**

```bash
# Import the GPG private key from the secret
echo "${{ secrets.PGP_PRIVATE_KEY }}" | gpg --batch --import

# Get the key fingerprint
KEY_FPR=$(gpg --list-secret-keys --keyid-format LONG "github-actions[bot]" | grep -A 1 "sec" | tail -1 | tr -d ' ')

# Configure git for GPG signing
git config --global commit.gpgsign true
git config --global user.signingkey "$KEY_FPR"
git config --global gpg.program gpg
git config --global user.name "github-actions[bot]"
git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"
```

**File Operations:**

```bash
# Create timestamp file
date +%s > last_modified.txt

# Create detached GPG signature
gpg --detach-sign --armor --output last_modified.txt.pgp.asc last_modified.txt
```

**Commit:**

```bash
git add last_modified.txt last_modified.txt.pgp.asc
git commit -S -m "GPG signing test at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

#### 4.2.2. Cosign Signing Operation

**Environment Setup:**

```bash
# Load Cosign private key from secret
export COSIGN_PRIVATE_KEY="${{ secrets.COSIGN_PRIVATE_KEY }}"
export COSIGN_PASSWORD=""

# Configure git for Cosign signing (using gitsign)
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.x509.program gitsign
git config --global gpg.format x509
git config --global user.name "github-actions[bot]"
git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"
```

**File Operations:**

```bash
# Create Cosign signature of the timestamp file
cosign sign-blob --key env://COSIGN_PRIVATE_KEY \
  --output-signature last_modified.txt.cosign \
  last_modified.txt
```

**Commit:**

```bash
git add last_modified.txt.cosign
git commit -m "Cosign signing test at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

#### 4.2.3. Push

```bash
git push origin main
```

**Expected Result:**

- Two new commits pushed to `main`
- First commit: GPG-signed, contains `last_modified.txt` and `last_modified.txt.pgp.asc`
- Second commit: Cosign-signed, contains `last_modified.txt.cosign`

---

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
