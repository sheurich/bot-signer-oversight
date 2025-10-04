# `SPEC.md`

## 1. Overview

This document outlines the technical specifications for the `bot-signer` GitHub Actions workflows. The project establishes and maintains a cryptographically verifiable identity for a bot account using GnuPG and Cosign. All operations are designed to be highly auditable through signed git commits, logs, and native GitHub attestations.

---

## 2. Workflows

### 2.1. Initialization Workflow (`.github/workflows/init.yml`)

This workflow establishes the root of trust. It is triggered manually via `workflow_dispatch`.

**Prerequisites:**

- An empty repository.
- Two empty repository secrets must be created manually before the first run: `GITHUB_ACTIONS_BOT_COSIGN` and `GITHUB_ACTIONS_BOT_PGP`.

**Steps:**

1.  **Cosign Root of Trust Ceremony**

    - Generate a new Cosign key pair. The private key is loaded into an environment variable from the `GITHUB_ACTIONS_BOT_COSIGN` secret.
      ```bash
      # COSIGN_PASSWORD is set to an empty string
      cosign generate-key-pair
      ```
    - Use the GitHub API to populate the `GITHUB_ACTIONS_BOT_COSIGN` secret with the newly generated private key.
    - Write the public key to `/cosign.pub`.
    - Append a log of the ceremony to `/changelog.txt`.
    - Commit `/cosign.pub` and `/changelog.txt`. The commit itself is signed using the new Cosign key. This is the **initial commit**.

2.  **GnuPG Root of Trust Ceremony**

    - Generate a new, non-interactive Curve 25519 GnuPG key pair for the `github-actions[bot]` identity.
    - Export the ASCII-armored private key and use the GitHub API to populate the `GITHUB_ACTIONS_BOT_PGP` secret.
    - Write the ASCII-armored public key to `/pgp.pub`.
    - Append a log of this ceremony to `/changelog.txt`.
    - Commit `/pgp.pub` and the updated `/changelog.txt`. The commit is signed using the new GPG key.

3.  **Attestation**

    - Use GitHub's native OIDC-based attestation feature (`actions/attest`) to generate and persist a signed attestation. The subject of the attestation will be the SHA of the git commit containing the full ceremony logs, linking the cryptographic keys to the specific, auditable workflow run that created them.

4.  **Push**

    - Push the two generated commits to the `main` branch.

---

### 2.2. Test Workflow (`.github/workflows/test.yml`)

This workflow regularly demonstrates the bot's ability to use its established keys. It can be triggered on a schedule (`schedule`) or manually (`workflow_dispatch`).

**Steps:**

1.  **GPG Signing Operation**

    - Configure `git` to use the GPG key from the `GITHUB_ACTIONS_BOT_PGP` secret for commit signing.
    - Overwrite `/last_modified.txt` with the current Unix epoch timestamp.
      ```bash
      date +%s > last_modified.txt
      ```
    - Create a detached, ASCII-armored GPG signature of the timestamp file.
      ```bash
      # Creates /last_modified.txt.pgp.asc
      gpg --detach-sign --armor last_modified.txt
      ```
    - Commit `/last_modified.txt` and `/last_modified.txt.pgp.asc` with a GPG-signed commit.

2.  **Cosign Signing Operation**

    - Configure `git` to use the Cosign key from the `GITHUB_ACTIONS_BOT_COSIGN` secret for commit signing.
    - Create a Cosign signature of the timestamp file.
      ```bash
      # Private key is loaded into COSIGN_PRIVATE_KEY env var
      cosign sign-blob --output-signature last_modified.txt.cosign last_modified.txt
      ```
    - Commit `/last_modified.txt.cosign` with a Cosign-signed commit.

3.  **Push**

    - Push the two new commits to the `main` branch.
