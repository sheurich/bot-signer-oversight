# bot-signer-oversight

Easily auditable cryptographic self-signed roots of trust for creation, usage, and maintenance by bot accounts.

## Overview

This repository demonstrates a transparent and auditable approach to creating and maintaining cryptographic identities for automated systems. All key generation ceremonies are logged and committed to the repository, providing a complete audit trail.

## Workflows

### Initialization (`init.yml`)

Manually run workflow that establishes the cryptographic roots of trust:

1. **Cosign Setup**: Generates cosign key pair, stores private key in `GITHUB_ACTIONS_BOT_COSIGN` secret, commits public key to `key.cosign`
2. **GnuPG Setup**: Generates Curve25519 key pair, stores private key in `GITHUB_ACTIONS_BOT_PGP` secret, commits public key to `key.pub.pgp.asc`
3. **Attestations**: Creates GitHub attestations for all ceremony logs and public keys

All ceremonies are logged to `changelog.txt` with timestamps and fingerprints.

### Test (`test.yml`)

Demonstrates signing capabilities:

1. Updates `last_modified.txt` with current Unix epoch timestamp
2. Creates PGP detached signature (`last_modified.txt.pgp.asc`) and commits with PGP signing
3. Creates cosign signature (`last_modified.txt.cosign`) and commits with cosign signing
4. Pushes all commits

## Usage

1. Run the **Initialize Bot Signer** workflow manually from the Actions tab
2. Verify the ceremony logs in `changelog.txt` and public keys are committed
3. The **Test Bot Signer** workflow runs automatically on pushes to main or can be triggered manually

## Security

- Private keys are stored as GitHub Actions secrets and never committed
- Public keys and ceremony logs are committed for transparency
- All operations are logged with timestamps
- GitHub attestations provide additional integrity verification