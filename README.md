# bot-signer

This repository provides an easily auditable cryptographic root of trust for bot accounts, designed for creation, usage, and maintenance entirely within GitHub Actions.

## Goal 🎯

The primary goal is to establish a verifiable, self-signed identity for automation. This identity is anchored by **GnuPG** and **Cosign** key pairs generated and managed through auditable GitHub Actions workflows. Every action taken by the bot, from its own key generation ceremony to subsequent file modifications, is cryptographically signed and logged, creating a transparent and secure audit trail.

This system allows repository automation to sign commits and artifacts, providing strong guarantees about the origin and integrity of bot-managed changes. The entire lifecycle of the bot's identity is contained within the repository's git history and the associated GitHub Actions logs and attestations.
