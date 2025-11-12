# Changelog

## Current Status

**Released:** Keyless OIDC signing. Eliminated ADMIN_TOKEN vulnerability (CVSS 9.3).

**Next:** Test in GitHub Actions, add In-toto/SLSA attestations.

## Keyless OIDC Signing (2025-11-12)

Keyless OIDC signing replaces static key storage:

- **ADMIN_TOKEN eliminated** - No more CVSS 9.3 vulnerability
- **Keyless OIDC signing** - Identity from GitHub Actions OIDC tokens
- **Ephemeral keys** - GPG keys with 10-minute expiration, no persistent storage
- **Sigstore integration** - Fulcio certificates and Rekor transparency log
- **Automated verification** - Workflow runs every 6 hours
- **Ceremony logs** - Complete audit trail with verification commands
- **Plugin architecture** - Extensible backend system for multiple formats

### Breaking Changes

- Removed static key generation from initialization workflow
- Removed `ADMIN_TOKEN` secret requirement
- Removed `COSIGN_PRIVATE_KEY` and `PGP_PRIVATE_KEY` secrets
- Workflows now require `id-token: write` permission for OIDC

### Migration Path

Existing users should:

1. Remove static secrets from GitHub repository
2. Update workflows to use `id-token: write` permission
3. Switch to keyless signing workflows
4. Verify signatures using Rekor transparency log

See [docs/security.md](docs/security.md#migration-from-static-keys) for detailed migration instructions.

## Future Work

### Next: Additional Formats

- Test keyless signing in GitHub Actions
- Adding In-toto/SLSA attestation backend
- Adding GitHub native attestation backend
- Implementing policy engine for artifact-specific rules
- Create configuration file support

### Planned: HSM Integration

- Creating HSM integration for production mode
- Integrate with cloud KMS (AWS, GCP, Azure)
- Add key rotation automation
- Implement approval workflows
- Support hardware HSMs
- Writing tests for backends and orchestrator
