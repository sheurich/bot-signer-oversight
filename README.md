# bot-signer-oversight

Establishes cryptographic identity for GitHub Actions bots through auditable key ceremonies and signed operations.

## Project Status

**Current state:** Working but flawed. Critical security issues require fixes before use.

**Planned state:** Multi-format keyless signing using OIDC, with clear upgrade path to HSM-backed production mode.

## Critical Issues

Three critical vulnerabilities exist in the current implementation:

1. **ADMIN_TOKEN vulnerability** - Anyone with this Personal Access Token can replace signing keys silently (CVSS 9.3)
2. **Gitsign/Cosign confusion** - Static Cosign keys generated but never used for commits; gitsign uses ephemeral certificates that expire
3. **No verification automation** - Signatures exist but cannot be verified without manual key imports

## What Works

- GPG key generation (Ed25519)
- Cosign key generation (ECDSA P-256)
- Weekly automated tests
- Ceremony logging
- GitHub attestations

## What Fails

| Issue | Impact | Fix Required |
|-------|--------|-------------|
| ADMIN_TOKEN security | Total compromise possible | Remove secret storage, use OIDC |
| GPG signatures unverifiable | "No public key" error | Add `gpg --import` step to docs |
| Gitsign certificates expire | Local verification fails after 10 minutes | Document Rekor verification or use GPG only |
| Cosign static key unused | Wasted complexity | Remove or use for blob signing only |
| Ceremony log unsigned | Could be tampered | Sign log with both formats |

## Proposed Architecture

The project will shift to keyless OIDC-based signing for development, eliminating secret storage entirely.

### Development Mode (OIDC)
- No persistent keys
- GitHub Actions OIDC token provides identity
- Fulcio issues ephemeral certificates (10-minute lifetime)
- Rekor transparency log stores all signatures
- Multiple signature formats from single operation

### Production Mode (Future)
- HSM-backed keys (AWS KMS, GCP KMS, or hardware HSM)
- Keys never leave hardware
- FIPS 140-2 Level 3 compliance
- Same tooling as development mode

### Supported Formats
- GPG/PGP (traditional, wide tool support)
- Sigstore (Cosign, Gitsign, Rekor)
- In-toto attestations (SLSA provenance)
- GitHub native attestations
- Docker Content Trust (future)
- GCP Binary Authorization (future)

## Quick Start

### Current Implementation (Static Keys)

```bash
# One-time initialization
gh workflow run init.yml

# Weekly tests run automatically
# Signatures created but verification requires manual setup
```

### Verifying Existing Signatures

```bash
# Import GPG public key first (required)
gpg --import pgp.pub

# Verify GPG signatures
git log --show-signature
gpg --verify last_modified.txt.pgp.asc last_modified.txt

# Verify Cosign blob signature
cosign verify-blob --key cosign.pub \
  --signature last_modified.txt.cosign \
  last_modified.txt

# Gitsign commit verification (requires network)
gitsign verify --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  <commit-sha>
```

## Implementation Roadmap

### Phase 1: Fix Critical Issues
- Remove ADMIN_TOKEN dependency
- Implement keyless OIDC signing
- Add automated verification
- Update documentation

### Phase 2: Multi-Format Support
- Build plugin architecture
- Sign artifacts in multiple formats simultaneously
- Generate unified ceremony logs
- Auto-generate verification scripts

### Phase 3: Production HSM Support
- Integrate with cloud KMS (AWS, GCP, Azure)
- Add key rotation automation
- Implement approval workflows
- Support hardware HSMs

## Use Cases

### Appropriate For
- Internal tooling with compliance needs
- Reference implementation for signing systems
- Learning automated key management
- Organizations already trusting GitHub platform

### Not Appropriate For
- Production release signing (use HSM)
- High-security environments (use hardware keys)
- Regulatory compliance (SOC 2, FedRAMP) without HSM
- Zero-trust architectures (single point of trust exists)

## Documentation

- [`docs/architecture.md`](docs/architecture.md) - Technical design and plugin system
- [`docs/security.md`](docs/security.md) - Threat model and vulnerability assessment
- [`docs/reference.md`](docs/reference.md) - Configuration, formats, and procedures
- [`docs/examples.md`](docs/examples.md) - Workflows and usage examples

## Repository Structure

```
.github/workflows/
  init.yml                 # Initialization (flawed, needs replacement)
  test.yml                 # Weekly signing tests
cosign.pub                 # Cosign ECDSA P-256 public key
pgp.pub                    # GPG Ed25519 public key
changelog.txt              # Ceremony audit log (not signed)
last_modified.txt          # Timestamp for testing
last_modified.txt.pgp.asc  # GPG detached signature
last_modified.txt.cosign   # Cosign blob signature
```

## Contributing

Contributions welcome, especially:

- Implementing keyless OIDC signing
- Building plugin architecture for multiple formats
- Adding automated verification workflows
- Fixing gitsign/Cosign confusion
- Creating HSM integration

## License

MIT

## References

- [Sigstore](https://www.sigstore.dev/) - Cosign, Gitsign, Fulcio, Rekor
- [SLSA Framework](https://slsa.dev/) - Supply chain security levels
- [GnuPG Documentation](https://gnupg.org/documentation/)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)
