# bot-signer-oversight

Establishes cryptographic identity for GitHub Actions bots through auditable key ceremonies and signed operations.

## Implementation

The keyless signing system includes:

### How It Works

1. GitHub Actions provides OIDC token with workflow identity
2. Signing backends (Cosign, GPG) generate ephemeral keys
3. Signatures logged to Rekor transparency log
4. Ceremony log records metadata and verification commands

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

### Run Keyless Signing

```bash
# Trigger signing workflow
gh workflow run sign-keyless.yml

# Check workflow status
gh run list --workflow=sign-keyless.yml

# Or wait for weekly automatic run (Sunday 00:00 UTC)
```

### Verify Signatures

```bash
# Automatic verification (runs every 6 hours)
gh workflow run verify.yml

# Or use generated verification script
./test-artifact.txt.verify.sh
```

### Local Development

```bash
# Install package
uv pip install -e .
uv pip install -r requirements.txt

# Sign artifact (requires GitHub Actions OIDC token)
signer sign artifact.txt --backends all

# Verify signatures
signer verify artifact.txt

# Display ceremony info
signer info artifact.txt
```

### Verifying Old Signatures (Static Keys)

```bash
# Import GPG public key first
gpg --import pgp.pub

# Verify GPG signatures
gpg --verify last_modified.txt.pgp.asc last_modified.txt

# Verify Cosign blob signature
cosign verify-blob --key cosign.pub \
  --signature last_modified.txt.cosign \
  last_modified.txt
```

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

- [`CHANGELOG.md`](CHANGELOG.md) - Version history and changes
- [`docs/architecture.md`](docs/architecture.md) - Technical design and plugin system
- [`docs/security.md`](docs/security.md) - Threat model and vulnerability assessment
- [`docs/reference.md`](docs/reference.md) - Configuration, formats, and procedures
- [`docs/examples.md`](docs/examples.md) - Workflows and usage examples

## Repository Structure

```
signer/                    # Python package
  backends/                # Signing backend plugins
    base.py                # Abstract base class
    gpg_keyless.py         # GPG with ephemeral keys
    sigstore.py            # Cosign/Fulcio/Rekor
  ceremony.py              # Ceremony log generation
  cli.py                   # Command-line interface
  identity.py              # OIDC and static key identities
  orchestrator.py          # Signing coordinator

.github/workflows/
  sign-keyless.yml         # Keyless OIDC signing workflow
  verify.yml               # Automated signature verification
  init.yml                 # Legacy initialization (deprecated)
  test.yml                 # Legacy tests (deprecated)

docs/                      # Architecture documentation
setup.py                   # Package configuration
requirements.txt           # Python dependencies
```

## Contributing

Contributions welcome. See [CHANGELOG.md](CHANGELOG.md#future-work) for planned work and roadmap.

## License

MIT

## References

- [Sigstore](https://www.sigstore.dev/) - Cosign, Gitsign, Fulcio, Rekor
- [SLSA Framework](https://slsa.dev/) - Supply chain security levels
- [GnuPG Documentation](https://gnupg.org/documentation/)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)
