# Phase 1 Implementation Complete

Phase 1 of the keyless OIDC signing architecture has been implemented.

## What Was Built

### Core Components

1. **Python Package Structure**
   - `signer/__init__.py` - Package initialization
   - `signer/backends/__init__.py` - Backend plugins module
   - `setup.py` - Package installation configuration

2. **Plugin Architecture**
   - `signer/backends/base.py` - Abstract base class for signing backends
   - `signer/backends/sigstore.py` - Cosign keyless signing via Fulcio/Rekor
   - `signer/backends/gpg_keyless.py` - GPG with ephemeral keys bound to OIDC

3. **Core Infrastructure**
   - `signer/identity.py` - OIDC and static key identity models
   - `signer/ceremony.py` - Unified ceremony log generation
   - `signer/orchestrator.py` - Coordinates signing across multiple backends

4. **CLI Tool**
   - `signer/cli.py` - Command-line interface
   - Commands: `sign`, `verify`, `info`

5. **GitHub Workflows**
   - `.github/workflows/sign-keyless.yml` - Keyless OIDC signing workflow
   - `.github/workflows/verify.yml` - Automated signature verification

6. **Dependencies**
   - `requirements.txt` - Python package dependencies

## How It Works

### Keyless Signing Flow

1. **OIDC Token Acquisition**
   - GitHub Actions provides OIDC token via environment variables
   - Token contains workflow identity claims (repo, ref, SHA, etc.)
   - No secrets or persistent keys needed

2. **Signing Backends**
   - **Cosign**: Uses OIDC token to request ephemeral certificate from Fulcio
   - **GPG**: Generates ephemeral Ed25519 key with 10-minute expiration
   - Both backends sign artifact in parallel

3. **Ceremony Log**
   - Records all signatures with metadata
   - Includes identity claims, artifact hashes, verification commands
   - Saved as `artifact.ceremony.json`

4. **Verification Script**
   - Auto-generated shell script
   - Verifies all signatures sequentially
   - Saved as `artifact.verify.sh`

5. **Commit Signing**
   - Uses gitsign to sign commits with x509 certificates
   - Certificate logged to Rekor transparency log
   - No persistent keys stored

## Usage

### Install Package

```bash
pip install -e .
pip install -r requirements.txt
```

### Sign an Artifact (Local)

```bash
# Requires GitHub Actions OIDC token
signer sign artifact.txt --backends all
```

### Sign via GitHub Actions

```bash
# Trigger keyless signing workflow
gh workflow run sign-keyless.yml

# Or wait for weekly automatic run (Sunday 00:00 UTC)
```

### Verify Signatures

```bash
# Using CLI
signer verify artifact.txt

# Using generated script
./artifact.verify.sh
```

### Display Ceremony Info

```bash
signer info artifact.txt
```

## Testing the Implementation

Since OIDC tokens are only available in GitHub Actions, test by running the workflow:

1. **Trigger Signing Workflow**
   ```bash
   gh workflow run sign-keyless.yml
   ```

2. **Check Workflow Status**
   ```bash
   gh run list --workflow=sign-keyless.yml
   ```

3. **View Results**
   - Workflow creates `test-artifact.txt`
   - Signs with GPG (ephemeral) and Cosign (keyless)
   - Commits signatures with gitsign
   - Generates ceremony log and verification script

4. **Verify Automatically**
   - Verification workflow runs on push
   - Also runs every 6 hours
   - Can trigger manually: `gh workflow run verify.yml`

## Files Created

### Package Structure
```
signer/
├── __init__.py
├── backends/
│   ├── __init__.py
│   ├── base.py
│   ├── gpg_keyless.py
│   └── sigstore.py
├── ceremony.py
├── cli.py
├── identity.py
└── orchestrator.py
```

### Configuration
```
setup.py
requirements.txt
```

### Workflows
```
.github/workflows/
├── sign-keyless.yml
└── verify.yml
```

## Key Differences from Old Implementation

| Aspect | Old (Static Keys) | New (Keyless OIDC) |
|--------|------------------|-------------------|
| Key Storage | GitHub Secrets (ADMIN_TOKEN) | No persistent keys |
| ADMIN_TOKEN | Required (CVSS 9.3 vulnerability) | Eliminated |
| Identity | Static keypairs | GitHub Actions OIDC token |
| GPG Keys | Persistent, stored in secrets | Ephemeral, 10-minute lifetime |
| Cosign Keys | Static ECDSA key | Fulcio-issued certificates |
| Commit Signing | GPG with static key | Gitsign with x509 certificates |
| Verification | Requires key import | Rekor transparency log |
| Security | Single point of compromise | Distributed trust (OIDC + Rekor) |

## Security Improvements

1. **No Secret Storage**
   - ADMIN_TOKEN removed (eliminates CVSS 9.3 vulnerability)
   - No private keys in GitHub Secrets
   - Keys generated on-demand, expire after 10 minutes

2. **OIDC-Based Identity**
   - Identity from GitHub's OIDC provider
   - Token contains workflow context (repo, ref, SHA)
   - Trust anchored in GitHub platform, not static keys

3. **Transparency Logging**
   - All signatures logged to Rekor
   - Public, immutable, append-only log
   - Long-term verification even after certificates expire

4. **Ceremony Logs**
   - Complete audit trail for each signing operation
   - Links signatures to workflow run
   - Includes identity claims and verification commands

## Next Steps

### Immediate Actions

1. **Test the Implementation**
   ```bash
   gh workflow run sign-keyless.yml
   ```

2. **Review Generated Files**
   - Check `test-artifact.txt.ceremony.json`
   - Run `test-artifact.txt.verify.sh`
   - Verify commit with `git log --show-signature`

3. **Update Documentation**
   - README.md should point to new workflows
   - Remove references to init.yml (deprecated)
   - Update verification instructions

### Phase 2 (Future)

- Add In-toto/SLSA attestations backend
- Add GitHub native attestations backend
- Implement policy engine (artifact-specific signing rules)
- Create configuration file support (`.signing/config.yaml`)

### Phase 3 (Future)

- HSM integration (AWS KMS, GCP KMS)
- Production mode with hardware-backed keys
- Key rotation automation
- Multi-signature support

## Troubleshooting

### "Not running in GitHub Actions"

The signer tool requires GitHub Actions OIDC tokens. Run workflows instead of local commands.

### "cosign: command not found"

Install Cosign:
```bash
# macOS
brew install cosign

# Linux
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo install cosign-linux-amd64 /usr/local/bin/cosign
```

### "gpg: key generation failed"

Ensure GnuPG is installed:
```bash
# macOS
brew install gnupg

# Linux
sudo apt-get install gnupg
```

### Verification Fails

1. Check ceremony log exists: `ls *.ceremony.json`
2. Verify artifact unchanged: `sha256sum artifact`
3. Check Rekor entry: `rekor-cli search --artifact artifact`
4. Review ceremony log: `jq . artifact.ceremony.json`

## References

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Fulcio Certificate Authority](https://github.com/sigstore/fulcio)
- [Rekor Transparency Log](https://github.com/sigstore/rekor)
- [Gitsign Commit Signing](https://github.com/sigstore/gitsign)
