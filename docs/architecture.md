# Architecture

This document specifies the technical design for multi-format cryptographic signing in GitHub Actions.

## Design Goals

1. Sign artifacts once, verify in multiple ecosystems
2. Eliminate persistent secret storage for development
3. Provide clear upgrade path to HSM for production
4. Support six signing formats from single operation
5. Generate automatic verification for all signatures

## System Overview

```
┌─────────────────────────────────────────────────┐
│          Signing Orchestrator                   │
│     (coordinates all operations)                │
└──────────────┬──────────────────────────────────┘
               │
     ┌─────────┼─────────┬──────────┐
     │         │         │          │
┌────▼───┐ ┌──▼───┐ ┌───▼────┐ ┌───▼──────┐
│  GPG   │ │Sigstore│ │In-toto│ │ GitHub  │
│Plugin  │ │Plugin  │ │Plugin  │ │Plugin   │
└────┬───┘ └──┬───┘ └───┬────┘ └───┬──────┘
     │         │         │          │
┌────▼────────┴─────────┴──────────▼─────┐
│          Key Backend Layer              │
│   OIDC (dev) | Static | HSM (prod)      │
└────────────────────────────────────────────┘
```

## Core Components

### Signing Orchestrator

Coordinates signing operations across formats.

**Responsibilities:**
- Authenticate identity (OIDC token, static key, or HSM)
- Call each enabled plugin in parallel
- Collect all signatures
- Generate unified ceremony log
- Create verification manifest

**Interface:**
```python
def sign_artifact(
    artifact: bytes,
    identity: Identity,
    backends: List[str]
) -> SigningManifest:
    """Sign artifact with configured backends."""
```

### Plugin System

Each plugin implements the `SigningBackend` interface:

```python
class SigningBackend(ABC):
    def sign(artifact: bytes, identity: Identity) -> Signature
    def verify(artifact: bytes, signature: Signature) -> bool
    def supports_keyless() -> bool
    def get_format() -> str
```

**Available Plugins:**
- `gpg` - GPG/PGP signatures with ephemeral or static keys
- `sigstore` - Cosign and Gitsign (keyless OIDC)
- `intoto` - In-toto attestations with SLSA predicates
- `github` - Native GitHub attestations

## Identity Models

### Development Mode: OIDC

Uses GitHub Actions OIDC token as identity source.

**Token Claims:**
```json
{
  "iss": "https://token.actions.githubusercontent.com",
  "sub": "repo:owner/repo:ref:refs/heads/main",
  "aud": "sigstore",
  "repository": "owner/repo",
  "workflow": ".github/workflows/sign.yml",
  "ref": "refs/heads/main",
  "sha": "abc123..."
}
```

**Key Properties:**
- No persistent keys stored
- 10-minute certificate lifetime
- Sigstore Fulcio issues x509 certificates
- Rekor transparency log stores all signatures

**GPG with OIDC:**

Generate ephemeral GPG keys bound to OIDC identity:

```python
def create_ephemeral_gpg_key(identity: OIDCIdentity) -> GPGKey:
    """Generate Ed25519 key from OIDC claims."""
    key = gpg.generate_key(
        name=identity.subject,
        email=f"{identity.subject_hash}@oidc.sigstore.dev",
        key_type="Ed25519",
        expire_time="10m"
    )
    log_to_rekor(key.public_key, identity)
    return key
```

### Production Mode: HSM

Keys never leave hardware security module.

**Supported Providers:**
- AWS KMS (FIPS 140-2 Level 3)
- GCP Cloud KMS (FIPS 140-2 Level 3)
- Azure Key Vault (FIPS 140-2 Level 2)
- PKCS#11 hardware HSMs (FIPS 140-2 Level 4)

**Signing Flow:**
1. Compute digest locally
2. Send digest to HSM via API
3. HSM signs digest with private key
4. Return signature bytes
5. Private key never exported

**Example (AWS KMS):**
```python
response = kms_client.sign(
    KeyId='arn:aws:kms:us-east-1:123456:key/abc-123',
    Message=sha256(artifact),
    SigningAlgorithm='ECDSA_SHA_256'
)
signature = response['Signature']
```

## Multi-Format Strategy

**Question:** Sign once or sign multiple times?

**Answer:** Sign multiple times.

**Rationale:**
- Formats are incompatible (PGP → Cosign conversion loses information)
- Each ecosystem expects specific format
- Signing is fast (100-200ms per format)
- Users verify with tools they already have

### Format Matrix

| Artifact Type | Primary Format | Additional Formats | Reason |
|---------------|----------------|-------------------|---------|
| Git commits | Gitsign (x509) | GPG | Transparency log + traditional tools |
| Release binaries | Cosign | GPG, In-toto | Supply chain + SLSA compliance |
| Container images | Cosign | - | Native OCI support |
| SBOM files | In-toto | GitHub | Provenance tracking |
| Source archives | GPG | Cosign | Traditional distribution |

### Signature Files

Each artifact generates these files:

```bash
artifact.txt              # Original file
artifact.txt.gpg         # GPG detached signature
artifact.txt.gpg.pub     # GPG public key (keyless mode)
artifact.txt.cosign      # Cosign signature
artifact.txt.cosign.cert # Fulcio certificate
artifact.txt.bundle      # Sigstore bundle (sig + cert + rekor)
artifact.txt.intoto      # In-toto attestation (DSSE envelope)
artifact.txt.ceremony.json  # Unified ceremony log
artifact.txt.verify.sh   # Auto-generated verification script
```

## Ceremony Log Format

Unified log ties all signatures together:

```json
{
  "ceremony_type": "artifact_signing",
  "timestamp": "2025-11-12T14:30:00Z",
  "identity": {
    "type": "oidc",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:owner/repo:ref:refs/heads/main",
    "claims": {
      "repository": "owner/repo",
      "workflow": ".github/workflows/sign.yml",
      "sha": "abc123...",
      "run_id": "123456789"
    }
  },
  "artifact": {
    "path": "artifact.txt",
    "sha256": "def456...",
    "size": 1234
  },
  "signatures": [
    {
      "format": "gpg",
      "file": "artifact.txt.gpg",
      "key_id": "ephemeral:789abc...",
      "public_key_file": "artifact.txt.gpg.pub",
      "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/...",
      "verification_command": "gpg --import artifact.txt.gpg.pub && gpg --verify artifact.txt.gpg artifact.txt"
    },
    {
      "format": "cosign",
      "file": "artifact.txt.cosign",
      "certificate_file": "artifact.txt.cosign.cert",
      "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/...",
      "bundle_file": "artifact.txt.bundle",
      "verification_command": "cosign verify-blob --bundle artifact.txt.bundle artifact.txt"
    },
    {
      "format": "intoto",
      "file": "artifact.txt.intoto",
      "predicate_type": "https://slsa.dev/provenance/v1",
      "envelope_type": "application/vnd.in-toto+json",
      "verification_command": "in-toto-verify --attestation artifact.txt.intoto"
    }
  ],
  "workflow_run": "https://github.com/owner/repo/actions/runs/123456789"
}
```

## Trust Model Comparison

| Feature | PGP/WoT | PKI/x509 | Sigstore/OIDC | HSM |
|---------|---------|----------|---------------|-----|
| Root of Trust | Key signatures | CA hierarchy | OIDC + Rekor | Hardware + CA |
| Key Lifetime | Years | Days-years | Minutes | Years |
| Revocation | Revocation certs | CRL/OCSP | Rekor entry | CRL/OCSP |
| Verification | Local keyring | CA bundle | Rekor + OIDC | CA bundle |
| Network Required | No | Optional | Yes | Optional |
| Tool Support | Wide (GPG) | Wide (OpenSSL) | Growing | Specialized |

### OIDC → Traditional Systems

Map ephemeral OIDC identity to static key-based systems:

**Identity Certificate Approach:**

1. Generate ephemeral keypair (Ed25519 or ECDSA P-256)
2. Create self-signed x509 certificate
3. Embed OIDC claims in certificate extensions (SAN, custom OIDs)
4. Certificate lifetime matches OIDC token (10 minutes)
5. Export public key with signature
6. Log certificate to Rekor for long-term verification

## Configuration Schema

### Global Configuration

```yaml
# .signing/config.yaml
version: "1.0"
mode: development  # or production

identity:
  oidc:
    issuer: https://token.actions.githubusercontent.com
    audience: sigstore
    subject_pattern: "repo:owner/repo:*"

  hsm:  # production mode only
    provider: aws-kms
    region: us-east-1
    key_id: arn:aws:kms:us-east-1:123456:key/abc-123
    role_arn: arn:aws:iam::123456:role/SignerRole

backends:
  gpg:
    enabled: true
    keyless_mode: true  # ephemeral keys from OIDC
    key_type: Ed25519

  sigstore:
    enabled: true
    keyless_mode: true
    fulcio_url: https://fulcio.sigstore.dev
    rekor_url: https://rekor.sigstore.dev

  intoto:
    enabled: true
    predicate_types:
      - https://slsa.dev/provenance/v1

  github:
    enabled: true
    attestation_api: true

policies:
  - name: commits
    artifacts: ["**/*.git/objects/**"]
    required_backends: [gitsign, gpg]

  - name: releases
    artifacts: ["dist/**/*.tar.gz", "dist/**/*.whl"]
    required_backends: [cosign, gpg, intoto, github]
    ceremony_log: true
```

## Verification Strategy

### Unified Verification Script

Auto-generate shell script for each artifact:

```bash
#!/bin/bash
set -euo pipefail

ARTIFACT="artifact.txt"
FAILED=0

echo "Verifying signatures for $ARTIFACT"
echo "======================================"

# GPG verification
echo "Checking GPG signature..."
if gpg --import artifact.txt.gpg.pub && \
   gpg --verify artifact.txt.gpg artifact.txt; then
    echo "GPG signature valid"
else
    echo "GPG signature FAILED"
    FAILED=1
fi

# Cosign verification
echo "Checking Cosign signature..."
if cosign verify-blob --bundle artifact.txt.bundle artifact.txt; then
    echo "Cosign signature valid"
else
    echo "Cosign signature FAILED"
    FAILED=1
fi

# In-toto verification
echo "Checking In-toto attestation..."
if in-toto-verify --attestation artifact.txt.intoto; then
    echo "In-toto attestation valid"
else
    echo "In-toto attestation FAILED"
    FAILED=1
fi

# GitHub attestation verification
echo "Checking GitHub attestation..."
FILE_OID="oid:gitoid:blob:sha256:$(sha256sum artifact.txt | cut -d' ' -f1)"
if gh attestation verify "$FILE_OID" --repo owner/repo; then
    echo "GitHub attestation valid"
else
    echo "GitHub attestation FAILED"
    FAILED=1
fi

if [ $FAILED -eq 0 ]; then
    echo "======================================"
    echo "All signatures verified"
    exit 0
else
    echo "======================================"
    echo "One or more signatures failed"
    exit 1
fi
```

### Source of Truth

When formats disagree, priority order:

1. **Rekor entry** - Immutable, timestamped, public
2. **GitHub attestation** - Tied to workflow run
3. **Ceremony log** - Contains all metadata
4. **Individual signatures** - May expire (gitsign)

## Implementation Phases

### Phase 1: Core Infrastructure

**Deliverables:**
- Signing CLI tool (`signer`)
- Plugin interface definition
- Configuration system
- Ceremony log generator

**Files:**
```
signer/
  __init__.py
  cli.py
  orchestrator.py
  identity.py
  ceremony.py
  backends/
    __init__.py
    base.py
```

### Phase 2: Keyless Backends

**Deliverables:**
- GPG keyless plugin (ephemeral keys)
- Sigstore plugin (native OIDC)
- In-toto plugin (SLSA provenance)
- GitHub plugin (native attestations)

**Files:**
```
signer/backends/
  gpg_keyless.py
  sigstore.py
  intoto.py
  github.py
```

### Phase 3: Development Workflows

**Deliverables:**
- Development mode initialization
- Multi-format signing workflow
- Automated verification workflow

**Files:**
```
.github/workflows/
  init-development.yml
  sign.yml
  verify.yml
```

### Phase 4: Verification Tooling

**Deliverables:**
- Verification script generator
- Verification GitHub Action
- Format-specific verification procedures

### Phase 5: Production HSM Support

**Deliverables:**
- HSM plugin interface
- AWS KMS integration
- GCP KMS integration
- Key rotation automation

**Files:**
```
signer/backends/
  hsm.py
  aws_kms.py
  gcp_kms.py
```

## Migration Path

### Current → Development Mode

1. Remove static key generation from init workflow
2. Remove `COSIGN_PRIVATE_KEY` and `PGP_PRIVATE_KEY` secrets
3. Remove `ADMIN_TOKEN` (no longer needed)
4. Implement OIDC token acquisition
5. Add keyless signing for all formats
6. Generate ceremony logs
7. Create verification scripts

### Development → Production Mode

1. Provision HSM (AWS KMS, GCP KMS, or hardware)
2. Generate keys in HSM (never exported)
3. Update configuration to use HSM backend
4. Maintain same workflows (different backend only)
5. Implement key rotation ceremony
6. Add approval gates for production signing

## Security Considerations

### Development Mode

**Trust Boundary:** GitHub's OIDC token issuance

**Attack Vectors:**
- Workflow injection (mitigated by branch protection)
- GitHub platform compromise (inherent risk)
- Rekor unavailability (signatures still valid, verification requires Rekor)

**Not Protected Against:**
- Malicious workflow modifications by authorized users
- GitHub infrastructure compromise

### Production Mode

**Trust Boundary:** HSM hardware + IAM policies

**Attack Vectors:**
- KMS API credential theft (mitigated by OIDC short-lived tokens)
- IAM policy misconfiguration (mitigated by least privilege)
- HSM compromise (requires physical access for Level 4)

**Not Protected Against:**
- Authorized users with HSM access
- Cloud provider compromise

## Performance

### Signing Performance

Per-format signing times (on GitHub-hosted runner):

- GPG: 50-100ms (key generation) + 10ms (signing)
- Cosign: 200-300ms (Fulcio certificate) + 10ms (signing)
- In-toto: 50-100ms (predicate generation) + 10ms (signing)
- GitHub: 100-200ms (attestation API call)

**Total:** 400-700ms for all four formats in parallel

### Verification Performance

- GPG: 10-50ms (local)
- Cosign: 200-500ms (Rekor API call)
- In-toto: 10-50ms (local)
- GitHub: 200-500ms (attestation API call)

## Future Enhancements

### Additional Formats

- Docker Content Trust (Notary v2)
- GCP Binary Authorization
- APT repository signing
- RPM package signing
- macOS code signing
- Windows Authenticode

### Advanced Features

- Multi-signature threshold (N-of-M signing)
- Offline signing support
- Air-gapped key ceremony
- Hardware security key support (YubiKey, etc.)
- Policy engine for required signatures
- Automated key rotation schedules

## References

- [Sigstore Architecture](https://docs.sigstore.dev/cosign/overview/) - Cosign, Fulcio, Rekor
- [In-toto Specification](https://github.com/in-toto/docs) - Attestation framework
- [SLSA Framework](https://slsa.dev/spec/v1.0/) - Supply chain levels
- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html) - OpenID Connect
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) - GitHub's OIDC implementation
