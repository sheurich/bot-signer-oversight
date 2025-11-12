# Reference

This document specifies configuration, formats, and procedures for bot-signer-oversight.

## Configuration

### Global Configuration

File: `.signing/config.yaml`

```yaml
version: "1.0"

# Signing mode: development or production
mode: development

# Identity configuration
identity:
  # Development mode: OIDC
  oidc:
    issuer: https://token.actions.githubusercontent.com
    audience: sigstore
    subject_pattern: "repo:owner/repo:*"

  # Production mode: HSM (future)
  hsm:
    provider: aws-kms  # aws-kms | gcp-kms | azure-kv | pkcs11
    region: us-east-1
    key_id: arn:aws:kms:us-east-1:123456:key/abc-123
    role_arn: arn:aws:iam::123456:role/SignerRole

# Enabled signing backends
backends:
  gpg:
    enabled: true
    keyless_mode: true  # Generate ephemeral keys from OIDC
    key_type: Ed25519   # Ed25519 | RSA-4096
    public_key_export: true

  cosign:
    enabled: true
    keyless_mode: true  # Use Fulcio + Rekor
    fulcio_url: https://fulcio.sigstore.dev
    rekor_url: https://rekor.sigstore.dev
    oidc_provider: https://oauth2.sigstore.dev/auth

  gitsign:
    enabled: true
    fulcio_url: https://fulcio.sigstore.dev
    rekor_url: https://rekor.sigstore.dev
    commit_signing: true

  intoto:
    enabled: true
    predicate_types:
      - https://slsa.dev/provenance/v1
      - https://in-toto.io/attestation/v1
    layouts:
      - name: build-and-release
        path: .signing/layouts/build-release.layout

  github:
    enabled: true
    attestation_api: true
    predicate_types:
      - https://slsa.dev/provenance/v1

# Artifact-specific signing policies
policies:
  - name: git-commits
    artifacts:
      - "**/*.git/objects/**"
    required_backends: [gitsign, gpg]
    ceremony_log: false  # Too frequent for logging

  - name: release-artifacts
    artifacts:
      - "dist/**/*.tar.gz"
      - "dist/**/*.whl"
      - "dist/**/*.zip"
    required_backends: [cosign, gpg, intoto, github]
    ceremony_log: true
    ceremony_log_path: ".signing/ceremonies/"

  - name: container-images
    artifacts:
      - "**/*.tar"
    required_backends: [cosign]
    oci_attach: true

# Verification configuration
verification:
  auto_generate_script: true
  script_name: "verify.sh"
  fail_on_missing_backend: false  # Allow partial verification
  rekor_verification: true

# Ceremony logging
ceremony_log:
  enabled: true
  format: json
  sign_log: true  # Sign ceremony log itself
  backends: [gpg, cosign]

# Rekor integration
rekor:
  log_all_signatures: true
  public_instance: true
  custom_instance_url: null
```

### Policy Configuration

File: `.signing/policies/releases.yaml`

```yaml
name: release-artifacts
description: Sign all release artifacts with multiple formats

# Artifact patterns (glob)
artifacts:
  - "dist/**/*.tar.gz"
  - "dist/**/*.whl"
  - "dist/**/*.zip"
  - "dist/**/*.rpm"
  - "dist/**/*.deb"

# Required backends
required_backends:
  - cosign
  - gpg
  - intoto
  - github

# Optional backends
optional_backends: []

# Ceremony logging
ceremony_log:
  enabled: true
  path: ".signing/ceremonies/release-{timestamp}.json"
  sign: true

# Verification
verification:
  generate_script: true
  script_template: ".signing/templates/verify-release.sh.tmpl"
```

## Signing Formats

### GPG/PGP

**Algorithm:** Ed25519 (EdDSA)

**Key Properties:**
- Keyless mode: 10-minute ephemeral keys
- Static mode: Persistent keys in secrets
- Public key: 32 bytes
- Signature: ~64 bytes

**Signature Format:**
```
-----BEGIN PGP SIGNATURE-----

iHUEARYKAB0WIQTcHBZqZjSGHSTjK3TjgYeE1o/uqQUCY9...
-----END PGP SIGNATURE-----
```

**File Extensions:**
- `.gpg` - Detached signature
- `.gpg.pub` - Public key (keyless mode)
- `.asc` - Armored signature

**Verification:**
```bash
# Import public key
gpg --import file.gpg.pub

# Verify signature
gpg --verify file.gpg file

# Expected output
gpg: Signature made Tue 12 Nov 2025 02:30:00 PM EST
gpg:                using EDDSA key ABC123...
gpg: Good signature from "github-actions[bot] <...>"
```

### Sigstore (Cosign)

**Algorithm:** ECDSA P-256 (ES256)

**Key Properties:**
- Keyless mode: Fulcio-issued ephemeral certificates
- Static mode: Persistent ECDSA keys
- Certificate: x509 with OIDC claims in SAN
- Signature: ~70 bytes

**Bundle Format:**
```json
{
  "base64Signature": "MEUCIQD7...",
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "rekorBundle": {
    "SignedEntryTimestamp": "MEUCIQD...",
    "Payload": {
      "body": "eyJhcGl...",
      "integratedTime": 1699804800,
      "logIndex": 12345,
      "logID": "c0d23d6..."
    }
  }
}
```

**File Extensions:**
- `.cosign` - Raw signature
- `.cosign.cert` - Fulcio certificate
- `.bundle` - Sigstore bundle (signature + cert + rekor)

**Verification:**
```bash
# Verify with bundle (includes Rekor entry)
cosign verify-blob --bundle file.bundle file

# Verify with separate files
cosign verify-blob \
  --signature file.cosign \
  --certificate file.cosign.cert \
  file

# Expected output
Verified OK
```

### Gitsign (Git Commit Signing)

**Algorithm:** ECDSA P-256 via Fulcio

**Key Properties:**
- Always keyless (OIDC-based)
- 10-minute certificate lifetime
- Rekor transparency log entry
- x509 certificate with GitHub Actions claims

**Certificate SAN:**
```
URI:https://github.com/owner/repo/.github/workflows/sign.yml@refs/heads/main
```

**Verification:**
```bash
# Verify with gitsign (checks Rekor)
gitsign verify --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  <commit-sha>

# Git native (shows certificate)
git log --show-signature -1 <commit-sha>

# Expected output
tlog entry verified with uuid: "abc123..."
Issuer: CN=sigstore-intermediate,O=sigstore.dev
```

### In-toto Attestations

**Format:** DSSE (Dead Simple Signing Envelope)

**Predicate Types:**
- `https://slsa.dev/provenance/v1` - SLSA provenance
- `https://in-toto.io/attestation/v1` - Generic attestation
- `https://spdx.dev/Document` - SBOM attestation

**Envelope Structure:**
```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64-encoded-predicate>",
  "signatures": [
    {
      "keyid": "",
      "sig": "<base64-signature>"
    }
  ]
}
```

**SLSA Provenance Predicate:**
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "artifact.tar.gz",
      "digest": {"sha256": "abc123..."}
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/owner/repo",
          "path": ".github/workflows/build.yml"
        }
      },
      "internalParameters": {
        "github": {
          "event_name": "push",
          "repository_id": "123456",
          "repository_owner_id": "78910"
        }
      },
      "resolvedDependencies": []
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/Attestations/GitHubHostedActions@v1"
      },
      "metadata": {
        "invocationId": "https://github.com/owner/repo/actions/runs/123456"
      }
    }
  }
}
```

**File Extension:** `.intoto`

**Verification:**
```bash
# Verify with in-toto
in-toto-verify --attestation file.intoto

# Verify SLSA provenance
slsa-verifier verify-artifact \
  --provenance-path file.intoto \
  --source-uri github.com/owner/repo \
  file
```

### GitHub Attestations

**Storage:** GitHub Attestation API

**Predicate Types:**
- SLSA provenance
- SBOM (CycloneDX, SPDX)
- Custom predicates

**Attestation Structure:**
```json
{
  "bundle": {
    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
    "verificationMaterial": {...},
    "dsseEnvelope": {...}
  },
  "attestation": {
    "type": "https://slsa.dev/provenance/v1",
    "predicateType": "https://slsa.dev/provenance/v1",
    "subject": [{
      "name": "file",
      "digest": {"gitoid:blob:sha256": "abc123..."}
    }]
  }
}
```

**Verification:**
```bash
# Generate artifact digest
FILE_OID="oid:gitoid:blob:sha256:$(git hash-object file)"

# Verify attestation
gh attestation verify "$FILE_OID" --repo owner/repo

# Expected output
Loaded digest sha256:abc123... for file://file
Loaded 1 attestation from GitHub API
✓ Verification succeeded!
```

## Keyless Signing (OIDC)

### OIDC Token Acquisition

**GitHub Actions provides OIDC tokens via environment:**

```yaml
permissions:
  id-token: write  # Required

steps:
  - name: Get OIDC Token
    run: |
      OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -r .value)
      echo "token=$OIDC_TOKEN" >> $GITHUB_OUTPUT
```

### Fulcio Certificate Request

**Fulcio issues short-lived x509 certificates based on OIDC token:**

```python
import requests

def get_fulcio_certificate(oidc_token: str, public_key: bytes) -> str:
    """Request certificate from Fulcio."""
    response = requests.post(
        "https://fulcio.sigstore.dev/api/v2/signingCert",
        json={
            "credentials": {
                "oidcIdentityToken": oidc_token
            },
            "publicKeyRequest": {
                "publicKey": {
                    "algorithm": "ECDSA",
                    "content": base64.b64encode(public_key).decode()
                },
                "proofOfPossession": create_proof(public_key)
            }
        }
    )
    return response.json()["signedCertificateDetachedSct"]["cert"]
```

**Certificate contains OIDC claims in SAN:**

```
X509v3 Subject Alternative Name:
    URI:https://github.com/owner/repo/.github/workflows/sign.yml@refs/heads/main
X509v3 extensions:
    1.3.6.1.4.1.57264.1.1: github.com/owner/repo
    1.3.6.1.4.1.57264.1.2: refs/heads/main
    1.3.6.1.4.1.57264.1.3: abc123... (commit SHA)
```

### Rekor Transparency Log

**All keyless signatures logged to Rekor:**

```bash
# Log entry manually
SIGNATURE_BASE64=$(base64 -w0 < signature)
PAYLOAD=$(cat <<EOF
{
  "apiVersion": "0.0.1",
  "kind": "hashedrekord",
  "spec": {
    "signature": {
      "content": "$SIGNATURE_BASE64",
      "publicKey": {
        "content": "$CERT_BASE64"
      }
    },
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "$ARTIFACT_SHA256"
      }
    }
  }
}
EOF
)

curl -X POST https://rekor.sigstore.dev/api/v1/log/entries \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
```

**Rekor entry includes:**
- Signature
- Certificate
- Artifact hash
- Timestamp (from transparency log)
- Inclusion proof

**Verification queries Rekor:**

```bash
# Verify signature exists in Rekor
REKOR_UUID=$(rekor-cli search --artifact file | head -1)
rekor-cli verify --uuid $REKOR_UUID --artifact file
```

### Ephemeral Key Generation

**For GPG compatibility with keyless:**

```python
def generate_ephemeral_gpg_key(oidc_identity: OIDCIdentity) -> GPGKey:
    """Generate Ed25519 key bound to OIDC identity."""
    # Hash OIDC subject for consistent email
    subject_hash = hashlib.sha256(oidc_identity.subject.encode()).hexdigest()[:16]

    # Generate key with 10-minute expiration
    key = gpg.generate_key(gpg.gen_key_input(
        key_type="EDDSA",
        key_curve="ed25519",
        name_real=oidc_identity.subject,
        name_email=f"{subject_hash}@oidc.sigstore.dev",
        expire_date="10m",
        passphrase=""  # No password for automation
    ))

    # Export public key
    public_key = gpg.export_keys(key.fingerprint)

    # Log to Rekor for transparency
    log_to_rekor(public_key, oidc_identity)

    return key
```

## Ceremony Log Format

**File:** `<artifact>.ceremony.json`

```json
{
  "ceremony_version": "1.0",
  "ceremony_type": "artifact_signing",
  "timestamp": "2025-11-12T14:30:00Z",
  "identity": {
    "type": "oidc",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:owner/repo:ref:refs/heads/main",
    "claims": {
      "repository": "owner/repo",
      "repository_id": "123456",
      "repository_owner": "owner",
      "repository_owner_id": "78910",
      "workflow": ".github/workflows/sign.yml",
      "ref": "refs/heads/main",
      "sha": "abc123...",
      "event_name": "push",
      "run_id": "987654",
      "run_attempt": "1",
      "actor": "username",
      "actor_id": "12345"
    }
  },
  "artifact": {
    "path": "dist/package-1.0.0.tar.gz",
    "sha256": "def456...",
    "sha512": "ghi789...",
    "size": 1234567
  },
  "signatures": [
    {
      "backend": "gpg",
      "format": "pgp",
      "algorithm": "EdDSA",
      "key_type": "Ed25519",
      "keyless": true,
      "files": {
        "signature": "dist/package-1.0.0.tar.gz.gpg",
        "public_key": "dist/package-1.0.0.tar.gz.gpg.pub"
      },
      "key_id": "ephemeral:F98FAEE5480A92A894628D30DC421C1CA627E433",
      "key_fingerprint": "F98F AEE5 480A 92A8 9462  8D30 DC42 1C1C A627 E433",
      "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/abc123...",
      "rekor_index": 12345,
      "created_at": "2025-11-12T14:30:01Z",
      "verification_command": "gpg --import dist/package-1.0.0.tar.gz.gpg.pub && gpg --verify dist/package-1.0.0.tar.gz.gpg dist/package-1.0.0.tar.gz"
    },
    {
      "backend": "sigstore",
      "format": "cosign",
      "algorithm": "ECDSA",
      "key_type": "P-256",
      "keyless": true,
      "files": {
        "signature": "dist/package-1.0.0.tar.gz.cosign",
        "certificate": "dist/package-1.0.0.tar.gz.cosign.cert",
        "bundle": "dist/package-1.0.0.tar.gz.bundle"
      },
      "certificate_subject": "https://github.com/owner/repo/.github/workflows/sign.yml@refs/heads/main",
      "certificate_issuer": "https://token.actions.githubusercontent.com",
      "certificate_serial": "123456789...",
      "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/def456...",
      "rekor_index": 12346,
      "created_at": "2025-11-12T14:30:02Z",
      "verification_command": "cosign verify-blob --bundle dist/package-1.0.0.tar.gz.bundle dist/package-1.0.0.tar.gz"
    },
    {
      "backend": "intoto",
      "format": "dsse",
      "algorithm": "ECDSA",
      "key_type": "P-256",
      "keyless": true,
      "files": {
        "attestation": "dist/package-1.0.0.tar.gz.intoto"
      },
      "predicate_type": "https://slsa.dev/provenance/v1",
      "envelope_type": "application/vnd.in-toto+json",
      "created_at": "2025-11-12T14:30:03Z",
      "verification_command": "slsa-verifier verify-artifact --provenance-path dist/package-1.0.0.tar.gz.intoto --source-uri github.com/owner/repo dist/package-1.0.0.tar.gz"
    },
    {
      "backend": "github",
      "format": "attestation",
      "files": {},
      "attestation_id": "att_123456",
      "predicate_type": "https://slsa.dev/provenance/v1",
      "created_at": "2025-11-12T14:30:04Z",
      "verification_command": "gh attestation verify oid:gitoid:blob:sha256:def456... --repo owner/repo"
    }
  ],
  "workflow_run": "https://github.com/owner/repo/actions/runs/987654",
  "signed_by": {
    "backend": "gpg",
    "signature_file": "dist/package-1.0.0.tar.gz.ceremony.json.asc"
  }
}
```

## Verification Procedures

### Manual Verification

**GPG Signature:**

```bash
# 1. Import public key
gpg --import artifact.gpg.pub

# 2. Verify signature
gpg --verify artifact.gpg artifact

# 3. Check key fingerprint matches ceremony log
gpg --list-keys --fingerprint

# 4. Verify Rekor entry (keyless mode)
REKOR_UUID=$(jq -r '.signatures[] | select(.format=="pgp") | .rekor_entry' artifact.ceremony.json | sed 's|.*/||')
rekor-cli get --uuid $REKOR_UUID
```

**Cosign Signature:**

```bash
# 1. Verify with bundle (easiest)
cosign verify-blob --bundle artifact.bundle artifact

# 2. Or verify with separate files
cosign verify-blob \
  --signature artifact.cosign \
  --certificate artifact.cosign.cert \
  artifact

# 3. Check certificate SAN matches expected identity
openssl x509 -in artifact.cosign.cert -text -noout | grep "Subject Alternative Name" -A1

# 4. Verify Rekor inclusion
rekor-cli verify --artifact artifact --signature artifact.cosign
```

**In-toto Attestation:**

```bash
# 1. Verify SLSA provenance
slsa-verifier verify-artifact \
  --provenance-path artifact.intoto \
  --source-uri github.com/owner/repo \
  artifact

# 2. Extract and inspect predicate
jq -r '.payload' artifact.intoto | base64 -d | jq .

# 3. Verify signature in envelope
in-toto-verify --attestation artifact.intoto
```

**GitHub Attestation:**

```bash
# 1. Compute artifact gitoid
FILE_OID="oid:gitoid:blob:sha256:$(git hash-object artifact)"

# 2. Verify attestation
gh attestation verify "$FILE_OID" --repo owner/repo

# 3. Download attestation for inspection
gh attestation download "$FILE_OID" --repo owner/repo -o attestation.json
cat attestation.json | jq .
```

### Automated Verification

**Generated Script:** `artifact.verify.sh`

```bash
#!/bin/bash
set -euo pipefail

ARTIFACT="artifact"
CEREMONY="artifact.ceremony.json"
FAILED=0

echo "Verifying signatures for $ARTIFACT"
echo "Ceremony: $(jq -r .timestamp $CEREMONY)"
echo "Identity: $(jq -r .identity.subject $CEREMONY)"
echo "======================================"

# Verify each signature from ceremony log
for format in $(jq -r '.signatures[].format' $CEREMONY); do
    echo "Checking $format signature..."

    # Get verification command from ceremony log
    VERIFY_CMD=$(jq -r ".signatures[] | select(.format==\"$format\") | .verification_command" $CEREMONY)

    if eval "$VERIFY_CMD" 2>&1 | tee /tmp/verify-$format.log; then
        echo "✅ $format signature valid"
    else
        echo "❌ $format signature FAILED"
        cat /tmp/verify-$format.log
        FAILED=1
    fi
    echo
done

if [ $FAILED -eq 0 ]; then
    echo "======================================"
    echo "✅ All signatures verified successfully"
    echo "Artifact: $ARTIFACT"
    echo "SHA256: $(sha256sum $ARTIFACT | cut -d' ' -f1)"
    exit 0
else
    echo "======================================"
    echo "❌ One or more signatures failed"
    exit 1
fi
```

## Migration Guide

### Current State → Keyless Development

**Step 1: Remove Static Keys**

```bash
# Delete secret-generating code from init.yml
# Remove these lines:
# - cosign generate-key-pair
# - gpg --gen-key
# - gh secret set COSIGN_PRIVATE_KEY
# - gh secret set PGP_PRIVATE_KEY

# Delete secrets from GitHub
gh secret remove COSIGN_PRIVATE_KEY
gh secret remove PGP_PRIVATE_KEY
gh secret remove ADMIN_TOKEN  # No longer needed
```

**Step 2: Implement OIDC Signing**

```yaml
# .github/workflows/sign.yml
name: Sign with OIDC
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: write
  attestations: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Signing Tools
        run: |
          # Install cosign, gitsign, in-toto-verify
          curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          # Verify checksum
          echo "$EXPECTED_SHA  cosign-linux-amd64" | sha256sum -c -
          sudo mv cosign-linux-amd64 /usr/local/bin/cosign
          sudo chmod +x /usr/local/bin/cosign

      - name: Sign Artifact
        run: |
          # Get OIDC token
          OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -r .value)

          # Sign with Cosign (keyless)
          cosign sign-blob --yes \
            --identity-token="$OIDC_TOKEN" \
            --bundle artifact.bundle \
            artifact
```

**Step 3: Add Verification**

```yaml
# .github/workflows/verify.yml
name: Verify Signatures
on:
  push:
  schedule:
    - cron: '0 */6 * * *'

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify All Signatures
        run: |
          for ceremony in .signing/ceremonies/*.json; do
            artifact=$(jq -r .artifact.path "$ceremony")
            ./signer verify --ceremony "$ceremony" --artifact "$artifact"
          done
```

**Step 4: Update Documentation**

```markdown
# README.md

## Signing Process

This repository uses keyless OIDC signing:

- No secrets stored in GitHub
- Identity from GitHub Actions OIDC token
- Certificates from Sigstore Fulcio
- Transparency log in Rekor

## Verification

```bash
# Verify with Cosign
cosign verify-blob --bundle artifact.bundle artifact

# Check Rekor transparency log
rekor-cli search --artifact artifact
```
```

### Development → Production (HSM)

**Step 1: Provision HSM**

```bash
# AWS KMS
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --customer-master-key-spec ECC_NIST_P256 \
  --description "Bot signing key"

# GCP KMS
gcloud kms keys create bot-signing-key \
  --location us-east1 \
  --keyring bot-signer \
  --purpose asymmetric-signing \
  --default-algorithm ec-sign-p256-sha256 \
  --protection-level hsm
```

**Step 2: Configure OIDC Authentication**

```yaml
# .github/workflows/sign-production.yml
permissions:
  id-token: write

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456:role/SignerRole
      aws-region: us-east-1
```

**Step 3: Update Configuration**

```yaml
# .signing/config.yaml
mode: production

identity:
  hsm:
    provider: aws-kms
    key_id: arn:aws:kms:us-east-1:123456:key/abc-123
```

**Step 4: Implement HSM Signing**

```python
# signer/backends/aws_kms.py
import boto3

class AWSKMSBackend(SigningBackend):
    def sign(self, artifact: bytes, identity: Identity) -> Signature:
        kms = boto3.client('kms')

        # Compute digest locally
        digest = hashlib.sha256(artifact).digest()

        # Sign in HSM
        response = kms.sign(
            KeyId=self.key_id,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm='ECDSA_SHA_256'
        )

        return Signature(
            format='hsm-cosign',
            data=response['Signature'],
            key_id=self.key_id
        )
```

## Troubleshooting

### GPG: "No public key"

**Problem:** `gpg: Can't check signature: No public key`

**Solution:**
```bash
gpg --import artifact.gpg.pub
```

### Cosign: "Certificate has expired"

**Problem:** Gitsign certificate expired after 10 minutes

**Solution:** Verify via Rekor instead of local verification:
```bash
gitsign verify <commit-sha>
```

### Rekor: "Entry not found"

**Problem:** Signature not logged to Rekor

**Cause:** Network error during signing or Rekor outage

**Solution:** Re-sign artifact

### GitHub Attestation: "Not found"

**Problem:** Attestation not created

**Cause:** Missing `attestations: write` permission

**Solution:** Add to workflow:
```yaml
permissions:
  attestations: write
```

## References

- [Sigstore Documentation](https://docs.sigstore.dev/) - Fulcio, Rekor, Cosign
- [GnuPG Manual](https://www.gnupg.org/documentation/manuals/gnupg/) - GPG reference
- [In-toto Specification](https://github.com/in-toto/docs/blob/master/in-toto-spec.md) - Attestation format
- [SLSA Provenance](https://slsa.dev/spec/v1.0/provenance) - Provenance specification
- [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) - GitHub's OIDC implementation
