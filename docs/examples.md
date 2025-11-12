# Examples

This document provides working examples for bot-signer-oversight workflows.

## Development Mode Workflows

### Basic Keyless Signing

Sign artifacts using OIDC without storing secrets.

```yaml
# .github/workflows/sign-keyless.yml
name: Sign with Keyless OIDC

on:
  push:
    branches: [main]
  release:
    types: [published]

permissions:
  id-token: write      # Get OIDC token
  contents: write      # Push signatures
  attestations: write  # Create attestations

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3.7.0

      - name: Install Gitsign
        uses: sigstore/gitsign-installer@v0.10.2

      - name: Create Test Artifact
        run: |
          echo "Build $(date -Iseconds)" > artifact.txt
          tar -czf artifact.tar.gz artifact.txt

      - name: Sign with Cosign (Keyless)
        run: |
          # Keyless signing via Fulcio + Rekor
          cosign sign-blob --yes \
            --bundle artifact.tar.gz.bundle \
            artifact.tar.gz

          echo "Signed with Cosign"
          echo "Bundle: artifact.tar.gz.bundle"

      - name: Create GitHub Attestation
        uses: actions/attest@v1
        with:
          subject-path: artifact.tar.gz
          predicate-type: https://slsa.dev/provenance/v1
          predicate: |
            {
              "buildDefinition": {
                "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
                "externalParameters": {
                  "workflow": {
                    "ref": "${{ github.ref }}",
                    "repository": "${{ github.repository }}",
                    "path": ".github/workflows/sign-keyless.yml"
                  }
                }
              },
              "runDetails": {
                "builder": {
                  "id": "https://github.com/Attestations/GitHubHostedActions@v1"
                },
                "metadata": {
                  "invocationId": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
                }
              }
            }

      - name: Commit Signatures
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

          # Configure gitsign for commit signing
          git config gpg.format x509
          git config gpg.x509.program gitsign
          git config commit.gpgsign true

          git add artifact.tar.gz.bundle
          git commit -m "Add signature for artifact.tar.gz"
          git push
```

### Multi-Format Signing

Sign once, output multiple formats.

```yaml
# .github/workflows/sign-multi-format.yml
name: Multi-Format Signing

on:
  release:
    types: [published]

permissions:
  id-token: write
  contents: write
  attestations: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download Release Assets
        run: |
          gh release download ${{ github.ref_name }} -D dist/
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Install Tools
        run: |
          # Cosign
          curl -LO https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64
          echo "d7c2c9ba..."  # expected checksum
          sudo install cosign-linux-amd64 /usr/local/bin/cosign

          # GPG (already installed)

          # In-toto (for SLSA)
          pip install in-toto slsa-verifier

      - name: Sign with Multiple Formats
        run: |
          for artifact in dist/*; do
            echo "Signing $artifact..."

            # 1. Cosign signature (keyless)
            cosign sign-blob --yes \
              --bundle "${artifact}.bundle" \
              "$artifact"

            # 2. GPG signature (ephemeral key)
            gpg --batch --gen-key <<EOF
          %no-protection
          Key-Type: eddsa
          Key-Curve: ed25519
          Name-Real: github-actions[bot]
          Name-Email: 41898282+github-actions[bot]@users.noreply.github.com
          Expire-Date: 10m
          EOF

            KEY_ID=$(gpg --list-keys --with-colons | grep ^fpr | head -1 | cut -d: -f10)
            gpg --detach-sign --armor -u "$KEY_ID" -o "${artifact}.asc" "$artifact"
            gpg --export -a "$KEY_ID" > "${artifact}.pub"

            # 3. In-toto attestation (SLSA provenance)
            in-toto-run \
              --step-name build \
              --products "$artifact" \
              --key <(echo "${{ secrets.SIGNING_KEY }}") \
              -- echo "Attesting $artifact"

            # 4. GitHub attestation
            gh attestation attest \
              --repo ${{ github.repository }} \
              --predicate-type https://slsa.dev/provenance/v1 \
              --predicate <(cat <<EOF
          {
            "buildDefinition": {
              "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1"
            }
          }
          EOF
          ) \
              "$artifact"

            echo "Signed $artifact with 4 formats"
          done

      - name: Create Verification Script
        run: |
          cat > verify.sh <<'EOF'
          #!/bin/bash
          set -euo pipefail

          ARTIFACT="$1"

          echo "Verifying $ARTIFACT"
          echo "===================="

          # Cosign
          echo "Checking Cosign..."
          cosign verify-blob --bundle "${ARTIFACT}.bundle" "$ARTIFACT" && echo "Cosign OK"

          # GPG
          echo "Checking GPG..."
          gpg --import "${ARTIFACT}.pub"
          gpg --verify "${ARTIFACT}.asc" "$ARTIFACT" && echo "GPG OK"

          # GitHub attestation
          echo "Checking GitHub attestation..."
          FILE_OID="oid:gitoid:blob:sha256:$(git hash-object "$ARTIFACT")"
          gh attestation verify "$FILE_OID" --repo ${{ github.repository }} && echo "GitHub OK"

          echo "===================="
          echo "All signatures valid"
          EOF

          chmod +x verify.sh

      - name: Upload to Release
        run: |
          gh release upload ${{ github.ref_name }} dist/* verify.sh
        env:
          GH_TOKEN: ${{ github.token }}
```

### Commit Signing with Gitsign

Sign all commits using Fulcio certificates.

```yaml
# .github/workflows/commit-with-gitsign.yml
name: Commit with Gitsign

on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

permissions:
  id-token: write
  contents: write

jobs:
  commit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Gitsign
        uses: sigstore/gitsign-installer@v0.10.2

      - name: Configure Git
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

          # Use gitsign for signing
          git config gpg.format x509
          git config gpg.x509.program gitsign
          git config commit.gpgsign true

      - name: Make Changes
        run: |
          date +%s > timestamp.txt
          echo "Last updated: $(date)" >> README.md

      - name: Commit and Push
        run: |
          git add timestamp.txt README.md
          git commit -m "Update timestamp at $(date -Iseconds)"
          git push

      - name: Verify Commit
        run: |
          # Get latest commit
          COMMIT=$(git rev-parse HEAD)

          # Verify with gitsign
          gitsign verify \
            --certificate-identity-regexp=".*" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            $COMMIT

          echo "Commit $COMMIT verified"

          # Show certificate details
          git log --show-signature -1
```

## Automated Verification Workflow

Verify all signatures on push and schedule.

```yaml
# .github/workflows/verify-signatures.yml
name: Verify Signatures

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  verify-commits:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 10  # Last 10 commits

      - name: Install Gitsign
        uses: sigstore/gitsign-installer@v0.10.2

      - name: Verify Recent Commits
        run: |
          echo "Verifying last 10 commits..."
          FAILED=0

          for commit in $(git log -10 --format=%H); do
            echo "Checking commit $commit"

            # Try gitsign verification (for keyless commits)
            if gitsign verify \
              --certificate-identity-regexp=".*" \
              --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
              $commit 2>&1; then
              echo "Commit $commit verified (gitsign)"
            else
              echo "Commit $commit verification FAILED"
              FAILED=1
            fi
          done

          if [ $FAILED -eq 1 ]; then
            echo "One or more commit verifications failed"
            exit 1
          fi

          echo "All commits verified"

  verify-artifacts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Verification Tools
        run: |
          # Cosign
          curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          sudo install cosign-linux-amd64 /usr/local/bin/cosign

      - name: Find and Verify Bundles
        run: |
          echo "Finding Cosign bundles..."
          FAILED=0

          find . -name "*.bundle" | while read bundle; do
            artifact="${bundle%.bundle}"

            if [ -f "$artifact" ]; then
              echo "Verifying $artifact"

              if cosign verify-blob --bundle "$bundle" "$artifact"; then
                echo "$artifact verified"
              else
                echo "$artifact verification FAILED"
                FAILED=1
              fi
            else
              echo "Warning: Artifact $artifact not found for bundle $bundle"
            fi
          done

          if [ $FAILED -eq 1 ]; then
            exit 1
          fi

          echo "All artifacts verified"

  verify-attestations:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify GitHub Attestations
        run: |
          echo "Verifying GitHub attestations..."

          # Find all tracked files
          for file in $(git ls-files); do
            # Skip workflow files and documentation
            if [[ "$file" == .github/* ]] || [[ "$file" == *.md ]]; then
              continue
            fi

            # Compute gitoid
            FILE_OID="oid:gitoid:blob:sha256:$(git hash-object "$file")"

            # Try to verify attestation
            if gh attestation verify "$FILE_OID" --repo ${{ github.repository }} 2>/dev/null; then
              echo "$file has valid attestation"
            fi
          done
        env:
          GH_TOKEN: ${{ github.token }}
```

## Production Mode Workflows

### HSM Signing (AWS KMS)

Sign with HSM-backed keys.

```yaml
# .github/workflows/sign-production.yml
name: Production Signing (HSM)

on:
  release:
    types: [published]

permissions:
  id-token: write       # For AWS OIDC
  contents: write

jobs:
  sign:
    runs-on: ubuntu-latest
    environment: production  # Requires approval

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_SIGNER_ROLE_ARN }}
          aws-region: us-east-1

      - name: Download Release Assets
        run: |
          gh release download ${{ github.ref_name }} -D dist/
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Sign with AWS KMS
        run: |
          KMS_KEY_ID="${{ secrets.AWS_KMS_KEY_ID }}"

          for artifact in dist/*; do
            echo "Signing $artifact with KMS..."

            # Compute digest locally
            DIGEST=$(sha256sum "$artifact" | cut -d' ' -f1)

            # Sign in KMS (key never leaves HSM)
            SIGNATURE=$(aws kms sign \
              --key-id "$KMS_KEY_ID" \
              --message "fileb://<(echo -n $DIGEST | xxd -r -p)" \
              --message-type DIGEST \
              --signing-algorithm ECDSA_SHA_256 \
              --query 'Signature' \
              --output text)

            # Save signature
            echo "$SIGNATURE" | base64 -d > "${artifact}.kms.sig"

            # Get public key for verification
            aws kms get-public-key \
              --key-id "$KMS_KEY_ID" \
              --query 'PublicKey' \
              --output text | base64 -d > kms-public-key.der

            echo "✅ Signed $artifact"
          done

      - name: Create Ceremony Log
        run: |
          cat > ceremony.json <<EOF
          {
            "ceremony_type": "production_signing",
            "timestamp": "$(date -Iseconds)",
            "identity": {
              "type": "hsm",
              "provider": "aws-kms",
              "key_id": "${{ secrets.AWS_KMS_KEY_ID }}",
              "role_arn": "${{ secrets.AWS_SIGNER_ROLE_ARN }}"
            },
            "artifacts": $(ls dist/* | jq -R . | jq -s .),
            "workflow_run": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
          }
          EOF

      - name: Upload Signatures
        run: |
          gh release upload ${{ github.ref_name }} dist/*.kms.sig ceremony.json kms-public-key.der
        env:
          GH_TOKEN: ${{ github.token }}
```

### Key Rotation

Rotate HSM keys with continuity proof.

```yaml
# .github/workflows/rotate-keys.yml
name: Rotate HSM Keys

on:
  workflow_dispatch:
    inputs:
      reason:
        required: true
        description: 'Reason for rotation'

permissions:
  id-token: write
  contents: write

jobs:
  rotate:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_SIGNER_ROLE_ARN }}
          aws-region: us-east-1

      - name: Generate New Key
        run: |
          # Create new KMS key
          NEW_KEY=$(aws kms create-key \
            --key-usage SIGN_VERIFY \
            --customer-master-key-spec ECC_NIST_P256 \
            --description "Bot signing key (rotated $(date -Idate))" \
            --query 'KeyMetadata.KeyId' \
            --output text)

          echo "NEW_KEY_ID=$NEW_KEY" >> $GITHUB_ENV

          # Create alias
          aws kms create-alias \
            --alias-name alias/bot-signer-current \
            --target-key-id $NEW_KEY

          echo "Created new key: $NEW_KEY"

      - name: Sign Rotation Ceremony with Old Key
        run: |
          OLD_KEY_ID="${{ secrets.AWS_KMS_KEY_ID }}"

          # Create rotation ceremony log
          cat > rotation-ceremony.txt <<EOF
          Key Rotation Ceremony
          Date: $(date -Iseconds)
          Reason: ${{ github.event.inputs.reason }}
          Old Key: $OLD_KEY_ID
          New Key: $NEW_KEY_ID
          Workflow: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
          Actor: ${{ github.actor }}
          EOF

          # Sign with OLD key
          DIGEST=$(sha256sum rotation-ceremony.txt | cut -d' ' -f1)
          aws kms sign \
            --key-id "$OLD_KEY_ID" \
            --message "fileb://<(echo -n $DIGEST | xxd -r -p)" \
            --message-type DIGEST \
            --signing-algorithm ECDSA_SHA_256 \
            --query 'Signature' \
            --output text | base64 -d > rotation-ceremony.old-key.sig

          echo "Signed ceremony with old key"

      - name: Sign Rotation Ceremony with New Key
        run: |
          # Sign with NEW key
          DIGEST=$(sha256sum rotation-ceremony.txt | cut -d' ' -f1)
          aws kms sign \
            --key-id "$NEW_KEY_ID" \
            --message "fileb://<(echo -n $DIGEST | xxd -r -p)" \
            --message-type DIGEST \
            --signing-algorithm ECDSA_SHA_256 \
            --query 'Signature' \
            --output text | base64 -d > rotation-ceremony.new-key.sig

          echo "Signed ceremony with new key"

      - name: Export Public Keys
        run: |
          # Old key public key
          aws kms get-public-key \
            --key-id "${{ secrets.AWS_KMS_KEY_ID }}" \
            --query 'PublicKey' \
            --output text | base64 -d > old-key.pub

          # New key public key
          aws kms get-public-key \
            --key-id "$NEW_KEY_ID" \
            --query 'PublicKey' \
            --output text | base64 -d > new-key.pub

      - name: Commit Rotation
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

          # Move old key to archive
          mkdir -p archive
          mv kms-public-key.der archive/key-$(date -Idate).der

          # Install new key
          cp new-key.pub kms-public-key.der

          # Add rotation ceremony
          git add rotation-ceremony.txt rotation-ceremony.*.sig old-key.pub new-key.pub archive/
          git commit -m "Rotate KMS key: ${{ github.event.inputs.reason }}"
          git push

      - name: Update Secret
        run: |
          gh secret set AWS_KMS_KEY_ID --body "$NEW_KEY_ID"
        env:
          GH_TOKEN: ${{ secrets.ADMIN_TOKEN }}

      - name: Schedule Old Key Deletion
        run: |
          # Schedule deletion in 30 days (KMS minimum)
          aws kms schedule-key-deletion \
            --key-id "${{ secrets.AWS_KMS_KEY_ID }}" \
            --pending-window-in-days 30

          echo "Old key scheduled for deletion in 30 days"
```

## Configuration Examples

### Basic Development Configuration

```yaml
# .signing/config.yaml
version: "1.0"
mode: development

identity:
  oidc:
    issuer: https://token.actions.githubusercontent.com
    audience: sigstore

backends:
  cosign:
    enabled: true
    keyless_mode: true

  gitsign:
    enabled: true

policies:
  - name: all-commits
    artifacts: ["**"]
    required_backends: [gitsign]
```

### Multi-Format Release Configuration

```yaml
# .signing/config.yaml
version: "1.0"
mode: development

identity:
  oidc:
    issuer: https://token.actions.githubusercontent.com
    audience: sigstore

backends:
  gpg:
    enabled: true
    keyless_mode: true
    key_type: Ed25519

  cosign:
    enabled: true
    keyless_mode: true

  intoto:
    enabled: true
    predicate_types:
      - https://slsa.dev/provenance/v1

  github:
    enabled: true

policies:
  - name: releases
    artifacts:
      - "dist/**/*.tar.gz"
      - "dist/**/*.whl"
    required_backends: [cosign, gpg, intoto, github]
    ceremony_log: true
```

### Production HSM Configuration

```yaml
# .signing/config.yaml
version: "1.0"
mode: production

identity:
  hsm:
    provider: aws-kms
    region: us-east-1
    key_id: arn:aws:kms:us-east-1:123456:key/abc-123
    role_arn: arn:aws:iam::123456:role/SignerRole

backends:
  cosign:
    enabled: true
    keyless_mode: false  # Use HSM key
    hsm_backend: true

  intoto:
    enabled: true
    predicate_types:
      - https://slsa.dev/provenance/v1

policies:
  - name: production-releases
    artifacts: ["dist/**/*"]
    required_backends: [cosign, intoto]
    ceremony_log: true
    ceremony_log_path: ".signing/ceremonies/prod-{timestamp}.json"
```

## Common Use Cases

### Use Case 1: Sign Release Binaries

```bash
# 1. Build binaries
make build

# 2. Sign with multiple formats
./signer sign \
  --mode development \
  --artifact dist/binary-linux-amd64 \
  --backends cosign,gpg,intoto,github

# 3. Upload to release
gh release upload v1.0.0 \
  dist/binary-linux-amd64 \
  dist/binary-linux-amd64.bundle \
  dist/binary-linux-amd64.asc \
  dist/binary-linux-amd64.pub \
  dist/binary-linux-amd64.intoto \
  dist/binary-linux-amd64.verify.sh
```

### Use Case 2: Sign Container Images

```bash
# 1. Build image
docker build -t myimage:latest .

# 2. Push to registry
docker push myimage:latest

# 3. Sign image with Cosign
cosign sign --yes myimage:latest

# 4. Attach SBOM
syft myimage:latest -o spdx-json > sbom.spdx.json
cosign attach sbom --sbom sbom.spdx.json myimage:latest
cosign sign --yes myimage:latest-sbom

# 5. Generate attestation
cosign attest --yes \
  --predicate sbom.spdx.json \
  --type spdx \
  myimage:latest
```

### Use Case 3: Verify Downloaded Artifact

```bash
# 1. Download artifact and signatures
gh release download v1.0.0

# 2. Run verification script
chmod +x binary-linux-amd64.verify.sh
./binary-linux-amd64.verify.sh

# 3. Or verify manually
cosign verify-blob \
  --bundle binary-linux-amd64.bundle \
  binary-linux-amd64
```

## Troubleshooting

### Debug OIDC Token

```yaml
- name: Debug OIDC Token
  run: |
    OIDC_TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -r .value)

    # Decode JWT (without verification)
    echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d | jq .

    # Check claims
    echo "Issuer: $(echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d | jq -r .iss)"
    echo "Subject: $(echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d | jq -r .sub)"
```

### Verify Rekor Entry

```bash
# Find entry for artifact
rekor-cli search --artifact artifact.tar.gz

# Get entry details
rekor-cli get --uuid <uuid>

# Verify inclusion proof
rekor-cli verify --artifact artifact.tar.gz --signature artifact.tar.gz.sig
```

### Check Certificate

```bash
# Decode Fulcio certificate
openssl x509 -in artifact.cosign.cert -text -noout

# Check SAN
openssl x509 -in artifact.cosign.cert -text -noout | grep -A1 "Subject Alternative Name"

# Check validity
openssl x509 -in artifact.cosign.cert -noout -dates
```

## References

- [Sigstore Examples](https://github.com/sigstore/cosign/tree/main/examples) - Cosign usage examples
- [Gitsign Examples](https://github.com/sigstore/gitsign/tree/main/examples) - Gitsign examples
- [SLSA Provenance Examples](https://slsa.dev/spec/v1.0/example) - SLSA provenance examples
- [GitHub Actions Workflows](https://docs.github.com/en/actions/using-workflows) - Workflow syntax
