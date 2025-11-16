#!/bin/bash
set -euo pipefail

ARTIFACT="test-artifact.txt"
CEREMONY="test-artifact.txt.verify.ceremony.json"
FAILED=0

echo "Verifying signatures for $ARTIFACT"
echo "Ceremony: $(jq -r .timestamp $CEREMONY)"
echo "Identity: $(jq -r .identity.subject $CEREMONY)"
echo "======================================"

echo "Checking gpg signature..."
if gpg --import test-artifact.txt.gpg.pub && gpg --verify test-artifact.txt.gpg.asc ARTIFACT 2>&1 | tee /tmp/verify-gpg.log; then
    echo "✅ gpg signature valid"
else
    echo "❌ gpg signature FAILED"
    cat /tmp/verify-gpg.log
    FAILED=1
fi

echo "Checking cosign signature..."
if cosign verify-blob --bundle test-artifact.txt.cosign.bundle --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com ARTIFACT 2>&1 | tee /tmp/verify-cosign.log; then
    echo "✅ cosign signature valid"
else
    echo "❌ cosign signature FAILED"
    cat /tmp/verify-cosign.log
    FAILED=1
fi

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