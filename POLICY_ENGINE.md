# Policy Engine

Controls signing requirements based on artifact patterns.

## Files Created

- `/Users/sheurich/src/sheurich/bot-signer-oversight/signer/policy.py` - Policy engine implementation
- `/Users/sheurich/src/sheurich/bot-signer-oversight/tests/unit/test_policy.py` - Test suite (34 tests, all passing)
- `/Users/sheurich/src/sheurich/bot-signer-oversight/config.example.policy.yaml` - Example configuration

## Files Modified

- `/Users/sheurich/src/sheurich/bot-signer-oversight/signer/orchestrator.py` - Integrated policy engine
- `/Users/sheurich/src/sheurich/bot-signer-oversight/signer/backends/__init__.py` - Fixed lazy imports

## Policy Structure

```python
@dataclass
class Policy:
    match: str              # glob pattern (*.tar.gz, release-*, etc.)
    require: List[str]      # required backend formats (gpg, cosign, etc.)
    min_signatures: int     # minimum signature count (default: 1)
    allow_expired: bool     # allow expired signatures (default: False)
```

## Configuration Example

```yaml
policies:
  - match: "release-*.tar.gz"
    require: [gpg, cosign]
    min_signatures: 2
    allow_expired: false

  - match: "*.tar"
    require: [cosign]
    min_signatures: 1
```

## Usage

### Automatic Policy Application

When configured, the orchestrator automatically applies policies:

```python
orchestrator = SigningOrchestrator.from_config(config)
ceremony = orchestrator.sign_artifact("release-1.0.tar.gz", identity)
# Only signs with backends required by matching policy
# Validates signatures meet policy requirements
```

### Manual Policy Evaluation

```python
from signer.policy import Policy, PolicyEngine

policies = [
    Policy(match="*.tar.gz", require=["gpg", "cosign"])
]
engine = PolicyEngine(policies)

# Get required backends
backends = engine.get_required_backends("release.tar.gz")  # ["gpg", "cosign"]

# Validate signatures
result = engine.validate_signatures(artifact_path, signatures)
print(result.compliant)  # True/False
print(result.violations)  # List of violation messages
```

### Compliance Reports

```python
report = orchestrator.generate_compliance_report(
    artifact_path,
    ceremony_log_path
)
```

Report structure:
```python
{
    "artifact": "release.tar.gz",
    "compliant": True,
    "policy_matched": True,
    "signature_count": 2,
    "policy": {
        "match": "*.tar.gz",
        "require": ["gpg", "cosign"],
        "min_signatures": 2,
        "allow_expired": False
    },
    "required_backends": ["gpg", "cosign"],
    "present_backends": ["gpg", "cosign"],
    "missing_backends": [],
    "violations": []  # Only present if non-compliant
}
```

## Features

### Pattern Matching

Uses `fnmatch` for glob patterns:
- `*.tar.gz` - matches any .tar.gz file
- `release-*` - matches files starting with "release-"
- `file?.txt` - matches file1.txt, fileA.txt, etc.
- `*` - matches any file

### Policy Ordering

Policies are evaluated in order. First match wins.

```yaml
policies:
  - match: "release-*"      # Checked first
    require: [gpg, cosign]

  - match: "*.tar.gz"       # Checked second
    require: [gpg]

  - match: "*"              # Default for everything else
    require: [gpg]
```

### Validation

Checks:
- Required backends present
- Minimum signature count
- Expired signatures (if disallowed)

Multiple violations are reported together.

### Orchestrator Integration

When policy engine is configured:

1. `sign_artifact()` filters backends to only those required by policy
2. Validates required backends are configured
3. After signing, validates signatures meet policy requirements
4. Raises `RuntimeError` if policy validation fails

## Testing

Run tests:
```bash
uv run pytest tests/unit/test_policy.py -v
```

34 tests covering:
- Pattern matching
- Backend requirements
- Signature validation
- Compliance reporting
- Edge cases
