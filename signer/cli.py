"""Command-line interface for signing operations."""

import click
import yaml
import sys
from pathlib import Path
from .identity import OIDCIdentity
from .orchestrator import SigningOrchestrator
from .backends.gpg_keyless import GPGKeylessBackend
from .backends.sigstore import SigstoreBackend


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Multi-format keyless signing tool."""
    pass


@main.command()
@click.argument("artifact", type=click.Path(exists=True))
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Configuration file (YAML)",
)
@click.option(
    "--backends",
    multiple=True,
    type=click.Choice(["gpg", "cosign", "all"]),
    default=["all"],
    help="Signing backends to use",
)
@click.option(
    "--oidc-audience",
    default="sigstore",
    help="OIDC token audience",
)
@click.option(
    "--no-ceremony-log",
    is_flag=True,
    help="Skip ceremony log generation",
)
@click.option(
    "--no-verify-script",
    is_flag=True,
    help="Skip verification script generation",
)
def sign(artifact, config, backends, oidc_audience, no_ceremony_log, no_verify_script):
    """Sign an artifact with keyless OIDC signing."""
    try:
        # Load configuration
        config_data = {}
        if config:
            with open(config, "r") as f:
                config_data = yaml.safe_load(f)

        # Get OIDC identity
        click.echo("Acquiring OIDC token from GitHub Actions...")
        try:
            identity = OIDCIdentity.from_github_actions(audience=oidc_audience)
            click.echo(f"✅ Identity: {identity.subject}")
        except RuntimeError as e:
            click.echo(f"❌ Failed to acquire OIDC token: {e}", err=True)
            sys.exit(1)

        # Initialize backends
        backend_list = []

        # Determine which backends to use
        if "all" in backends:
            use_backends = ["gpg", "cosign"]
        else:
            use_backends = list(backends)

        if "gpg" in use_backends:
            gpg_config = config_data.get("backends", {}).get("gpg", {})
            backend_list.append(GPGKeylessBackend(gpg_config))
            click.echo("Enabled backend: GPG")

        if "cosign" in use_backends:
            cosign_config = config_data.get("backends", {}).get("cosign", {})
            backend_list.append(SigstoreBackend(cosign_config))
            click.echo("Enabled backend: Cosign")

        if not backend_list:
            click.echo("❌ No backends enabled", err=True)
            sys.exit(1)

        # Create orchestrator
        orchestrator = SigningOrchestrator(backend_list)

        # Sign artifact
        click.echo(f"\nSigning artifact: {artifact}")
        ceremony = orchestrator.sign_artifact(
            artifact,
            identity,
            parallel=True,
            generate_ceremony_log=not no_ceremony_log,
            generate_verification_script=not no_verify_script,
        )

        click.echo("\n✅ Signing complete!")
        click.echo(f"Artifact: {artifact}")
        click.echo(f"Signatures: {len(ceremony.signatures)}")

        if not no_ceremony_log:
            click.echo(f"Ceremony log: {artifact}.ceremony.json")

        if not no_verify_script:
            click.echo(f"Verification script: {artifact}.verify.sh")

    except Exception as e:
        click.echo(f"❌ Signing failed: {e}", err=True)
        import traceback

        traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument("artifact", type=click.Path(exists=True))
@click.option(
    "--ceremony-log",
    type=click.Path(exists=True),
    help="Ceremony log file",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Configuration file (YAML)",
)
def verify(artifact, ceremony_log, config):
    """Verify artifact signatures using ceremony log."""
    try:
        # Determine ceremony log path
        if ceremony_log is None:
            ceremony_log = f"{artifact}.ceremony.json"

        if not Path(ceremony_log).exists():
            click.echo(f"❌ Ceremony log not found: {ceremony_log}", err=True)
            sys.exit(1)

        # Load configuration
        config_data = {}
        if config:
            with open(config, "r") as f:
                config_data = yaml.safe_load(f)

        # Initialize backends
        backend_list = [
            GPGKeylessBackend(config_data.get("backends", {}).get("gpg", {})),
            SigstoreBackend(config_data.get("backends", {}).get("cosign", {})),
        ]

        # Create orchestrator
        orchestrator = SigningOrchestrator(backend_list)

        # Verify
        click.echo(f"Verifying artifact: {artifact}")
        click.echo(f"Ceremony log: {ceremony_log}\n")

        if orchestrator.verify_artifact(artifact, ceremony_log):
            click.echo("\n✅ All signatures verified successfully!")
        else:
            click.echo("\n❌ Verification failed!", err=True)
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Verification failed: {e}", err=True)
        import traceback

        traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument("artifact", type=click.Path(exists=True))
@click.option(
    "--ceremony-log",
    type=click.Path(exists=True),
    help="Ceremony log file",
)
def info(artifact, ceremony_log):
    """Display information about signed artifact."""
    import json

    try:
        # Determine ceremony log path
        if ceremony_log is None:
            ceremony_log = f"{artifact}.ceremony.json"

        if not Path(ceremony_log).exists():
            click.echo(f"❌ Ceremony log not found: {ceremony_log}", err=True)
            sys.exit(1)

        # Load ceremony log
        with open(ceremony_log, "r") as f:
            ceremony_data = json.load(f)

        # Display info
        click.echo(f"Artifact: {artifact}")
        click.echo(f"Ceremony: {ceremony_data.get('ceremony_type')}")
        click.echo(f"Timestamp: {ceremony_data.get('timestamp')}")
        click.echo(f"\nIdentity:")
        click.echo(f"  Type: {ceremony_data['identity'].get('type')}")
        click.echo(f"  Subject: {ceremony_data['identity'].get('subject')}")
        click.echo(f"\nArtifact:")
        click.echo(f"  SHA256: {ceremony_data['artifact'].get('sha256')}")
        click.echo(f"  Size: {ceremony_data['artifact'].get('size')} bytes")
        click.echo(f"\nSignatures ({len(ceremony_data['signatures'])}):")

        for sig in ceremony_data["signatures"]:
            click.echo(f"  - {sig['format']}")
            if "key_fingerprint" in sig:
                click.echo(f"    Key: {sig['key_fingerprint']}")
            if "rekor_index" in sig:
                click.echo(f"    Rekor: {sig['rekor_index']}")

        click.echo(f"\nWorkflow: {ceremony_data.get('workflow_run')}")

    except Exception as e:
        click.echo(f"❌ Failed to read ceremony log: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
