"""Command-line interface for modelguard."""

import json
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from .core.scanner import ModelScanner
from .core.signature import SignatureManager
from .core.policy import Policy, PolicyConfig
from .core.exceptions import ModelGuardError

app = typer.Typer(
    name="modelguard",
    help="A drop-in seat-belt library for ML model files",
    no_args_is_help=True
)
console = Console()


@app.command()
def scan(
    paths: List[Path] = typer.Argument(..., help="Paths to model files or directories"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", "-r", help="Scan directories recursively"),
    exit_on_threat: bool = typer.Option(True, "--exit-on-threat/--no-exit", help="Exit with code 1 if threats found")
):
    """Scan model files for malicious content."""
    scanner = ModelScanner()
    all_results = []
    
    for path in paths:
        if path.is_file():
            result = scanner.scan_file(path)
            all_results.append(result)
        elif path.is_dir():
            results = scanner.scan_directory(path, recursive=recursive)
            all_results.extend(results)
        else:
            rprint(f"[red]Error: Path not found: {path}[/red]")
            raise typer.Exit(1)
    
    if not all_results:
        rprint("[yellow]No model files found to scan[/yellow]")
        return
    
    # Output results
    if format == "json":
        output = {
            "scanned_files": len(all_results),
            "safe_files": sum(1 for r in all_results if r.is_safe),
            "threat_files": sum(1 for r in all_results if not r.is_safe),
            "results": [r.to_dict() for r in all_results]
        }
        print(json.dumps(output, indent=2))
    else:
        _display_scan_table(all_results)
    
    # Exit with error code if threats found and requested
    if exit_on_threat and any(not r.is_safe for r in all_results):
        raise typer.Exit(1)


@app.command()
def sign(
    path: Path = typer.Argument(..., help="Path to model file to sign"),
    identity: Optional[str] = typer.Option(None, "--identity", "-i", help="Signer identity (email)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output signature file path")
):
    """Sign a model file using Sigstore."""
    if not path.exists():
        rprint(f"[red]Error: Model file not found: {path}[/red]")
        raise typer.Exit(1)
    
    try:
        sig_manager = SignatureManager()
        signature_path = sig_manager.sign_model(path, identity)
        
        if output:
            signature_path.rename(output)
            signature_path = output
        
        rprint(f"[green]✓ Model signed successfully[/green]")
        rprint(f"Model: {path}")
        rprint(f"Signature: {signature_path}")
        
    except ModelGuardError as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def verify(
    path: Path = typer.Argument(..., help="Path to model file to verify"),
    signature: Optional[Path] = typer.Option(None, "--signature", "-s", help="Path to signature file")
):
    """Verify a model file's signature."""
    if not path.exists():
        rprint(f"[red]Error: Model file not found: {path}[/red]")
        raise typer.Exit(1)
    
    try:
        sig_manager = SignatureManager()
        result = sig_manager.verify_signature(path, signature)
        
        if result["verified"]:
            rprint(f"[green]✓ Signature verified successfully[/green]")
            rprint(f"Model: {path}")
            rprint(f"Signature: {result['signature_path']}")
            if result.get("signer"):
                rprint(f"Signer: {result['signer'].get('identity', 'unknown')}")
        else:
            rprint(f"[red]✗ Signature verification failed[/red]")
            rprint(f"Error: {result.get('error', 'Unknown error')}")
            raise typer.Exit(1)
            
    except ModelGuardError as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def policy(
    action: str = typer.Argument(..., help="Action: init, show, validate"),
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to policy file")
):
    """Manage modelguard policies."""
    if action == "init":
        _init_policy(path)
    elif action == "show":
        _show_policy(path)
    elif action == "validate":
        _validate_policy(path)
    else:
        rprint(f"[red]Error: Unknown action: {action}[/red]")
        rprint("Available actions: init, show, validate")
        raise typer.Exit(1)


def _display_scan_table(results):
    """Display scan results in a table format."""
    table = Table(title="Model Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Threats", style="red")
    table.add_column("Details")
    
    for result in results:
        status = "[green]✓ Safe[/green]" if result.is_safe else "[red]✗ Unsafe[/red]"
        threats = "; ".join(result.threats) if result.threats else "-"
        details = result.details.get("error", "") or f"{result.details.get('total_opcodes', 0)} opcodes"
        
        table.add_row(
            str(result.path),
            status,
            threats,
            details
        )
    
    console.print(table)
    
    # Summary
    safe_count = sum(1 for r in results if r.is_safe)
    total_count = len(results)
    
    if safe_count == total_count:
        rprint(f"\n[green]✓ All {total_count} files are safe[/green]")
    else:
        unsafe_count = total_count - safe_count
        rprint(f"\n[yellow]⚠ {unsafe_count} of {total_count} files have potential threats[/yellow]")


def _init_policy(path: Optional[Path]):
    """Initialize a new policy file."""
    if path is None:
        path = Path.cwd() / "modelguard.yaml"
    
    if path.exists():
        overwrite = typer.confirm(f"Policy file already exists at {path}. Overwrite?")
        if not overwrite:
            rprint("Aborted.")
            return
    
    # Create default policy
    default_config = PolicyConfig()
    policy_data = {
        "enforce": default_config.enforce,
        "require_signatures": default_config.require_signatures,
        "trusted_signers": default_config.trusted_signers,
        "allow_unsigned": default_config.allow_unsigned,
        "scan_on_load": default_config.scan_on_load,
        "max_file_size_mb": default_config.max_file_size_mb,
        "timeout_seconds": default_config.timeout_seconds,
    }
    
    import yaml
    with open(path, 'w') as f:
        yaml.dump(policy_data, f, default_flow_style=False)
    
    rprint(f"[green]✓ Policy file created: {path}[/green]")


def _show_policy(path: Optional[Path]):
    """Show current policy configuration."""
    if path:
        if not path.exists():
            rprint(f"[red]Error: Policy file not found: {path}[/red]")
            raise typer.Exit(1)
        policy = Policy.from_file(path)
        rprint(f"Policy from: {path}")
    else:
        from .core.policy import load_policy
        policy = load_policy()
        rprint("Current effective policy:")
    
    # Display policy settings
    table = Table(title="Policy Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="bold")
    
    config = policy.config
    table.add_row("Enforce Mode", str(config.enforce))
    table.add_row("Require Signatures", str(config.require_signatures))
    table.add_row("Trusted Signers", ", ".join(config.trusted_signers) or "None")
    table.add_row("Allow Unsigned", str(config.allow_unsigned))
    table.add_row("Scan on Load", str(config.scan_on_load))
    table.add_row("Max File Size (MB)", str(config.max_file_size_mb))
    table.add_row("Timeout (seconds)", str(config.timeout_seconds))
    
    console.print(table)


def _validate_policy(path: Optional[Path]):
    """Validate a policy file."""
    if path is None:
        path = Path.cwd() / "modelguard.yaml"
    
    if not path.exists():
        rprint(f"[red]Error: Policy file not found: {path}[/red]")
        raise typer.Exit(1)
    
    try:
        policy = Policy.from_file(path)
        rprint(f"[green]✓ Policy file is valid: {path}[/green]")
        
        # Show any warnings
        config = policy.config
        if config.require_signatures and not config.trusted_signers:
            rprint("[yellow]⚠ Warning: require_signatures is true but no trusted_signers specified[/yellow]")
        
        if not config.enforce and config.require_signatures:
            rprint("[yellow]⚠ Warning: require_signatures is true but enforce is false[/yellow]")
            
    except Exception as e:
        rprint(f"[red]✗ Policy file is invalid: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()