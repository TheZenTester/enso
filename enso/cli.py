"""ENSO CLI entry point using Typer."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import IntPrompt, Prompt

from . import __version__
from .cli_helpers import (
    apply_dhcp_and_exit,
    display_pipeline_summary,
    run_credential_check,
    run_pre_flight_checks,
    sync_nessus_credentials,
)
from .config import load_config, get_default_config_dir, EnsoConfig
from .context import ContextManager, EngagementContext
from .utils.logging import setup_logging, get_logger

app = typer.Typer(
    name="enso",
    help="Engagement Network Scanning Orchestrator for penetration testing.",
    add_completion=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()
logger = get_logger(__name__)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"ENSO version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    config_dir: Optional[Path] = typer.Option(
        None,
        "--config-dir", "-c",
        help="Configuration directory path",
        envvar="ENSO_CONFIG_DIR",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output (DEBUG level)",
    ),
    version: bool = typer.Option(
        False,
        "--version", "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """ENSO - Engagement Network Scanning Orchestrator."""
    # Load configuration
    cfg_dir = config_dir or get_default_config_dir()
    
    try:
        config = load_config(cfg_dir)
    except FileNotFoundError:
        console.print(f"[yellow]Warning: Config directory not found: {cfg_dir}[/yellow]")
        console.print("[dim]Using default configuration[/dim]")
        config = EnsoConfig()
    
    # Setup logging
    log_level = "DEBUG" if verbose else config.global_config.log_level
    setup_logging(level=log_level)
    
    # Store config in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["config_dir"] = cfg_dir


# Nessus command group
nessus_app = typer.Typer(
    name="nessus",
    help="Nessus-related commands",
)
app.add_typer(nessus_app, name="nessus")


@nessus_app.command("setup")
def nessus_setup(ctx: typer.Context) -> None:
    """Set up Nessus API keys for persistent storage.
    
    Prompts for access_key and secret_key, then stores them securely at
    ~/.config/enso/nessus_keys with 600 permissions.
    
    Keys stored here persist across reboots and terminal sessions.
    """
    from rich.prompt import Prompt
    from .nessus_keys import save_nessus_keys, load_nessus_keys, get_key_file_path
    
    console.print("\n[bold cyan]ENSO Nessus API Key Setup[/bold cyan]\n")
    
    # Check for existing keys
    existing = load_nessus_keys()
    if existing:
        console.print(f"[yellow]⚠ Existing keys found at: {get_key_file_path()}[/yellow]")
        overwrite = Prompt.ask(
            "Overwrite existing keys?",
            choices=["y", "n"],
            default="n",
        )
        if overwrite.lower() != "y":
            console.print("[dim]Setup cancelled[/dim]")
            return
    
    console.print("[dim]Enter your Nessus API credentials.[/dim]")
    console.print("[dim]These are generated in Nessus: Settings → My Account → API Keys[/dim]\n")
    
    access_key = Prompt.ask("Access Key")
    secret_key = Prompt.ask("Secret Key", password=True)
    
    if not access_key or not secret_key:
        console.print("[red]✗ Both access key and secret key are required[/red]")
        raise typer.Exit(1)
    
    # Save keys
    key_file = save_nessus_keys(access_key, secret_key)
    
    console.print(f"\n[green]✓ Keys saved to: {key_file}[/green]")
    console.print("[dim]File has 600 permissions (owner read/write only)[/dim]")
    console.print("\n[bold]Run 'enso nessus check' to verify the connection.[/bold]")


@nessus_app.command("clear")
def nessus_clear(ctx: typer.Context) -> None:
    """Remove stored Nessus API keys."""
    from rich.prompt import Confirm
    from .nessus_keys import delete_nessus_keys, get_key_file_path
    
    key_file = get_key_file_path()
    
    if not key_file.exists():
        console.print("[yellow]No stored keys found[/yellow]")
        return
    
    if Confirm.ask(f"Delete stored keys at {key_file}?", default=False):
        delete_nessus_keys()
        console.print("[green]✓ Keys deleted[/green]")
    else:
        console.print("[dim]Cancelled[/dim]")


@nessus_app.command("check")
def nessus_check(ctx: typer.Context) -> None:
    """Run Nessus pre-flight validation checks.
    
    Validates server connectivity, authentication, scanner status, and policy mapping.
    """
    from .nessus_validator import NessusValidator
    from .nessus_keys import load_nessus_keys, get_key_file_path
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]Running Nessus Pre-flight Checks...[/bold cyan]\n")
    
    # Show key source
    if load_nessus_keys():
        console.print(f"[dim]Using keys from: {get_key_file_path()}[/dim]\n")
    elif config.nessus.keys_configured():
        console.print("[dim]Using keys from: environment variables or nessus.yaml[/dim]\n")
    else:
        console.print("[yellow]⚠ No API keys configured. Run 'enso nessus setup' first.[/yellow]\n")
    
    validator = NessusValidator(config)
    report = validator.validate_all()
    validator.display_report(report)
    
    if not report.all_passed:
        raise typer.Exit(1)


@nessus_app.command("sync-creds")
def nessus_sync_creds(ctx: typer.Context) -> None:
    """Push credentials from credentials.yaml to the Nessus policy.
    
    Updates the default Nessus policy with Windows and Linux credentials
    from your credentials.yaml configuration.
    """
    from rich.table import Table
    from rich.prompt import Confirm
    from .nessus_policy import NessusPolicyManager
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]Nessus Credential Sync[/bold cyan]\n")
    
    policy_name = config.nessus.policy_mapping.default
    console.print(f"[dim]Target policy: {policy_name}[/dim]")
    
    # Check if we have credentials configured
    has_creds = bool(config.credentials.linux) or bool(config.credentials.windows)
    if not has_creds:
        console.print("[yellow]⚠ No credentials configured in credentials.yaml[/yellow]")
        console.print("[dim]Edit configs/credentials.yaml to add Windows/Linux credentials[/dim]")
        raise typer.Exit(1)
    
    # Show what will be synced
    console.print("\n[bold]Credentials to sync:[/bold]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("Domain/Escalation")
    table.add_column("Description", style="dim")

    for name, cred in config.credentials.windows.items():
        table.add_row("Windows", name, cred.username, cred.domain or "LOCAL", cred.description)

    for name, cred in config.credentials.linux.items():
        table.add_row("SSH", name, cred.username, cred.privilege_escalation or "none", cred.description)

    console.print(table)

    # Let user select which credentials to push
    from .ui.prompts import Prompts
    win_names, lin_names = Prompts.select_credentials(
        config.credentials.windows, config.credentials.linux,
    )
    if not win_names and not lin_names:
        console.print("[dim]No credentials selected — sync cancelled[/dim]")
        raise typer.Exit(0)

    filtered_creds = config.credentials.filter_by_names(win_names, lin_names)

    # Connect and sync
    console.print("\n[dim]Connecting to Nessus...[/dim]")

    try:
        manager = NessusPolicyManager(config.nessus)

        # Show existing credentials if parseable
        existing_creds = manager.get_policy_credentials(policy_name)
        delete_ids: list[int] | None = None

        if existing_creds:
            console.print(f"\n[yellow]Policy already has {len(existing_creds)} credential(s):[/yellow]")

            existing_table = Table(show_header=True, header_style="bold")
            existing_table.add_column("Type")
            existing_table.add_column("Username")
            existing_table.add_column("Domain")

            for cred in existing_creds:
                existing_table.add_row(
                    cred.credential_type.title(),
                    cred.username,
                    cred.domain or "",
                )

            console.print(existing_table)

        # Always offer removal — parsing may miss creds the API stores
        if Confirm.ask(
            "\nRemove existing credentials from policy before adding new ones?",
            default=True,
        ):
            delete_ids = manager.get_policy_credential_ids(policy_name)
            if delete_ids:
                console.print(
                    f"[dim]Will remove {len(delete_ids)} credential(s) "
                    f"and replace with credentials.yaml[/dim]"
                )
            else:
                console.print(
                    "[yellow]Could not find credential IDs to delete "
                    "— credentials will be added alongside existing ones. "
                    "Remove duplicates manually via the Nessus web UI.[/yellow]"
                )
        else:
            console.print("[dim]Existing credentials will be kept (new ones added alongside)[/dim]")

        console.print("[dim]Updating policy credentials...[/dim]")

        if manager.update_policy_credentials(
            policy_name, filtered_creds, delete_ids=delete_ids
        ):
            console.print(f"\n[green]✓ Credentials synced to policy: {policy_name}[/green]")
        else:
            console.print("[red]✗ Failed to sync credentials[/red]")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        raise typer.Exit(1)


def _resolve_nessus_output_dir(
    scan_name: str,
    config: EnsoConfig,
    client_dir: Path,
) -> Path:
    """Determine the correct nessus output directory based on scan name prefix.

    Matches the scan name prefix (the ``network_id`` portion of
    ``{network_id}_{YYYYMMDD_HHMMSS}``) against configured network drops.
    Falls back to simple engagement output dir if no match.
    """
    import re

    network_drops = config.engagement.network_drops or []

    # Extract network_id prefix: everything before _YYYYMMDD_HHMMSS
    match = re.match(r'^(.+)_\d{8}_\d{6}$', scan_name)
    prefix = match.group(1) if match else None

    nessus_dir = config.global_config.get_module_output_dir("nessus")

    if prefix and network_drops:
        for nd in network_drops:
            if nd.get_network_dir() == prefix:
                return client_dir / nd.get_output_dir() / "scans" / nessus_dir

    # Fallback: simple engagement output dir
    return client_dir / config.engagement.simple.output_dir / "scans" / nessus_dir


@nessus_app.command("export")
def nessus_export(
    ctx: typer.Context,
    scan_ids: Optional[str] = typer.Argument(
        None,
        help="Scan ID(s) to export, comma-separated (e.g. 42 or 42,43,86)",
        metavar="SCAN_IDS",
    ),
    client_dir: Optional[Path] = typer.Option(
        None,
        "--client-dir",
        help="Client engagement directory",
    ),
) -> None:
    """Export Nessus scan(s) to .nessus file(s).

    Downloads scans in Nessus native XML format and saves them to the
    engagement's scans/nessus/ directory.  Output directory is automatically
    determined by matching the scan name prefix against configured network drops.

    If no scan IDs are provided, recent scans are listed for interactive selection.
    """
    from rich.table import Table
    from .nessus_bridge import NessusBridge

    config: EnsoConfig = ctx.obj["config"]
    client = client_dir or config.engagement.client_dir

    console.print("\n[bold cyan]Nessus Scan Export[/bold cyan]\n")

    # Connect to Nessus
    bridge = NessusBridge(config.nessus, credentials=config.credentials)
    if not bridge.connect():
        console.print("[red]Failed to connect to Nessus[/red]")
        raise typer.Exit(1)

    # Build scan name lookup from recent scans
    recent = bridge.list_recent_scans(limit=50)
    name_lookup: dict[int, str] = {s["id"]: s["name"] for s in recent}

    # Resolve scan IDs
    if scan_ids is not None:
        try:
            id_list = [int(x.strip()) for x in scan_ids.split(",")]
        except ValueError:
            console.print("[red]Invalid scan ID(s). Use comma-separated integers.[/red]")
            raise typer.Exit(1)
    else:
        # Interactive selection
        if not recent:
            console.print("[yellow]No Nessus scans found[/yellow]")
            raise typer.Exit(0)

        table = Table(title="Recent Scans")
        table.add_column("ID", style="dim")
        table.add_column("Name", style="cyan")
        table.add_column("Status")

        for scan in recent:
            status = scan["status"]
            style = "green" if status == "completed" else "yellow"
            table.add_row(
                str(scan["id"]),
                scan["name"],
                f"[{style}]{status}[/{style}]",
            )

        console.print(table)
        console.print()
        raw = Prompt.ask("Enter scan ID(s) to export (comma-separated)")
        try:
            id_list = [int(x.strip()) for x in raw.split(",")]
        except ValueError:
            console.print("[red]Invalid input. Use comma-separated integers.[/red]")
            raise typer.Exit(1)

    # Export each scan
    success_count = 0
    for sid in id_list:
        # Resolve scan name
        scan_name = name_lookup.get(sid)
        if not scan_name:
            status_info = bridge.get_scan_status(sid)
            scan_name = status_info.get("name")
            if not scan_name or scan_name == "Unknown":
                console.print(f"[yellow]Could not resolve name for scan {sid}[/yellow]")
                scan_name = None

        # Determine output directory based on scan name routing
        if scan_name:
            output_dir = _resolve_nessus_output_dir(scan_name, config, client)
        else:
            nessus_dir = config.global_config.get_module_output_dir("nessus")
            output_dir = client / config.engagement.simple.output_dir / "scans" / nessus_dir

        output_dir.mkdir(parents=True, exist_ok=True)

        label = f"{scan_name} (ID {sid})" if scan_name else f"scan {sid}"
        console.print(f"[dim]Exporting {label} to {output_dir}...[/dim]")

        result = bridge.export_scan(sid, output_dir, scan_name=scan_name)

        if result:
            size_kb = result.stat().st_size / 1024
            console.print(f"[green]  ✓ {result.name}[/green] [dim]({size_kb:.1f} KB)[/dim]")
            success_count += 1
        else:
            console.print(f"[red]  ✗ Export failed for scan {sid}[/red]")

    # Summary for multi-scan exports
    total = len(id_list)
    if total > 1:
        console.print(
            f"\n[bold]Exported {success_count}/{total} scan(s)[/bold]"
        )
    if success_count == 0:
        raise typer.Exit(1)


# Credentials command group
creds_app = typer.Typer(
    name="creds",
    help="Credential management and validation commands",
)
app.add_typer(creds_app, name="creds")


@creds_app.command("show")
def creds_show(ctx: typer.Context) -> None:
    """Display configured credentials (passwords masked)."""
    from rich.table import Table
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]Configured Credentials[/bold cyan]\n")
    
    # Linux credentials
    if config.credentials.linux:
        table = Table(title="Linux (SSH) Credentials")
        table.add_column("Name", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("Privilege Escalation")
        table.add_column("Password Status")
        table.add_column("Description", style="dim")

        for name, cred in config.credentials.linux.items():
            if cred.needs_runtime_prompt():
                pwd_status = "[yellow]⚠ Will prompt at runtime[/yellow]"
            elif cred.password and cred.password.startswith("${"):
                pwd_status = f"[dim]Env: {cred.password}[/dim]"
            else:
                pwd_status = "[green]✓ Configured[/green]"

            table.add_row(
                name,
                cred.username,
                cred.privilege_escalation or "none",
                pwd_status,
                cred.description,
            )
        
        console.print(table)
    else:
        console.print("[dim]No Linux credentials configured[/dim]")
    
    console.print()
    
    # Windows credentials
    if config.credentials.windows:
        table = Table(title="Windows (SMB) Credentials")
        table.add_column("Name", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("Domain")
        table.add_column("Password Status")
        table.add_column("Description", style="dim")

        for name, cred in config.credentials.windows.items():
            if cred.needs_runtime_prompt():
                pwd_status = "[yellow]⚠ Will prompt at runtime[/yellow]"
            elif cred.password and cred.password.startswith("${"):
                pwd_status = f"[dim]Env: {cred.password}[/dim]"
            else:
                pwd_status = "[green]✓ Configured[/green]"

            table.add_row(
                name,
                cred.username,
                cred.domain or "LOCAL",
                pwd_status,
                cred.description,
            )
        
        console.print(table)
    else:
        console.print("[dim]No Windows credentials configured[/dim]")
    
    console.print()


@creds_app.command("test")
def creds_test(
    ctx: typer.Context,
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope", "-s",
        help="Path to in-scope hosts file (one IP per line)",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output directory for failure report",
    ),
    linux_only: bool = typer.Option(
        False,
        "--linux-only",
        help="Only test Linux/SSH credentials",
    ),
    windows_only: bool = typer.Option(
        False,
        "--windows-only",
        help="Only test Windows/SMB credentials",
    ),
) -> None:
    """Test credentials against in-scope hosts using nxc.
    
    Validates that configured credentials work against target hosts
    before running Nessus authenticated scans.
    
    Requires: nxc (NetExec) installed on the system.
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    
    from .cred_validator import CredentialValidator
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]ENSO Credential Validation[/bold cyan]\n")
    
    # Check nxc availability
    validator = CredentialValidator(
        credentials=config.credentials,
        targets=[],  # Temporary, will update
        output_dir=output_dir or Path("."),
    )
    
    if not validator.check_nxc_available():
        console.print("[red]✗ nxc (NetExec) not found[/red]")
        console.print("[dim]Install with: pip install netexec[/dim]")
        raise typer.Exit(1)
    
    console.print("[green]✓[/green] nxc detected")
    
    # Load targets from scope file
    if scope_file:
        if not scope_file.exists():
            console.print(f"[red]✗ Scope file not found: {scope_file}[/red]")
            raise typer.Exit(1)
        targets = [line.strip() for line in scope_file.read_text().splitlines() if line.strip() and not line.startswith("#")]
    else:
        # Try to find scope file from engagement config
        console.print("[yellow]⚠ No scope file specified[/yellow]")
        console.print("[dim]Use --scope to specify a file with target IPs[/dim]")
        raise typer.Exit(1)
    
    if not targets:
        console.print("[yellow]⚠ No targets found in scope file[/yellow]")
        raise typer.Exit(1)
    
    console.print(f"[green]✓[/green] Loaded {len(targets)} targets from scope file")
    
    # Check credentials are configured
    has_linux = bool(config.credentials.linux) and not windows_only
    has_windows = bool(config.credentials.windows) and not linux_only
    
    if not has_linux and not has_windows:
        console.print("[yellow]⚠ No credentials configured in credentials.yaml[/yellow]")
        raise typer.Exit(1)
    
    # Update validator with targets
    validator.targets = targets
    if output_dir:
        validator.output_dir = output_dir
    
    console.print()
    
    # Run validation with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        results = []
        
        if has_linux:
            for cred_name, linux_cred in config.credentials.linux.items():
                task = progress.add_task(f"Testing SSH: {cred_name}...", total=None)
                
                # Resolve password
                password = linux_cred.password
                if linux_cred.needs_runtime_prompt():
                    progress.stop()
                    from .ui.prompts import Prompts
                    password = Prompts.prompt_secret(
                        f"SSH password for {cred_name}",
                        "SSH_PASSWORD",
                    )
                    progress.start()
                
                if password:
                    result = validator.validate_ssh_credential(
                        cred_name,
                        linux_cred.username,
                        password,
                    )
                    results.append(result)
                
                progress.remove_task(task)
        
        if has_windows:
            for cred_name, win_cred in config.credentials.windows.items():
                task = progress.add_task(f"Testing SMB: {cred_name}...", total=None)
                
                # Resolve password
                password = win_cred.password
                if win_cred.needs_runtime_prompt():
                    progress.stop()
                    from .ui.prompts import Prompts
                    password = Prompts.prompt_secret(
                        f"Windows password for {cred_name}",
                        "WINDOWS_ADMIN_PASSWORD",
                    )
                    progress.start()
                
                if password:
                    result = validator.validate_smb_credential(
                        cred_name,
                        win_cred.username,
                        password,
                        win_cred.domain,
                    )
                    results.append(result)
                
                progress.remove_task(task)
    
    # Display results
    console.print()
    
    table = Table(title="Credential Validation Results")
    table.add_column("Credential", style="cyan")
    table.add_column("Type")
    table.add_column("Username")
    table.add_column("Success", justify="right", style="green")
    table.add_column("Failed", justify="right", style="red")
    table.add_column("Rate", justify="right")
    
    total_success = 0
    total_failed = 0
    all_failed_hosts: list[str] = []
    
    for result in results:
        rate = f"{result.success_rate:.1f}%"
        rate_style = "green" if result.success_rate >= 80 else "yellow" if result.success_rate >= 50 else "red"
        
        table.add_row(
            result.credential_name,
            result.credential_type.upper(),
            result.username,
            str(result.success_count),
            str(result.failure_count),
            f"[{rate_style}]{rate}[/{rate_style}]",
        )
        
        total_success += result.success_count
        total_failed += result.failure_count
        all_failed_hosts.extend(result.failed_hosts)
    
    console.print(table)
    
    # Write failure report if there were failures
    if all_failed_hosts:
        from .cred_validator import CredentialValidationReport
        report = CredentialValidationReport(results=results)
        report.output_file = validator._write_failure_report(report)
        
        console.print()
        console.print(Panel(
            f"[yellow]Failed hosts written to:[/yellow]\n{report.output_file}",
            title="Failure Report",
            border_style="yellow",
        ))
    
    # Summary
    console.print()
    if total_failed == 0:
        console.print("[green]✓ All credential tests passed![/green]")
    else:
        console.print(f"[yellow]⚠ {total_failed} authentication failures detected[/yellow]")


@app.command()
def configure(
    ctx: typer.Context,
    client_dir: Optional[Path] = typer.Option(
        None,
        "--client-dir",
        help="Client engagement directory (default: /client)",
    ),
) -> None:
    """Configure network interface for the engagement."""
    from .net_config import NetplanManager
    from .ui.prompts import Prompts
    from .utils.network import ConnectivityValidator
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]ENSO Network Configuration[/bold cyan]\n")

    # ── Pre-flight: Power + Interface ──────────────────────────────
    Prompts.power_gate()

    iface = config.engagement.interface
    if iface:
        Prompts.interface_gate(iface)

    # Initialize context manager to detect engagement type
    client = client_dir or config.engagement.client_dir
    context_mgr = ContextManager(config, client)
    
    try:
        context = context_mgr.build_context(interactive=True)
        console.print(f"[green]✓[/green] Engagement type: {context.engagement_type}")
        console.print(f"[green]✓[/green] Scope file: {context.scope_files.in_scope}")
        context.ensure_output_dirs()
        console.print(f"[green]✓[/green] Output directory: {context.output_dir}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Configuration cancelled[/yellow]")
        raise typer.Exit(1)
    except ValueError as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)
    
    # Get available network interfaces for manual entry
    from .utils.network import get_available_interfaces
    interfaces = get_available_interfaces()
    
    # Initialize available_ips so it's always defined for the reconfig branch below
    available_ips = []

    # Check if user requested Manual Entry or DHCP from the network drop selection
    if context.dhcp_requested:
        apply_dhcp_and_exit(interfaces)
    
    elif context.manual_entry_requested:
        # Manual entry flow
        selected_ip = Prompts.manual_ip_entry(interfaces)
    
    elif context.network_drop:
        # Use the already-selected network drop
        selected_ip = {
            "name": context.network_drop.name,
            "static_ip": context.network_drop.static_ip,
            "subnet": context.network_drop.subnet,
            "gateway": context.network_drop.gateway,
            "dns": context.network_drop.dns,
            "interface": context.network_drop.interface,
        }
        console.print(f"\n[bold cyan]Using selected network: {context.network_drop.name}[/bold cyan]")
    
    else:
        # No network drop selected yet - show IP config table with Manual/DHCP options
        # (This is for simple engagements without network drops)
        network_drops = config.engagement.network_drops
        if network_drops:
            available_ips = [
                {
                    "name": nd.name,
                    "static_ip": nd.static_ip,
                    "subnet": nd.subnet,
                    "gateway": nd.gateway,
                    "dns": nd.dns,
                    "interface": nd.interface,
                }
                for nd in network_drops
            ]
        else:
            available_ips = []
        
        if available_ips:
            selected_ip = Prompts.select_ip_config(available_ips, allow_manual=True)
            if selected_ip and selected_ip.get("_manual"):
                selected_ip = Prompts.manual_ip_entry(interfaces)
            elif selected_ip and selected_ip.get("_dhcp"):
                apply_dhcp_and_exit(interfaces)
        else:
            console.print("[yellow]No IP configurations found in config.[/yellow]")
            selected_ip = Prompts.manual_ip_entry(interfaces)
    
    if not selected_ip:
        console.print("[yellow]No IP configuration selected[/yellow]")
        raise typer.Exit(1)
    
    # Determine interface to use
    interface = selected_ip.get("interface") or config.engagement.interface

    # Apply network configuration
    console.print("\n[bold]Applying network configuration...[/bold]")

    netplan_mgr = NetplanManager(interface=interface)
    try:
        netplan_mgr.backup()
        netplan_mgr.apply_config(
            ip=selected_ip["static_ip"],
            subnet=selected_ip.get("subnet", "24"),
            gateway=selected_ip["gateway"],
            dns=selected_ip.get("dns", []),
        )
        console.print("[green]✓[/green] Network configuration applied")
    except Exception as e:
        console.print(f"[red]Failed to apply network config: {e}[/red]")
        raise typer.Exit(1)
    
    # Validate connectivity
    validator = ConnectivityValidator()

    # ── Ping Validation ─────────────────────────────────────────────
    console.print("\n[bold cyan]Ping Validation[/bold cyan]")
    console.print("[dim]Validating network connectivity with ping commands...[/dim]\n")

    while True:
        console.print(f"Pinging gateway {selected_ip['gateway']}...")
        if not validator.ping_gateway(selected_ip["gateway"]):
            action = Prompts.connectivity_failure_menu()
            if action == "exit":
                raise typer.Exit(1)
            elif action == "retry":
                continue
            elif action == "reconfig":
                if available_ips:
                    selected_ip = Prompts.select_ip_config(available_ips)
                    if selected_ip:
                        netplan_mgr.apply_config(
                            ip=selected_ip["static_ip"],
                            subnet=selected_ip.get("subnet", "24"),
                            gateway=selected_ip["gateway"],
                            dns=selected_ip.get("dns", []),
                        )
                continue
            elif action == "manual":
                selected_ip = Prompts.manual_ip_entry()
                netplan_mgr.apply_config(
                    ip=selected_ip["static_ip"],
                    subnet=selected_ip.get("subnet", "24"),
                    gateway=selected_ip["gateway"],
                    dns=selected_ip.get("dns", []),
                )
                continue

        console.print("[green]✓[/green] Gateway reachable")
        break

    # Random host pings
    scope_hosts = context.scope_files.load_in_scope_hosts()
    ping_count = config.global_config.resolve_ping_count(len(scope_hosts))
    threshold = config.global_config.reachability_threshold

    console.print(f"Pinging {ping_count} random hosts from scope...")
    successful, total = validator.ping_random_hosts(context.scope_files.in_scope, count=ping_count)
    if total > 0:
        success_rate = successful / total
        if successful == 0:
            console.print(f"[red]✗[/red] Random host check: {successful}/{total} reachable")
            console.print("[bold red]ERROR: No hosts were reachable. Please verify network connectivity.[/bold red]")
            console.print("[yellow]Check that:[/yellow]")
            console.print("  • Network cable is connected")
            console.print("  • IP configuration is correct")
            console.print("  • Target hosts are online")
            raise typer.Exit(1)
        elif success_rate < threshold:
            console.print(f"[yellow]![/yellow] Random host check: {successful}/{total} reachable (below {int(threshold*100)}% threshold)")
        else:
            console.print(f"[green]✓[/green] Random host check: {successful}/{total} reachable")

    # ── DNS Validation ──────────────────────────────────────────────
    dns_servers = selected_ip.get("dns", [])
    if dns_servers:
        fqdns = Prompts.prompt_fqdn()
        if fqdns:
            dns_server = dns_servers[0] if dns_servers else None
            resolved_count = 0
            for fqdn in fqdns:
                result = validator.resolve_fqdn(fqdn, dns_server)
                if result:
                    console.print(f"[green]✓[/green] DNS resolution: {fqdn} -> {result}")
                    resolved_count += 1
                else:
                    console.print(f"[yellow]![/yellow] DNS resolution failed for {fqdn}")
            console.print(
                f"\n[bold]Name Resolution results: {resolved_count}/{len(fqdns)} resolved[/bold]"
            )
    
    console.print("\n[bold green]Network configuration complete![/bold green]")


@app.command()
def scan(
    ctx: typer.Context,
    client_dir: Optional[Path] = typer.Option(
        None,
        "--client-dir",
        help="Client engagement directory",
    ),
    network: Optional[str] = typer.Option(
        None,
        "--network",
        help="Pre-select network drop by name (skips network selection prompt)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would be done without executing",
    ),
    top_ports: Optional[int] = typer.Option(
        None,
        "--top-ports",
        help="Scan only top N ports instead of all ports",
    ),
    skip_nessus: bool = typer.Option(
        False,
        "--skip-nessus",
        help="Skip Nessus scan",
    ),
    skip_preflight: bool = typer.Option(
        False,
        "--skip-preflight",
        help="Skip pre-flight checks (network config, Nessus validation)",
    ),
) -> None:
    """Launch scanning workflow based on execution strategy."""
    from rich.prompt import Confirm
    from .orchestrator import ScanOrchestrator
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]ENSO Scanning Workflow[/bold cyan]\n")
    
    # Determine if we need interactive network selection
    engagement_type = config.engagement.engagement_type
    needs_network_config = False
    
    # Step 1: Network configuration prompt (only if not skipped and not pre-selected)
    if not skip_preflight and not network:
        needs_network_config = Confirm.ask(
            "Do you need to configure network settings?",
            default=False,
        )
        if needs_network_config:
            console.print("\n[dim]Running network configuration...[/dim]\n")
            # Invoke configure command - must explicitly pass client_dir to avoid OptionInfo bug
            ctx.invoke(configure, ctx=ctx, client_dir=None)
            console.print()
    
    # Pre-flight gates — always check unless preflight is skipped
    if not skip_preflight:
        from .ui.prompts import Prompts as _Prompts
        _Prompts.power_gate()

        iface = config.engagement.interface
        if iface:
            _Prompts.interface_gate(iface)

    # Build engagement context
    client = client_dir or config.engagement.client_dir
    context_mgr = ContextManager(config, client)
    
    try:
        # Only use interactive mode if:
        # 1. Complex engagement AND user said "yes" to network config, OR
        # 2. Complex engagement AND no network pre-selected AND user said "yes" to network config
        # Otherwise use non-interactive (first network drop or pre-selected)
        if network:
            # Pre-selected network - find and set context for that network
            context = context_mgr.build_context_for_network(network)
        elif engagement_type == "complex" and needs_network_config:
            # User wants to configure/select network
            context = context_mgr.build_context(interactive=True)
        else:
            # Simple engagement or complex with no network config needed
            context = context_mgr.build_context(interactive=False)
    except (KeyboardInterrupt, ValueError) as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)
    
    # Load hosts
    hosts = context.scope_files.load_in_scope_hosts()
    if not hosts:
        console.print("[red]No hosts found in scope file[/red]")
        raise typer.Exit(1)
    
    console.print(f"[green]✓[/green] Loaded {len(hosts)} hosts from scope")
    
    # Step 2: Disable Nessus module if --skip-nessus flag
    if skip_nessus:
        nessus_module = config.global_config.get_module_by_name("nessus")
        if nessus_module:
            nessus_module.enabled = False
    
    # Step 3: Run pre-flight checks (Nessus validation if enabled)
    if not skip_preflight:
        if not run_pre_flight_checks(config):
            console.print("\n[red]Pre-flight checks failed. Aborting.[/red]")
            raise typer.Exit(1)
    
    # Step 3b: Check Nessus policy credentials (only if Nessus is enabled)
    nessus_enabled = any(
        m.name == "nessus" and m.enabled 
        for m in config.global_config.scan_pipeline
    )
    
    if nessus_enabled and not skip_nessus and not skip_preflight:
        sync_nessus_credentials(config)

    # Step 3c: Optional credential check
    if nessus_enabled and not skip_nessus and not skip_preflight:
        run_credential_check(config, context)

    # Step 4: Display pipeline summary
    console.print()
    display_pipeline_summary(config)
    console.print()
    
    # Step 5: Dry run handling
    if dry_run:
        console.print("[yellow]Dry run mode - no scans will be executed[/yellow]")
        console.print(f"Would scan: {hosts[:5]}{'...' if len(hosts) > 5 else ''}")
        raise typer.Exit(0)
    
    # Step 6: Confirmation
    if not skip_preflight:
        proceed = Confirm.ask("Proceed with scan?", default=True)
        if not proceed:
            console.print("[yellow]Scan cancelled by user[/yellow]")
            raise typer.Exit(0)
    
    # Step 7: Execute scan
    module_dirs = [m.get_output_dir() for m in config.global_config.get_enabled_modules()]
    module_dirs.append(config.nmap.log_dir)
    module_dirs.append(config.global_config.cred_check_dir)
    context.ensure_output_dirs(module_dirs)
    orchestrator = ScanOrchestrator(
        config=config,
        context=context,
        skip_nessus=skip_nessus,
        top_ports=top_ports,
    )
    
    try:
        orchestrator.run(hosts)
        console.print("\n[bold green]Scanning complete![/bold green]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        logger.exception("Scan failed")
        console.print(f"\n[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


def _interactive_nessus_export(config: EnsoConfig, nessus_dir: Path) -> list[Path]:
    """Connect to Nessus, list scans, prompt for selection, export.

    Returns list of exported file paths.
    """
    from rich.table import Table
    from rich.prompt import Confirm
    from .nessus_bridge import NessusBridge

    bridge = NessusBridge(config.nessus, credentials=config.credentials)
    if not bridge.connect():
        console.print("[red]Failed to connect to Nessus[/red]")
        return []

    recent = bridge.list_recent_scans(limit=20)
    if not recent:
        console.print("[yellow]No scans found on Nessus server[/yellow]")
        return []

    table = Table(title="Available Nessus Scans")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Status")

    for scan in recent:
        status_str = scan["status"]
        style = "green" if status_str == "completed" else "yellow"
        table.add_row(
            str(scan["id"]),
            scan["name"],
            f"[{style}]{status_str}[/{style}]",
        )

    console.print(table)
    console.print()

    raw = Prompt.ask("Enter scan ID(s) to export (comma-separated)")
    try:
        id_list = [int(x.strip()) for x in raw.split(",")]
    except ValueError:
        console.print("[red]Invalid input. Use comma-separated integers.[/red]")
        return []

    name_lookup = {s["id"]: s["name"] for s in recent}
    nessus_dir.mkdir(parents=True, exist_ok=True)
    exported: list[Path] = []

    for sid in id_list:
        scan_name = name_lookup.get(sid)
        if not scan_name:
            info = bridge.get_scan_status(sid)
            scan_name = info.get("name")
            if not scan_name or scan_name == "Unknown":
                scan_name = None

        result = bridge.export_scan(sid, nessus_dir, scan_name=scan_name)
        if result:
            size_kb = result.stat().st_size / 1024
            console.print(
                f"[green]  ✓ {result.name}[/green] [dim]({size_kb:.1f} KB)[/dim]"
            )
            exported.append(result)
        else:
            console.print(f"[red]  ✗ Export failed for scan {sid}[/red]")

    return exported


@app.command()
def export(
    ctx: typer.Context,
    export_dir: Optional[Path] = typer.Option(
        None,
        "--export-dir",
        "-e",
        help="Directory to save the zip (prompts with tab completion if not set)",
    ),
    client_dir: Optional[Path] = typer.Option(
        None,
        "--client-dir",
        help="Client engagement directory",
    ),
    network: Optional[str] = typer.Option(
        None,
        "--network",
        help="Pre-select network drop by name (complex engagements)",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Export all files (ignore previous export history)",
    ),
    skip_nessus: bool = typer.Option(
        False,
        "--skip-nessus",
        help="Skip Nessus export prompt",
    ),
) -> None:
    """Package scan results into a zip file for delivery.

    Collects nmap and nessus scan results, optionally exports pending
    Nessus scans, and creates a zip archive.  Tracks exported files
    so subsequent runs only include new or changed results.
    """
    from rich.prompt import Confirm
    from rich.table import Table
    from .exporter import ExportManifest, ScanExporter
    from .ui.prompts import Prompts as _Prompts

    config: EnsoConfig = ctx.obj["config"]

    console.print("\n[bold cyan]ENSO Scan Export[/bold cyan]\n")

    # Step 1: Build engagement context
    client = client_dir or config.engagement.client_dir
    context_mgr = ContextManager(config, client)

    try:
        if network:
            context = context_mgr.build_context_for_network(network)
        elif config.engagement.engagement_type == "complex":
            context = context_mgr.build_context(interactive=True)
        else:
            context = context_mgr.build_context(interactive=False)
    except (KeyboardInterrupt, ValueError) as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)

    # Step 2: Derive network_id
    if context.network_drop:
        network_id = context.network_drop.get_network_dir()
    else:
        network_id = context.output_dir.name

    console.print(f"[dim]Network: {network_id}[/dim]")
    console.print(f"[dim]Scans directory: {context.scans_dir}[/dim]\n")

    # Step 3: Create exporter
    exporter = ScanExporter(
        context.scans_dir,
        network_id,
        exclude_dirs=config.global_config.export_exclude_dirs,
    )

    # Step 4: Nessus integration
    nessus_output_dir = config.global_config.get_module_output_dir("nessus")
    if not skip_nessus:
        existing_nessus = exporter.get_nessus_files(nessus_output_dir)

        if not existing_nessus:
            console.print("[yellow]No .nessus exports found in scan results[/yellow]")
            if Confirm.ask("Export Nessus scan(s) now?", default=True):
                _interactive_nessus_export(config, context.get_module_dir(nessus_output_dir))
                console.print()
        else:
            console.print(
                f"[green]Found {len(existing_nessus)} .nessus file(s):[/green]"
            )
            for f in existing_nessus:
                size_kb = f.stat().st_size / 1024
                console.print(f"  {f.name} [dim]({size_kb:.1f} KB)[/dim]")

            if Confirm.ask("\nExport additional Nessus scans?", default=False):
                _interactive_nessus_export(config, context.get_module_dir(nessus_output_dir))
                console.print()

    # Step 5: Collect all files
    all_files = exporter.collect_files()

    if not all_files:
        console.print("[yellow]No scan files found to export[/yellow]")
        raise typer.Exit(0)

    # Step 6: Differential check
    if full:
        files_to_export = all_files
        console.print(f"[bold]Full export: {len(files_to_export)} file(s)[/bold]")
    else:
        manifest = ExportManifest.load(context.scans_dir)
        files_to_export = exporter.filter_new_or_changed(all_files, manifest)

        if not files_to_export:
            console.print(
                "[green]Nothing new to export since last run.[/green]\n"
                "[dim]Use --full to re-export everything.[/dim]"
            )
            raise typer.Exit(0)

        if manifest.exports:
            console.print(
                f"[bold]{len(files_to_export)} new/changed file(s) "
                f"since last export[/bold] "
                f"[dim]({len(all_files)} total on disk)[/dim]"
            )
            while True:
                choice = Prompt.ask(
                    "Export [y]new only / [n]full / [l]list changed",
                    choices=["y", "n", "l"],
                    default="y",
                )
                if choice == "l":
                    for f in files_to_export:
                        size_kb = f.size / 1024
                        console.print(
                            f"  {f.relative_path} [dim]({size_kb:.1f} KB)[/dim]"
                        )
                    console.print()
                    continue
                break
            if choice == "n":
                files_to_export = all_files
                full = True
                console.print(
                    f"[bold]Full export: {len(files_to_export)} file(s)[/bold]"
                )
        else:
            console.print(f"[bold]{len(files_to_export)} file(s) to export[/bold]")

    # Step 7: Summary table
    categories: dict[str, int] = {}
    for f in files_to_export:
        cat = f.relative_path.split("/")[0]
        categories[cat] = categories.get(cat, 0) + 1

    table = Table(title="Export Contents", show_lines=False)
    table.add_column("Category", style="cyan")
    table.add_column("Files", justify="right")
    for cat, count in sorted(categories.items()):
        table.add_row(cat, str(count))
    console.print(table)
    console.print()

    # Step 8: Resolve export directory
    if export_dir is None:
        try:
            export_dir = _Prompts.prompt_export_dir(default="~/Downloads")
        except KeyboardInterrupt:
            console.print("\n[yellow]Export cancelled[/yellow]")
            raise typer.Exit(1)

    # Step 9: Create zip
    try:
        result = exporter.create_zip(files_to_export, export_dir, full_export=full)
    except Exception as e:
        console.print(f"[red]Failed to create zip: {e}[/red]")
        raise typer.Exit(1)

    # Step 10: Update manifest
    if not full:
        manifest.record_export(result.zip_path.name, files_to_export)
        manifest.save(context.scans_dir)

    # Step 11: Success
    console.print(f"\n[green]✓ Export complete: {result.zip_path}[/green]")
    console.print(
        f"[dim]{result.file_count} files, "
        f"{result.total_size / 1024:.1f} KB -> "
        f"{result.zip_size / 1024:.1f} KB compressed[/dim]"
    )
    if result.is_differential:
        console.print("[dim]Differential export (new/changed files only)[/dim]")


@app.command()
def status(
    ctx: typer.Context,
    scan_id: Optional[str] = typer.Argument(
        None,
        help="Nessus scan ID to check (default: latest)",
    ),
) -> None:
    """Check Nessus scan status."""
    from .nessus_bridge import NessusBridge
    
    config: EnsoConfig = ctx.obj["config"]
    
    console.print("\n[bold cyan]Nessus Scan Status[/bold cyan]\n")
    
    try:
        bridge = NessusBridge(config.nessus)
        
        if scan_id:
            status = bridge.get_scan_status(scan_id)
        else:
            # Get latest scan
            scans = bridge.list_recent_scans(limit=5)
            if not scans:
                console.print("[yellow]No Nessus scans found[/yellow]")
                raise typer.Exit(0)
            
            # Display recent scans
            from rich.table import Table
            table = Table(title="Recent Scans")
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Status")
            table.add_column("Progress")
            
            for scan in scans:
                table.add_row(
                    str(scan["id"]),
                    scan["name"],
                    scan["status"],
                    f"{scan.get('progress', 0)}%",
                )
            
            console.print(table)
    except Exception as e:
        console.print(f"[red]Failed to get Nessus status: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
