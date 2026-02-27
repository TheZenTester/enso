"""CLI helper functions extracted from cli.py to reduce module size."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.prompt import IntPrompt, Prompt

from .config import EnsoConfig
from .utils.logging import get_logger

console = Console()
logger = get_logger(__name__)


def display_pipeline_summary(config: EnsoConfig) -> None:
    """Display visual scan pipeline summary."""
    from rich.panel import Panel
    from rich.tree import Tree

    global_cfg = config.global_config
    enabled_modules = global_cfg.get_enabled_modules()
    strategy = global_cfg.execution_strategy

    if not enabled_modules:
        console.print("[yellow]No scan modules enabled[/yellow]")
        return

    if strategy == "linear":
        # Linear: show sequential list with arrows
        lines = [f"[bold]Scan Plan ({strategy})[/bold]", ""]
        for i, module in enumerate(enabled_modules):
            prefix = "  " if i == 0 else "    \u2193\n  "
            lines.append(f"{prefix}{i+1}. [cyan]{module.name}[/cyan] - {module.description}")

        panel = Panel(
            "\n".join(lines),
            border_style="cyan",
        )
        console.print(panel)
    else:
        # Concurrent: show dependency tree with stages
        tree = Tree(f"[bold]Scan Plan ({strategy})[/bold]")

        # Track which modules have been added to avoid duplicates
        added_modules: set[str] = set()

        def get_dependents(module_name: str) -> list:
            """Get all modules that depend on the given module."""
            return [m for m in enabled_modules if module_name in m.depends_on]

        def add_dependents_recursively(parent_node, module):
            """Recursively add all modules that depend on this one."""
            dependents = get_dependents(module.name)

            for dep in dependents:
                # Skip if already added (for modules with multiple dependencies,
                # we only add under first parent to avoid duplication)
                if dep.name in added_modules:
                    continue

                # Format the node label
                if len(dep.depends_on) > 1:
                    deps_str = ", ".join(dep.depends_on)
                    label = f"[green]{dep.name}[/green] - {dep.description} [dim](after: {deps_str})[/dim]"
                else:
                    label = f"[green]{dep.name}[/green] - {dep.description}"

                # Add to tree and mark as added
                dep_node = parent_node.add(label)
                added_modules.add(dep.name)

                # Recursively add modules that depend on THIS module
                add_dependents_recursively(dep_node, dep)

        # Start with root modules (no dependencies)
        root_modules = [m for m in enabled_modules if not m.depends_on]

        for root in root_modules:
            root_node = tree.add(f"[cyan]{root.name}[/cyan] - {root.description}")
            added_modules.add(root.name)
            # Add all modules that depend on this root
            add_dependents_recursively(root_node, root)

        # Add any orphaned modules (dependencies not enabled/defined)
        for module in enabled_modules:
            if module.name not in added_modules:
                missing = [d for d in module.depends_on
                          if not global_cfg.get_module_by_name(d) or not global_cfg.get_module_by_name(d).enabled]
                if missing:
                    tree.add(f"[yellow]{module.name}[/yellow] - {module.description} [dim](missing: {', '.join(missing)})[/dim]")
                else:
                    tree.add(f"[yellow]{module.name}[/yellow] - {module.description}")

        panel = Panel(
            tree,
            border_style="cyan",
        )
        console.print(panel)


def run_pre_flight_checks(config: EnsoConfig) -> bool:
    """Run pre-flight checks before scanning.

    Returns:
        True if all checks passed, False otherwise
    """
    from rich.prompt import Confirm

    global_cfg = config.global_config

    # Check if Nessus is enabled in pipeline
    nessus_module = global_cfg.get_module_by_name("nessus")
    if nessus_module and nessus_module.enabled:
        console.print("\n[bold]Nessus Validation[/bold]")

        from .nessus_validator import NessusValidator
        validator = NessusValidator(config)
        report = validator.validate_all()
        validator.display_report(report)

        if not report.all_passed:
            continue_without = Confirm.ask(
                "\n[yellow]Nessus validation failed. Continue without Nessus?[/yellow]",
                default=False,
            )
            if continue_without:
                # Disable Nessus module for this run
                nessus_module.enabled = False
                console.print("[dim]Nessus disabled for this scan[/dim]")
            else:
                return False

    return True


def sync_nessus_credentials(config: EnsoConfig) -> None:
    """Check and sync Nessus policy credentials with credentials.yaml.

    If credentials differ, prompts user to update the policy.
    """
    from rich.prompt import Confirm
    from rich.table import Table
    from .nessus_policy import NessusPolicyManager

    policy_name = config.nessus.policy_mapping.default

    console.print(f"\n[bold]Checking Nessus Policy Credentials[/bold]")
    console.print(f"[dim]Policy: {policy_name}[/dim]")

    # Check if we have any credentials configured
    has_creds = bool(config.credentials.linux) or bool(config.credentials.windows)
    if not has_creds:
        console.print("[dim]No credentials configured in credentials.yaml[/dim]")
        return

    try:
        manager = NessusPolicyManager(config.nessus)

        # Check if credentials match
        if manager.credentials_match(policy_name, config.credentials):
            console.print("[green]\u2713[/green] Policy credentials match credentials.yaml")
            return

        # Show what differs
        console.print("[yellow]\u26a0 Policy credentials differ from credentials.yaml[/yellow]")

        # Show comparison table
        policy_summary = manager.get_credential_summary(policy_name)
        local_win_count = len(config.credentials.windows)
        local_ssh_count = len(config.credentials.linux)

        table = Table(show_header=True, header_style="bold")
        table.add_column("Type")
        table.add_column("Policy")
        table.add_column("credentials.yaml")

        table.add_row(
            "Windows",
            f"{policy_summary['windows_count']} ({', '.join(policy_summary['windows_users']) or 'none'})",
            f"{local_win_count} ({', '.join(c.username for c in config.credentials.windows.values()) or 'none'})",
        )
        table.add_row(
            "SSH",
            f"{policy_summary['ssh_count']} ({', '.join(policy_summary['ssh_users']) or 'none'})",
            f"{local_ssh_count} ({', '.join(c.username for c in config.credentials.linux.values()) or 'none'})",
        )

        console.print(table)

        # Prompt to update
        update = Confirm.ask(
            "\nUpdate Nessus policy with credentials from credentials.yaml?",
            default=True,
        )

        if update:
            # Let user select which credentials to push
            from .ui.prompts import Prompts
            win_names, lin_names = Prompts.select_credentials(
                config.credentials.windows, config.credentials.linux,
            )
            if not win_names and not lin_names:
                console.print("[dim]No credentials selected — skipping sync[/dim]")
                return

            filtered_creds = config.credentials.filter_by_names(win_names, lin_names)

            # Always offer to clear existing credentials first
            delete_ids: list[int] | None = None

            if Confirm.ask(
                "Remove existing credentials from policy before adding?",
                default=True,
            ):
                delete_ids = manager.get_policy_credential_ids(policy_name)
                if delete_ids:
                    console.print(
                        f"[dim]Will remove {len(delete_ids)} existing "
                        f"credential(s) before adding[/dim]"
                    )
                else:
                    console.print(
                        "[yellow]Could not find credential IDs to delete "
                        "— credentials will be added alongside existing ones. "
                        "Remove duplicates manually via the Nessus web UI.[/yellow]"
                    )

            console.print("[dim]Updating policy credentials...[/dim]")
            if manager.update_policy_credentials(
                policy_name, filtered_creds, delete_ids=delete_ids
            ):
                console.print("[green]\u2713 Policy credentials updated[/green]")
            else:
                console.print("[red]\u2717 Failed to update policy credentials[/red]")
        else:
            console.print("[dim]Proceeding with existing policy credentials[/dim]")

    except Exception as e:
        logger.warning(f"Could not check policy credentials: {e}")
        console.print(f"[yellow]\u26a0 Could not check policy credentials: {e}[/yellow]")


def run_credential_check(config: EnsoConfig, context) -> bool:
    """Optionally test credentials against in-scope hosts with nxc.

    Prompts the user (default No). If accepted, runs nxc validation for each
    enabled credential and prints a summary table. Report files are written
    to ``{context.scans_dir}/cred_checks/``.

    This is non-blocking: always returns True so the caller can proceed to
    the existing "Proceed with scan?" confirmation gate.

    Args:
        config: ENSO configuration
        context: EngagementContext with scope_files and scans_dir

    Returns:
        True always (non-blocking)
    """
    from datetime import datetime

    from rich.prompt import Confirm
    from rich.table import Table

    from .cred_validator import CredentialValidator

    # Prompt — default No
    if not Confirm.ask(
        "\nTest credentials against in-scope hosts with nxc?",
        default=False,
    ):
        return True

    # Check nxc availability
    validator = CredentialValidator(
        credentials=config.credentials,
        targets=[],
        output_dir=context.scans_dir,
        cred_check_subdir=config.global_config.cred_check_dir,
    )

    if not validator.check_nxc_available():
        console.print(
            "[yellow]nxc (NetExec) not found — skipping credential check[/yellow]"
        )
        return True

    # Load hosts
    hosts = context.scope_files.load_in_scope_hosts()
    if not hosts:
        console.print("[yellow]No in-scope hosts found — skipping credential check[/yellow]")
        return True

    validator.targets = hosts
    timestamp = datetime.now()
    results = []
    report_dir = context.scans_dir / config.global_config.cred_check_dir

    # Iterate enabled credentials
    for cred_name, linux_cred in config.credentials.linux.items():
        if not linux_cred.enabled:
            continue

        password = linux_cred.password
        if linux_cred.needs_runtime_prompt():
            from .ui.prompts import Prompts

            password = Prompts.prompt_secret(
                f"SSH password for {cred_name}", "SSH_PASSWORD"
            )
        if not password:
            continue

        console.print(f"[dim]Testing SSH credential: {cred_name}...[/dim]")
        result = validator.validate_ssh_credential(cred_name, linux_cred.username, password)
        validator._write_full_report(result, timestamp=timestamp)
        results.append(result)

    for cred_name, win_cred in config.credentials.windows.items():
        if not win_cred.enabled:
            continue

        password = win_cred.password
        if win_cred.needs_runtime_prompt():
            from .ui.prompts import Prompts

            password = Prompts.prompt_secret(
                f"Windows password for {cred_name}", "WINDOWS_ADMIN_PASSWORD"
            )
        if not password:
            continue

        console.print(f"[dim]Testing SMB credential: {cred_name}...[/dim]")
        result = validator.validate_smb_credential(
            cred_name, win_cred.username, password, win_cred.domain
        )
        validator._write_full_report(result, timestamp=timestamp)
        results.append(result)

    if not results:
        console.print("[dim]No enabled credentials to test[/dim]")
        return True

    # Summary table
    console.print("\n[bold]Credential Check Results[/bold]\n")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("Responded", justify="right")
    table.add_column("Passed", justify="right", style="green")
    table.add_column("Failed", justify="right", style="red")

    ssh_responded = 0
    ssh_passed = 0
    smb_responded = 0
    smb_passed = 0

    for r in results:
        responded = r.success_count + r.failure_count
        table.add_row(
            r.credential_type.upper(),
            r.credential_name,
            r.username,
            str(responded),
            str(r.success_count),
            str(r.failure_count),
        )
        if r.credential_type == "ssh":
            ssh_responded += responded
            ssh_passed += r.success_count
        else:
            smb_responded += responded
            smb_passed += r.success_count

    console.print(table)

    # Per-service summary lines
    if ssh_responded:
        console.print(
            f"\nSSH: {ssh_passed}/{ssh_responded} hosts with SSH enabled passed authentication"
        )
    if smb_responded:
        console.print(
            f"SMB: {smb_passed}/{smb_responded} hosts with SMB enabled passed authentication"
        )

    console.print(f"\nResults written to: {report_dir}/")
    return True


def apply_dhcp_and_exit(interfaces: list[str]) -> None:
    """Prompt for interface, apply DHCP config, and exit.

    Args:
        interfaces: Available network interfaces for selection
    """
    from .net_config import NetplanManager

    console.print("\n[bold cyan]DHCP Configuration[/bold cyan]\n")
    if interfaces:
        console.print("Available interfaces:")
        for i, iface in enumerate(interfaces, 1):
            console.print(f"  [{i}] {iface}")
        while True:
            iface_choice = IntPrompt.ask("Select interface", default=1)
            if 1 <= iface_choice <= len(interfaces):
                dhcp_interface = interfaces[iface_choice - 1]
                break
            console.print(f"[red]Please enter 1-{len(interfaces)}[/red]")
    else:
        dhcp_interface = Prompt.ask("Interface name (e.g., eth0)", default="eth0")

    console.print("\n[bold]Applying DHCP configuration...[/bold]")
    netplan_mgr = NetplanManager(interface=dhcp_interface)
    try:
        netplan_mgr.backup()
        netplan_mgr.apply_dhcp_config()
        console.print("[green]\u2713[/green] DHCP configuration applied")
    except Exception as e:
        console.print(f"[red]Failed to apply DHCP config: {e}[/red]")
        raise typer.Exit(1)

    console.print("\n[bold green]Network configuration complete (DHCP)![/bold green]")
    raise typer.Exit(0)
