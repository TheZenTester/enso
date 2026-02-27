"""Interactive prompts using Rich."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.panel import Panel

console = Console()


class Prompts:
    """Interactive prompts for user input during ENSO operations."""
    
    @staticmethod
    def select_network_drop(networks: list[dict]) -> int:
        """Prompt user to select a network drop for complex engagements.
        
        Args:
            networks: List of network drop configurations with 'name' key
            
        Returns:
            Zero-based index of selected network, or:
            -1 for Manual Entry
            -2 for DHCP
        """
        console.print("\n[bold cyan]Select Network Drop to Scan:[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Network Name", style="cyan")
        table.add_column("Interface", style="magenta")
        table.add_column("Static IP", style="green")
        table.add_column("Gateway", style="yellow")
        
        # Add configured networks
        for i, network in enumerate(networks, 1):
            table.add_row(
                str(i),
                network.get("name", "Unknown"),
                network.get("interface", "auto"),
                network.get("static_ip", "N/A"),
                network.get("gateway", "N/A"),
            )
        
        # Add Manual Entry option
        manual_idx = len(networks) + 1
        table.add_row(
            str(manual_idx),
            "[italic]Manual Entry[/italic]",
            "—",
            "—",
            "—",
        )
        
        # Add DHCP option
        dhcp_idx = len(networks) + 2
        table.add_row(
            str(dhcp_idx),
            "[italic]DHCP[/italic]",
            "auto",
            "auto",
            "auto",
        )
        
        console.print(table)
        console.print()
        
        max_choice = dhcp_idx
        while True:
            choice = IntPrompt.ask(
                "Enter selection",
                default=1,
            )
            if 1 <= choice <= max_choice:
                if choice == manual_idx:
                    return -1  # Manual entry
                elif choice == dhcp_idx:
                    return -2  # DHCP
                else:
                    return choice - 1  # Network index
            console.print(f"[red]Please enter a number between 1 and {max_choice}[/red]")
    
    @staticmethod
    def _check_ac_power() -> bool:
        """Check if the laptop is connected to AC power.
        
        Reads from /sys/class/power_supply/ to detect AC adapter status.
        Works on Ubuntu/Linux systems.
        
        Returns:
            True if on AC power, False if on battery
        """
        power_supply_path = Path("/sys/class/power_supply")
        
        if not power_supply_path.exists():
            return True  # Assume plugged in if can't check (e.g., desktop)
        
        # Look for AC adapter
        for supply in power_supply_path.iterdir():
            supply_type_file = supply / "type"
            if supply_type_file.exists():
                supply_type = supply_type_file.read_text().strip().lower()
                if supply_type == "mains":
                    # Found AC adapter, check if online
                    online_file = supply / "online"
                    if online_file.exists():
                        online = online_file.read_text().strip()
                        return online == "1"
        
        # No AC adapter found - might be a desktop, assume OK
        return True
    
    @staticmethod
    def power_gate() -> bool:
        """Check AC power status and prompt user if on battery.
        
        Displays power status panel and waits for user to plug in if needed.
        
        Returns:
            True if power check passed (on AC or user confirmed after plugging in)
        """
        console.print()
        
        # Check current power status
        on_ac_power = Prompts._check_ac_power()
        
        if on_ac_power:
            panel = Panel(
                "[bold green]✓ AC Power Connected[/bold green]\n\n"
                "[dim]Laptop is plugged into AC power. Proceeding...[/dim]",
                title="[bold cyan]Power Status[/bold cyan]",
                border_style="green",
            )
            console.print(panel)
            return True
        
        # Not on AC power - prompt user
        panel = Panel(
            "[bold red]⚠ Running on Battery![/bold red]\n\n"
            "[yellow]Please connect the laptop to AC power before proceeding.\n"
            "Long-running scans may drain the battery and cause unexpected shutdowns.[/yellow]",
            title="[bold red]Power Status[/bold red]",
            border_style="red",
        )
        console.print(panel)
        
        # Wait for user to plug in
        while True:
            Prompt.ask("\n[bold]Press Enter after connecting to AC power[/bold]")
            
            # Re-check power status
            if Prompts._check_ac_power():
                console.print("[green]✓ AC power detected. Proceeding...[/green]\n")
                return True
            else:
                console.print("[red]Still on battery. Please connect AC power.[/red]")
    
    @staticmethod
    def interface_gate(interface: str) -> bool:
        """Verify that the expected network interface has a physical link.

        Reads carrier state from ``/sys/class/net/`` and loops until
        the cable is detected.  Mirrors the UX of ``power_gate()``.

        Args:
            interface: Interface name (e.g. ``eth0``)

        Returns:
            True once link is confirmed
        """
        from ..utils.network import check_interface_link

        console.print()
        status = check_interface_link(interface)

        if not status["exists"]:
            panel = Panel(
                f"[bold red]Interface not found: {interface}[/bold red]\n\n"
                "[yellow]The configured interface does not exist on this system.\n"
                "Check engagement.yaml or verify the adapter is connected.[/yellow]",
                title="[bold red]Interface Check[/bold red]",
                border_style="red",
            )
            console.print(panel)

            while True:
                Prompt.ask("\n[bold]Press Enter after validating the Ethernet adapter is connected securely[/bold]")

                status = check_interface_link(interface)
                if status["exists"]:
                    console.print(f"[green]Ethernet adapter detected on {interface}.[/green]")
                    break

                console.print(f"[red]Interface {interface} still not found. Please check the adapter.[/red]")

        if status["carrier"]:
            panel = Panel(
                f"[bold green]Ethernet Link Detected on {interface}[/bold green]\n\n"
                f"[dim]Operstate: {status['operstate']}[/dim]",
                title="[bold cyan]Interface Check[/bold cyan]",
                border_style="green",
            )
            console.print(panel)
            return True

        # No carrier — cable not connected or half-plugged
        panel = Panel(
            f"[bold red]No link detected on {interface}[/bold red]\n\n"
            f"[yellow]Operstate: {status['operstate']}\n"
            "The ethernet cable may be unplugged or not fully seated.[/yellow]",
            title="[bold red]Interface Check[/bold red]",
            border_style="red",
        )
        console.print(panel)

        while True:
            Prompt.ask("\n[bold]Press Enter after validating the Ethernet cable is connected securely[/bold]")

            status = check_interface_link(interface)
            if status["carrier"]:
                console.print(f"[green]Ethernet link detected on {interface}. Proceeding...[/green]\n")
                return True

            console.print(f"[red]Still no link on {interface}. Check the cable.[/red]")

    @staticmethod
    def physical_gate(network_name: str) -> bool:
        """Prompt user to confirm physical connection to network.
        
        Args:
            network_name: Name of the network to connect to
            
        Returns:
            True if user confirms connection
        """
        panel = Panel(
            f"[bold yellow]Please physically connect to:[/bold yellow]\n\n"
            f"[bold white]{network_name}[/bold white]\n\n"
            "[dim]Ensure the network cable is connected and link is active.[/dim]",
            title="[bold red]Physical Connection Required[/bold red]",
            border_style="red",
        )
        console.print(panel)
        
        return Confirm.ask("Ready to proceed?", default=True)
    
    @staticmethod
    def select_ip_config(
        available_ips: list[dict],
        allow_manual: bool = True,
    ) -> dict | None:
        """Prompt user to select or enter IP configuration.
        
        Args:
            available_ips: List of available IP configurations
            allow_manual: Whether to allow manual entry
            
        Returns:
            Selected or manually entered IP config dict, or None if cancelled
        """
        console.print("\n[bold cyan]Available IP Configurations:[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="white")
        table.add_column("Interface", style="magenta")
        table.add_column("IP Address", style="green")
        table.add_column("Subnet/Netmask", style="cyan")
        table.add_column("Gateway", style="yellow")
        table.add_column("DNS", style="blue")
        
        for i, ip_config in enumerate(available_ips, 1):
            dns_list = ip_config.get("dns", [])
            dns_str = ", ".join(dns_list) if dns_list else "N/A"
            iface = ip_config.get("interface") or "auto"
            subnet = ip_config.get("subnet", "24")
            name = ip_config.get("name", f"Config {i}")
            
            table.add_row(
                str(i),
                name,
                iface,
                ip_config.get("static_ip", "N/A"),
                subnet,
                ip_config.get("gateway", "N/A"),
                dns_str,
            )
        
        # Track extra options
        extra_options = 0
        
        if allow_manual:
            extra_options += 1
            table.add_row(
                str(len(available_ips) + extra_options),
                "[italic]Manual Entry[/italic]",
                "—",
                "—",
                "—",
                "—",
                "—",
            )
        
        # Add DHCP option
        extra_options += 1
        dhcp_idx = len(available_ips) + extra_options
        table.add_row(
            str(dhcp_idx),
            "[italic]DHCP[/italic]",
            "[dim]auto[/dim]",
            "[dim]auto[/dim]",
            "[dim]auto[/dim]",
            "[dim]auto[/dim]",
            "[dim]auto[/dim]",
        )
        
        console.print(table)
        console.print()
        
        max_choice = len(available_ips) + extra_options
        
        while True:
            choice = IntPrompt.ask("Enter selection", default=1)
            if 1 <= choice <= max_choice:
                break
            console.print(f"[red]Please enter a number between 1 and {max_choice}[/red]")
        
        # Check for DHCP selection
        if choice == dhcp_idx:
            return {"_dhcp": True}
        
        # Check for manual entry
        if allow_manual and choice == len(available_ips) + 1:
            # Return marker dict - CLI will handle manual entry with interfaces
            return {"_manual": True}
        
        return available_ips[choice - 1]
    
    @staticmethod
    def manual_ip_entry(available_interfaces: list[str] | None = None) -> dict:
        """Prompt user to manually enter IP configuration.
        
        Args:
            available_interfaces: Optional list of detected interfaces
        
        Returns:
            Dict with IP configuration
        """
        console.print("\n[bold cyan]Manual IP Configuration:[/bold cyan]\n")
        
        # Interface selection
        if available_interfaces:
            console.print("Available interfaces:")
            for i, iface in enumerate(available_interfaces, 1):
                console.print(f"  [{i}] {iface}")
            console.print(f"  [{len(available_interfaces) + 1}] Enter manually")
            console.print()
            
            while True:
                choice = IntPrompt.ask("Select interface", default=1)
                if 1 <= choice <= len(available_interfaces):
                    interface = available_interfaces[choice - 1]
                    break
                elif choice == len(available_interfaces) + 1:
                    interface = Prompt.ask("Interface name (e.g., eth0)")
                    break
                console.print(f"[red]Please enter 1-{len(available_interfaces) + 1}[/red]")
        else:
            interface = Prompt.ask("Interface name (e.g., eth0, leave blank for auto)", default="")
            interface = interface if interface else None
        
        static_ip = Prompt.ask("Static IP Address")
        subnet = Prompt.ask("Subnet (CIDR e.g. '24', or netmask e.g. '255.255.255.0')", default="24")
        gateway = Prompt.ask("Gateway IP")
        
        dns_input = Prompt.ask("DNS Servers (comma-separated, or leave blank)", default="")
        dns = [d.strip() for d in dns_input.split(",") if d.strip()] if dns_input else []

        return {
            "interface": interface,
            "static_ip": static_ip,
            "subnet": subnet,
            "gateway": gateway,
            "dns": dns,
        }
    
    @staticmethod
    def prompt_fqdn() -> list[str]:
        """Prompt user to enter internal FQDNs for DNS validation.

        Accepts comma-separated hostnames.

        Returns:
            List of FQDN strings (empty list if skipped)
        """
        console.print("\n[bold cyan]DNS Validation[/bold cyan]")
        console.print("[dim]Enter internal FQDNs to validate DNS resolution (comma-separated).[/dim]\n")

        raw = Prompt.ask(
            "Internal FQDN(s) (or leave blank to skip)",
            default="",
        )

        if not raw:
            return []

        return [f.strip() for f in raw.split(",") if f.strip()]

    @staticmethod
    def select_credentials(
        windows: dict,
        linux: dict,
    ) -> tuple[list[str], list[str]]:
        """Prompt user to select which credentials to sync.

        Displays a numbered table of all enabled credentials and lets
        the user pick by number.  Entering nothing or "all" selects
        everything.

        Args:
            windows: dict[name, credential] for Windows credentials
            linux: dict[name, credential] for Linux credentials

        Returns:
            (selected_windows_names, selected_linux_names)
        """
        entries: list[tuple[str, str, str]] = []  # (type, name, obj)

        for name, cred in windows.items():
            entries.append(("Windows", name, cred))
        for name, cred in linux.items():
            entries.append(("SSH", name, cred))

        if not entries:
            return ([], [])

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=4)
        table.add_column("Type")
        table.add_column("Name", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("Domain/Escalation")
        table.add_column("Description", style="dim")

        for i, (ctype, name, cred) in enumerate(entries, 1):
            if ctype == "Windows":
                detail = getattr(cred, "domain", "") or "LOCAL"
            else:
                detail = getattr(cred, "privilege_escalation", "") or "none"
            desc = getattr(cred, "description", "") or ""
            table.add_row(
                str(i),
                ctype,
                name,
                getattr(cred, "username", ""),
                detail,
                desc,
            )

        console.print("\n[bold]Select credentials to sync:[/bold]")
        console.print(table)
        console.print()

        raw = Prompt.ask(
            "Enter numbers (comma-separated) or [bold]all[/bold]",
            default="all",
        )

        if raw.strip().lower() == "all" or not raw.strip():
            win_names = [n for _, n, _ in entries if _ == "Windows" for _ in [_]]
            lin_names = [n for _, n, _ in entries if _ == "SSH" for _ in [_]]
            # Simpler approach:
            win_names = [name for ctype, name, _ in entries if ctype == "Windows"]
            lin_names = [name for ctype, name, _ in entries if ctype == "SSH"]
            return (win_names, lin_names)

        # Parse selected numbers
        selected_indices: set[int] = set()
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(entries):
                    selected_indices.add(idx)

        if not selected_indices:
            console.print("[yellow]No valid selection — using all credentials[/yellow]")
            win_names = [name for ctype, name, _ in entries if ctype == "Windows"]
            lin_names = [name for ctype, name, _ in entries if ctype == "SSH"]
            return (win_names, lin_names)

        win_names = []
        lin_names = []
        for idx in sorted(selected_indices):
            ctype, name, _ = entries[idx - 1]
            if ctype == "Windows":
                win_names.append(name)
            else:
                lin_names.append(name)

        return (win_names, lin_names)
    
    @staticmethod
    def confirm_resume(
        completed_discovery: int,
        pending_discovery: int,
        completed_deep: int,
        pending_deep: int,
        active_nessus: dict | None,
    ) -> bool:
        """Prompt user to resume a previously interrupted scan or start fresh.

        Args:
            completed_discovery: Number of hosts with completed discovery scans
            pending_discovery: Number of hosts still needing discovery
            completed_deep: Number of hosts with completed deep scans
            pending_deep: Number of hosts still needing deep scan
            active_nessus: Active Nessus scan info dict, or None

        Returns:
            True to resume, False to start fresh
        """
        console.print()
        lines = [
            "[bold yellow]Previous scan results detected[/bold yellow]\n",
            f"  Discovery:  [green]{completed_discovery} completed[/green]"
            f"  /  [yellow]{pending_discovery} remaining[/yellow]",
            f"  Deep scan:  [green]{completed_deep} completed[/green]"
            f"  /  [yellow]{pending_deep} remaining[/yellow]",
        ]
        if active_nessus:
            lines.append(
                f"  Nessus:     [cyan]{active_nessus['name']}[/cyan] "
                f"({active_nessus['status']})"
            )
        panel = Panel(
            "\n".join(lines),
            title="[bold cyan]Resume Scan[/bold cyan]",
            border_style="yellow",
        )
        console.print(panel)
        console.print()
        console.print("  [1] Resume remaining scans")
        console.print("  [2] Start fresh (deletes previous results)")
        console.print()

        while True:
            choice = IntPrompt.ask("Select option", default=1)
            if choice == 1:
                return True
            if choice == 2:
                return not Confirm.ask(
                    "[red]This will delete all previous scan results. "
                    "Are you sure?[/red]",
                    default=False,
                )  # Returns False (start fresh) only if user confirms
            console.print("[red]Please enter 1 or 2[/red]")

    @staticmethod
    def confirm_fresh_start(total_hosts: int) -> bool:
        """Prompt when all hosts already have completed scans.

        Args:
            total_hosts: Total number of in-scope hosts

        Returns:
            True to clear results and rescan, False to skip scanning
        """
        console.print()
        panel = Panel(
            f"[bold green]All {total_hosts} hosts have completed scans[/bold green]\n\n"
            "[dim]Discovery and deep scans are already on disk for every host.[/dim]",
            title="[bold cyan]Scan Status[/bold cyan]",
            border_style="green",
        )
        console.print(panel)

        return Confirm.ask(
            "Start fresh? (deletes previous results)", default=False
        )

    @staticmethod
    def prompt_secret(name: str, env_var: str) -> str:
        """Prompt user to enter a secret value that wasn't in environment.
        
        Args:
            name: Human-readable name of the secret
            env_var: Name of the environment variable
            
        Returns:
            Entered secret value
        """
        console.print(f"\n[yellow]Environment variable {env_var} not set.[/yellow]")
        return Prompt.ask(f"Enter {name}", password=True)
    
    @staticmethod
    def confirm_quality_gate(offline_percentage: float, threshold: float) -> bool:
        """Prompt user to confirm proceeding when quality gate triggers.

        Args:
            offline_percentage: Percentage of unreachable hosts
            threshold: Configured threshold

        Returns:
            True if user wants to proceed anyway
        """
        panel = Panel(
            f"[bold red]Quality Gate Warning[/bold red]\n\n"
            f"[yellow]{offline_percentage:.1%}[/yellow] of hosts appear offline.\n"
            f"Threshold is set to [yellow]{threshold:.1%}[/yellow].\n\n"
            "[dim]This may indicate network connectivity issues or firewall blocking.[/dim]",
            title="[bold red]⚠ High Offline Host Rate[/bold red]",
            border_style="red",
        )
        console.print(panel)

        return Confirm.ask("Proceed with deep scan anyway?", default=False)
    
    @staticmethod
    def connectivity_failure_menu() -> str:
        """Prompt user for action when connectivity validation fails.
        
        Returns:
            One of: 'retry', 'reconfig', 'manual', 'exit'
        """
        console.print("\n[bold red]Connectivity Validation Failed[/bold red]\n")
        console.print("Options:")
        console.print("  [1] Retry connection")
        console.print("  [2] Select different IP configuration")
        console.print("  [3] Manual IP entry")
        console.print("  [4] Exit")
        console.print()
        
        while True:
            choice = IntPrompt.ask("Select action", default=1)
            if choice == 1:
                return "retry"
            elif choice == 2:
                return "reconfig"
            elif choice == 3:
                return "manual"
            elif choice == 4:
                return "exit"
            console.print("[red]Please enter 1-4[/red]")

    @staticmethod
    def prompt_export_dir(default: str = "") -> Path:
        """Prompt for export directory with tab completion via readline.

        Temporarily installs a filesystem path completer and restores
        the previous readline state afterward.  Uses ``input()`` (not
        Rich Prompt) because readline requires the builtin input function.

        Args:
            default: Default directory path shown in the prompt.

        Returns:
            Resolved Path to the selected directory.
        """
        import os
        import readline

        old_completer = readline.get_completer()
        old_delims = readline.get_completer_delims()

        def _path_completer(text: str, state: int) -> str | None:
            expanded = os.path.expanduser(text)
            if os.path.isdir(expanded) and not expanded.endswith(os.sep):
                # Complete the directory itself first, then its contents
                if state == 0 and text and not text.endswith(os.sep):
                    return text + os.sep
                expanded += os.sep

            parent = os.path.dirname(expanded) or "."
            prefix = os.path.basename(expanded)

            try:
                entries = os.listdir(parent)
            except OSError:
                return None

            matches = []
            for entry in sorted(entries):
                if entry.startswith(prefix):
                    full = os.path.join(parent, entry)
                    if os.path.isdir(full):
                        matches.append(full + os.sep)
                    else:
                        matches.append(full)

            if state < len(matches):
                return matches[state]
            return None

        try:
            readline.set_completer(_path_completer)
            readline.set_completer_delims(" \t\n")
            readline.parse_and_bind("tab: complete")

            console.print("\n[bold cyan]Export Directory[/bold cyan]")
            console.print("[dim]Use Tab for path completion[/dim]\n")

            if default:
                prompt_text = f"Export directory [{default}]: "
            else:
                prompt_text = "Export directory: "

            user_input = input(prompt_text).strip()

            if not user_input and default:
                user_input = default
            elif not user_input:
                console.print("[red]No directory specified[/red]")
                raise KeyboardInterrupt("No export directory provided")

            return Path(os.path.expanduser(user_input))
        finally:
            readline.set_completer(old_completer)
            readline.set_completer_delims(old_delims)
