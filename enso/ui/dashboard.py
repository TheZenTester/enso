"""Rich dashboard for real-time scan progress display."""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from enum import Enum
from typing import Callable

from rich.console import Console, Group
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.layout import Layout


class ScanStatus(Enum):
    """Status of an individual scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class HostScanState:
    """Track scan state for a single host."""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.discovery_status = ScanStatus.PENDING
        self.deep_status = ScanStatus.PENDING
        self.nessus_status = ScanStatus.PENDING
        self.open_ports: list[int] = []
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None


class ScanDashboard:
    """Real-time dashboard for monitoring concurrent scans."""
    
    def __init__(self):
        self.console = Console()
        self.hosts: dict[str, HostScanState] = {}
        self._live: Live | None = None
        
        # Progress trackers
        self.discovery_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Discovery"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        )
        self.deep_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Deep Scan"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        )
        self.nessus_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]Nessus"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        )
        
        self._discovery_task_id = None
        self._deep_task_id = None
        self._nessus_task_id = None
    
    def add_host(self, ip: str) -> None:
        """Add a host to track."""
        self.hosts[ip] = HostScanState(ip)
    
    def add_hosts(self, ips: list[str]) -> None:
        """Add multiple hosts to track."""
        for ip in ips:
            self.add_host(ip)
    
    def update_host_status(
        self,
        ip: str,
        scan_type: str,
        status: ScanStatus,
        open_ports: list[int] | None = None,
    ) -> None:
        """Update the status of a specific scan for a host.
        
        Args:
            ip: Host IP address
            scan_type: One of 'discovery', 'deep', 'nessus'
            status: New status
            open_ports: Optional list of discovered open ports
        """
        if ip not in self.hosts:
            self.add_host(ip)
        
        host = self.hosts[ip]
        
        if scan_type == "discovery":
            host.discovery_status = status
        elif scan_type == "deep":
            host.deep_status = status
        elif scan_type == "nessus":
            host.nessus_status = status
        
        if open_ports is not None:
            host.open_ports = open_ports
        
        if status == ScanStatus.RUNNING and host.start_time is None:
            host.start_time = datetime.now()
        elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            host.end_time = datetime.now()
    
    def _build_status_table(self, hosts_snapshot: list[tuple[str, HostScanState]] | None = None) -> Table:
        """Build the host status table.

        Args:
            hosts_snapshot: Pre-captured list of (ip, state) pairs for thread safety.
                            Falls back to self.hosts.items() if not provided.
        """
        table = Table(title="Host Scan Status", show_header=True, header_style="bold")
        table.add_column("Host", style="cyan", width=16)
        table.add_column("Discovery", width=12)
        table.add_column("Deep", width=12)
        table.add_column("Nessus", width=12)
        table.add_column("Open Ports", style="dim")

        status_styles = {
            ScanStatus.PENDING: "[dim]pending[/dim]",
            ScanStatus.RUNNING: "[yellow]running[/yellow]",
            ScanStatus.COMPLETED: "[green]✓ done[/green]",
            ScanStatus.FAILED: "[red]✗ failed[/red]",
            ScanStatus.SKIPPED: "[dim]skipped[/dim]",
            ScanStatus.TIMEOUT: "[yellow]⏱ timeout[/yellow]",
        }

        items = hosts_snapshot if hosts_snapshot is not None else list(self.hosts.items())
        for ip, state in items:
            ports_str = ", ".join(map(str, state.open_ports[:5]))
            if len(state.open_ports) > 5:
                ports_str += f" (+{len(state.open_ports) - 5})"

            table.add_row(
                ip,
                status_styles[state.discovery_status],
                status_styles[state.deep_status],
                status_styles[state.nessus_status],
                ports_str or "—",
            )

        return table
    
    def _build_dashboard(self) -> Panel:
        """Build the complete dashboard display.

        This is called from Rich's refresh thread via get_renderable,
        so it must not raise or the Live display will break.
        """
        try:
            # Snapshot hosts to avoid RuntimeError from concurrent dict modification
            hosts_snapshot = list(self.hosts.items())

            content = Group(
                self.discovery_progress,
                self.deep_progress,
                self.nessus_progress,
                "",
                self._build_status_table(hosts_snapshot),
            )

            return Panel(
                content,
                title="[bold white]ENSO Scan Dashboard[/bold white]",
                border_style="blue",
            )
        except Exception:
            return Panel("[red]Dashboard render error[/red]", border_style="red")
    
    def start(self, total_hosts: int) -> None:
        """Start the live dashboard display.

        Args:
            total_hosts: Total number of hosts being scanned
        """
        # Create tasks with start=False so the elapsed timer doesn't tick
        # until the module actually begins executing.
        self._discovery_task_id = self.discovery_progress.add_task(
            "discovery", total=total_hosts, start=False
        )
        self._deep_task_id = self.deep_progress.add_task(
            "deep", total=total_hosts, start=False
        )
        self._nessus_task_id = self.nessus_progress.add_task(
            "nessus", total=total_hosts, start=False
        )
        self._module_started: set[str] = set()
        
        self._save_terminal_state()
        self._redirect_console_logging()
        self._live = Live(
            console=self.console,
            refresh_per_second=2,
            get_renderable=self._build_dashboard,
        )
        self._live.start()
    
    def start_module(self, scan_type: str) -> None:
        """Start the elapsed timer for a module.

        Called when the module actually begins executing, not when the
        dashboard is first displayed.  Safe to call multiple times —
        only the first call per module starts the timer.

        Args:
            scan_type: One of 'discovery', 'deep', 'nessus'
        """
        if scan_type in self._module_started:
            return
        self._module_started.add(scan_type)

        if scan_type == "discovery" and self._discovery_task_id is not None:
            self.discovery_progress.start_task(self._discovery_task_id)
        elif scan_type == "deep" and self._deep_task_id is not None:
            self.deep_progress.start_task(self._deep_task_id)
        elif scan_type == "nessus" and self._nessus_task_id is not None:
            self.nessus_progress.start_task(self._nessus_task_id)

    def update_progress(
        self,
        scan_type: str,
        completed: int,
    ) -> None:
        """Update the progress bar for a scan type.

        Args:
            scan_type: One of 'discovery', 'deep', 'nessus'
            completed: Number of completed scans
        """
        if scan_type == "discovery" and self._discovery_task_id is not None:
            self.discovery_progress.update(self._discovery_task_id, completed=completed)
        elif scan_type == "deep" and self._deep_task_id is not None:
            self.deep_progress.update(self._deep_task_id, completed=completed)
        elif scan_type == "nessus" and self._nessus_task_id is not None:
            self.nessus_progress.update(self._nessus_task_id, completed=completed)
    
    def _save_terminal_state(self) -> None:
        """Save terminal attributes so we can restore after Live display."""
        self._saved_term_attrs = None
        try:
            import termios
            if sys.stdin.isatty():
                self._saved_term_attrs = termios.tcgetattr(sys.stdin)
        except (ImportError, OSError):
            pass

    def _restore_terminal_state(self) -> None:
        """Restore terminal attributes (echo, line mode, etc.)."""
        if getattr(self, "_saved_term_attrs", None) is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._saved_term_attrs)
            except (ImportError, OSError):
                pass

    def _redirect_console_logging(self) -> None:
        """Redirect RichHandler output through the dashboard's Console.

        Rich's Live display properly handles concurrent writes from its own
        Console — log messages appear above the live area automatically.
        """
        self._saved_handler_consoles: list[tuple[RichHandler, Console]] = []
        for handler in logging.getLogger().handlers:
            if isinstance(handler, RichHandler):
                self._saved_handler_consoles.append((handler, handler.console))
                handler.console = self.console

    def _restore_console_logging(self) -> None:
        """Restore RichHandler consoles to their original values."""
        for handler, original_console in getattr(self, "_saved_handler_consoles", []):
            handler.console = original_console
        self._saved_handler_consoles = []

    def stop(self) -> None:
        """Stop the live dashboard display and restore terminal state."""
        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None
        self._restore_console_logging()
        self._restore_terminal_state()
    
    def _host_phase_statuses(self, host: HostScanState) -> list[ScanStatus]:
        """Return the list of scan-phase statuses for a host."""
        return [host.discovery_status, host.deep_status, host.nessus_status]

    def print_summary(self) -> None:
        """Print a final summary after scans complete."""
        self.console.print("\n[bold green]Scan Summary[/bold green]\n")
        self.console.print(f"Total hosts: {len(self.hosts)}\n")

        # Per-phase breakdown
        phases = [
            ("Discovery", "discovery_status"),
            ("Deep Scan", "deep_status"),
            ("Nessus", "nessus_status"),
        ]

        phase_table = Table(show_header=True, header_style="bold")
        phase_table.add_column("Phase", style="cyan", width=14)
        phase_table.add_column("Completed", justify="right", width=10)
        phase_table.add_column("Timeout", justify="right", width=10)
        phase_table.add_column("Failed", justify="right", width=10)
        phase_table.add_column("Skipped", justify="right", width=10)

        for label, attr in phases:
            done = sum(1 for h in self.hosts.values() if getattr(h, attr) == ScanStatus.COMPLETED)
            tout = sum(1 for h in self.hosts.values() if getattr(h, attr) == ScanStatus.TIMEOUT)
            fail = sum(1 for h in self.hosts.values() if getattr(h, attr) == ScanStatus.FAILED)
            skip = sum(1 for h in self.hosts.values() if getattr(h, attr) == ScanStatus.SKIPPED)
            done_s = f"[green]{done}[/green]" if done else "[dim]0[/dim]"
            tout_s = f"[yellow]{tout}[/yellow]" if tout else "[dim]0[/dim]"
            fail_s = f"[red]{fail}[/red]" if fail else "[dim]0[/dim]"
            skip_s = f"[dim]{skip}[/dim]"
            phase_table.add_row(label, done_s, tout_s, fail_s, skip_s)

        self.console.print(phase_table)
        self.console.print()

        # Per-host rollup
        #   "Fully completed" = all phases terminal, at least one of
        #                       discovery/deep COMPLETED, and nessus COMPLETED
        #   "Failed"          = at least one phase FAILED
        #   "Partial"         = everything else (timeouts, skipped-only,
        #                       still running, etc.)
        terminal = {ScanStatus.COMPLETED, ScanStatus.SKIPPED, ScanStatus.TIMEOUT}
        fully_completed = 0
        partial = 0
        failed = 0

        for host in self.hosts.values():
            statuses = self._host_phase_statuses(host)
            has_failed = any(s == ScanStatus.FAILED for s in statuses)
            all_terminal = all(s in terminal for s in statuses)
            nmap_completed = (
                host.discovery_status == ScanStatus.COMPLETED
                or host.deep_status == ScanStatus.COMPLETED
            )
            nessus_completed = host.nessus_status == ScanStatus.COMPLETED

            if has_failed:
                failed += 1
            elif all_terminal and nmap_completed and nessus_completed:
                fully_completed += 1
            else:
                partial += 1

        self.console.print(f"Fully completed: [green]{fully_completed}[/green]")
        self.console.print(f"Partial:         [yellow]{partial}[/yellow]")
        self.console.print(f"Failed:          [red]{failed}[/red]")

        total_ports = sum(len(h.open_ports) for h in self.hosts.values())
        self.console.print(f"Total open ports found: [cyan]{total_ports}[/cyan]")
