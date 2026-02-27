"""Nessus pre-flight validation for ENSO.

Validates Nessus server connectivity, authentication, and configuration
before scan execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from enso.utils.logging import get_logger

if TYPE_CHECKING:
    from enso.config import EnsoConfig

logger = get_logger(__name__)
console = Console()


@dataclass
class ValidationResult:
    """Result of a single validation check."""
    
    name: str
    passed: bool
    message: str
    details: str | None = None


@dataclass
class NessusValidationReport:
    """Complete validation report for Nessus."""
    
    results: list[ValidationResult] = field(default_factory=list)
    
    @property
    def all_passed(self) -> bool:
        """Check if all validations passed."""
        return all(r.passed for r in self.results)
    
    @property
    def passed_count(self) -> int:
        """Count of passed checks."""
        return sum(1 for r in self.results if r.passed)
    
    @property
    def total_count(self) -> int:
        """Total number of checks."""
        return len(self.results)
    
    def add(self, name: str, passed: bool, message: str, details: str | None = None) -> None:
        """Add a validation result."""
        self.results.append(ValidationResult(name, passed, message, details))


class NessusValidator:
    """Validates Nessus server configuration and connectivity."""

    def __init__(self, config: EnsoConfig):
        """Initialize with ENSO configuration.

        Args:
            config: ENSO configuration containing Nessus settings
        """
        self.config = config
        self.nessus_config = config.nessus
        self._nessus = None
    
    def validate_all(self) -> NessusValidationReport:
        """Run all Nessus validation checks.
        
        Returns:
            NessusValidationReport with all check results
        """
        report = NessusValidationReport()
        
        # Check 1: Server connectivity
        self._check_connectivity(report)
        
        # Check 2: Authentication
        if report.results[-1].passed:  # Only if connected
            self._check_authentication(report)
        else:
            report.add(
                "Authentication",
                False,
                "Skipped - server not reachable",
            )
        
        # Check 3: Scanner availability
        if report.passed_count >= 2:  # Connected and authenticated
            self._check_scanner_status(report)
        else:
            report.add(
                "Scanner Status",
                False,
                "Skipped - not authenticated",
            )
        
        # Check 4: Policy validation
        if report.passed_count >= 2:  # Connected and authenticated
            self._check_policies(report)
        else:
            report.add(
                "Policy Mapping",
                False,
                "Skipped - not authenticated",
            )
        
        return report
    
    def _check_connectivity(self, report: NessusValidationReport) -> None:
        """Check if Nessus server is reachable."""
        import socket
        from urllib.parse import urlparse
        
        url = self.nessus_config.url
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                report.add(
                    "Server Connectivity",
                    True,
                    f"Server reachable at {url}",
                )
            else:
                report.add(
                    "Server Connectivity",
                    False,
                    f"Cannot connect to {host}:{port}",
                    f"Socket error code: {result}",
                )
        except socket.error as e:
            report.add(
                "Server Connectivity",
                False,
                f"Connection failed: {e}",
            )
    
    def _connect(self) -> bool:
        """Create and cache a pyTenable Nessus connection.

        Returns:
            True if connection successful
        """
        if self._nessus is not None:
            return True

        from tenable.nessus import Nessus

        self._nessus = Nessus(
            url=self.nessus_config.url,
            access_key=self.nessus_config.access_key,
            secret_key=self.nessus_config.secret_key,
        )
        self._nessus.server.status()
        return True

    def _check_authentication(self, report: NessusValidationReport) -> None:
        """Check if Nessus credentials are valid."""
        try:
            access_key = self.nessus_config.access_key
            secret_key = self.nessus_config.secret_key

            if not access_key or not secret_key:
                report.add(
                    "Authentication",
                    False,
                    "Credentials not configured",
                    "Set NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY environment variables",
                )
                return

            if access_key.startswith("${") or secret_key.startswith("${"):
                report.add(
                    "Authentication",
                    False,
                    "Credentials contain unresolved environment variables",
                    "Ensure environment variables are set before running",
                )
                return

            self._connect()
            report.add(
                "Authentication",
                True,
                "API credentials valid",
            )
        except ImportError:
            report.add(
                "Authentication",
                False,
                "pyTenable not installed",
                "Run: pip install pytenable",
            )
        except Exception as e:
            report.add(
                "Authentication",
                False,
                f"Authentication error: {e}",
            )
    
    def _check_scanner_status(self, report: NessusValidationReport) -> None:
        """Check if at least one scanner is online."""
        try:
            scanners = list(self._nessus.scanners.list())
            online = [s for s in scanners if s.get("status") == "on"]
            offline = [s for s in scanners if s.get("status") != "on"]

            if online:
                report.add(
                    "Scanner Status",
                    True,
                    f"{len(online)} scanner(s) online",
                    f"{len(offline)} offline" if offline else None,
                )
            else:
                report.add(
                    "Scanner Status",
                    False,
                    "No scanners online",
                    f"Found {len(scanners)} scanner(s), all offline",
                )
        except Exception as e:
            report.add(
                "Scanner Status",
                False,
                f"Could not check scanners: {e}",
            )
    
    def _check_policies(self, report: NessusValidationReport) -> None:
        """Check if configured policies exist in Nessus."""
        try:
            # Get all available policies from the server
            policies = {p["name"]: p["id"] for p in self._nessus.policies.list()}

            # Validate the default policy from nessus.yaml
            configured_policies = {self.nessus_config.policy_mapping.default}

            missing = []
            found = []
            for policy_name in configured_policies:
                if policy_name in policies:
                    found.append(policy_name)
                else:
                    missing.append(policy_name)

            if missing:
                report.add(
                    "Policy Mapping",
                    False,
                    f"{len(missing)} policy(ies) not found",
                    f"Missing: {', '.join(missing)}",
                )
            else:
                report.add(
                    "Policy Mapping",
                    True,
                    f"All {len(found)} configured policy(ies) found",
                )
        except Exception as e:
            report.add(
                "Policy Mapping",
                False,
                f"Could not verify policies: {e}",
            )
    
    def display_report(self, report: NessusValidationReport) -> None:
        """Display validation report to console.
        
        Args:
            report: The validation report to display
        """
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Status", width=3)
        table.add_column("Check")
        table.add_column("Result")
        
        for result in report.results:
            status = "[green]✓[/green]" if result.passed else "[red]✗[/red]"
            message = result.message
            if result.details:
                message += f" [dim]({result.details})[/dim]"
            
            table.add_row(status, result.name, message)
        
        # Summary
        if report.all_passed:
            summary = f"[bold green]All {report.total_count} checks passed[/bold green]"
            border_style = "green"
        else:
            summary = f"[bold yellow]{report.passed_count}/{report.total_count} checks passed[/bold yellow]"
            border_style = "yellow" if report.passed_count > 0 else "red"
        
        panel = Panel(
            table,
            title="[bold cyan]Nessus Pre-flight Check[/bold cyan]",
            subtitle=summary,
            border_style=border_style,
        )
        console.print(panel)
