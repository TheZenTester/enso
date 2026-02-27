"""Context Manager for detecting engagement type and managing scope files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from rich.console import Console

from .config import EnsoConfig, NetworkDropConfig
from .ui.prompts import Prompts
from .utils.logging import get_logger

logger = get_logger(__name__)
console = Console()


@dataclass
class ScopeFiles:
    """Container for scope file paths."""
    
    in_scope: Path
    excluded: Path | None = None
    special: Path | None = None
    
    def load_in_scope_hosts(self) -> list[str]:
        """Load hosts from the in_scope file.
        
        Returns:
            List of IP addresses/ranges
        """
        if not self.in_scope.exists():
            logger.error(f"In-scope file not found: {self.in_scope}")
            return []
        
        with open(self.in_scope, "r") as f:
            hosts = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        
        logger.info(f"Loaded {len(hosts)} hosts from {self.in_scope.name}")
        return hosts
    
    def load_excluded_hosts(self) -> list[str]:
        """Load hosts from the excluded file.
        
        Returns:
            List of excluded IP addresses/ranges
        """
        if not self.excluded or not self.excluded.exists():
            return []
        
        with open(self.excluded, "r") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]


@dataclass
class EngagementContext:
    """Context for the current engagement."""
    
    engagement_type: Literal["simple", "complex"]
    client_dir: Path
    scope_files: ScopeFiles
    output_dir: Path
    network_drop: NetworkDropConfig | None = None
    manual_entry_requested: bool = False
    dhcp_requested: bool = False
    
    @property
    def scans_dir(self) -> Path:
        """Get the scans output directory."""
        return self.output_dir / "scans"

    @property
    def scans_nmap_dir(self) -> Path:
        """Get the Nmap scans output directory."""
        return self.output_dir / "scans" / "nmap"
    
    @property
    def scans_nessus_dir(self) -> Path:
        """Get the Nessus scans output directory."""
        return self.output_dir / "scans" / "nessus"
    
    def get_module_dir(self, module_output_dir: str) -> Path:
        """Resolve a module's output dir relative to scans/.

        Args:
            module_output_dir: e.g. "nmap/discovery", "nessus"

        Returns:
            Absolute Path, e.g. /client/internal/scans/nmap/discovery
        """
        return self.scans_dir / module_output_dir

    def ensure_output_dirs(self, module_dirs: list[str] | None = None) -> None:
        """Create output directories if they don't exist.

        Args:
            module_dirs: List of dirs relative to scans/ to create.
                         Defaults to legacy hardcoded dirs if None.
        """
        if module_dirs is None:
            module_dirs = ["nmap/discovery", "nmap/detailed", "nmap/logs", "nessus"]
        for d in module_dirs:
            (self.scans_dir / d).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Output directories created under {self.output_dir}")


class ContextManager:
    """Detects and manages engagement context."""
    
    def __init__(self, config: EnsoConfig, client_dir: Path | None = None):
        """Initialize the context manager.
        
        Args:
            config: ENSO configuration
            client_dir: Override for client directory (defaults to config)
        """
        self.config = config
        self.client_dir = client_dir or config.engagement.client_dir
    
    def detect_engagement_type(self) -> Literal["simple", "complex"]:
        """Get the engagement type from configuration.
        
        Returns:
            'single' or 'complex' as configured in engagement.yaml
        """
        engagement_type = self.config.engagement.engagement_type
        num_drops = len(self.config.engagement.network_drops)
        logger.info(f"{engagement_type.capitalize()} engagement ({num_drops} network drops configured)")
        return engagement_type
    
    def _find_single_network_scope(self) -> ScopeFiles:
        """Find scope files for a single network engagement."""
        scope_dir = self.client_dir / self.config.engagement.scope_dir
        sf = self.config.engagement.simple.scope_files

        return ScopeFiles(
            in_scope=scope_dir / sf.in_scope if sf.in_scope else scope_dir / "inscope.txt",
            excluded=(scope_dir / sf.excluded) if sf.excluded else None,
            special=(scope_dir / sf.special) if sf.special else None,
        )
    
    def _find_complex_network_scope(self, drop: NetworkDropConfig) -> ScopeFiles:
        """Find scope files for a specific network drop in a complex engagement.

        Args:
            drop: The network drop configuration
        """
        scope_dir = self.client_dir / self.config.engagement.scope_dir
        sf = self.config.engagement.resolve_scope_files_for_drop(drop)

        return ScopeFiles(
            in_scope=(scope_dir / sf.in_scope) if sf.in_scope else Path("/dev/null"),
            excluded=(scope_dir / sf.excluded) if sf.excluded else None,
            special=(scope_dir / sf.special) if sf.special else None,
        )
    
    def _discover_network_directories(self) -> list[dict]:
        """Discover network directories for complex engagements without config.

        Returns:
            List of discovered networks with name and paths
        """
        scope_dir_name = self.config.engagement.scope_dir
        networks = []

        for scan_dir in self.client_dir.glob("*/scans/nmap"):
            network_dir = scan_dir.parent.parent
            if network_dir.name in ("internal", scope_dir_name):
                continue

            networks.append({
                "name": network_dir.name,
                "output_dir": str(network_dir),
                # These would need to be filled in by the user
                "static_ip": "N/A",
                "gateway": "N/A",
            })

        return networks
    
    def build_context(self, interactive: bool = True) -> EngagementContext:
        """Build the engagement context, prompting user if needed.
        
        Args:
            interactive: Whether to prompt for user input
            
        Returns:
            Configured EngagementContext
        """
        engagement_type = self.detect_engagement_type()
        
        if engagement_type == "simple":
            return self._build_single_context()
        else:
            return self._build_complex_context(interactive)
    
    def build_context_for_network(self, network_name: str) -> EngagementContext:
        """Build context for a specific network drop by name.
        
        Args:
            network_name: Name of the network drop to use
            
        Returns:
            Configured EngagementContext for the specified network
            
        Raises:
            ValueError: If network is not found in configuration
        """
        network_drops = self.config.engagement.network_drops
        engagement_type = self.config.engagement.engagement_type
        
        # Find the network drop by name (case-insensitive)
        selected_drop = None
        for drop in network_drops:
            if drop.name.lower() == network_name.lower():
                selected_drop = drop
                break
        
        if not selected_drop:
            available = [d.name for d in network_drops]
            raise ValueError(
                f"Network '{network_name}' not found. Available networks: {', '.join(available)}"
            )

        # Build context for this network
        scope_files = self._find_complex_network_scope(selected_drop)
        output_dir = self.client_dir / selected_drop.get_output_dir()

        logger.info(f"Using pre-selected network: {selected_drop.name}")

        return EngagementContext(
            engagement_type=engagement_type,
            client_dir=self.client_dir,
            scope_files=scope_files,
            output_dir=output_dir,
            network_drop=selected_drop,
        )
    
    def _build_single_context(self) -> EngagementContext:
        """Build context for a single network engagement.

        Handles both:
        - No network_drops: uses simple.scope_files and simple.output_dir
        - Single network_drop: uses that drop's scope_files (with complex defaults)
        """
        network_drops = self.config.engagement.network_drops
        simple_cfg = self.config.engagement.simple

        if network_drops and len(network_drops) == 1:
            nd = network_drops[0]
            scope_files = self._find_complex_network_scope(nd)
            output_dir = self.client_dir / nd.get_output_dir()

            return EngagementContext(
                engagement_type="simple",
                client_dir=self.client_dir,
                scope_files=scope_files,
                output_dir=output_dir,
                network_drop=nd,
            )
        else:
            scope_files = self._find_single_network_scope()
            output_dir = self.client_dir / simple_cfg.output_dir

            return EngagementContext(
                engagement_type="simple",
                client_dir=self.client_dir,
                scope_files=scope_files,
                output_dir=output_dir,
                network_drop=None,
            )
    
    def _build_complex_context(self, interactive: bool) -> EngagementContext:
        """Build context for a complex multi-drop engagement."""
        network_drops = self.config.engagement.network_drops
        simple_cfg = self.config.engagement.simple

        if not network_drops:
            # Try to discover from directory structure
            discovered = self._discover_network_directories()
            if not discovered:
                raise ValueError(
                    "Complex engagement detected but no network drops configured "
                    "and none could be discovered from directory structure."
                )

            # Convert discovered to display format
            networks_for_display = discovered
        else:
            # Use configured network drops
            networks_for_display = [
                {
                    "name": nd.name,
                    "static_ip": nd.static_ip,
                    "gateway": nd.gateway,
                    "output_dir": nd.output_dir,
                    "interface": self.config.engagement.get_interface_for_drop(nd),
                }
                for nd in network_drops
            ]

        # Placeholder scope/output for manual-entry / DHCP fallback
        scope_dir = self.client_dir / self.config.engagement.scope_dir
        fallback_scope = ScopeFiles(in_scope=Path("/dev/null"))
        fallback_output = self.client_dir / simple_cfg.output_dir

        if interactive:
            # Prompt user to select network
            console.print("\n[bold]Complex Engagement Detected[/bold]")
            console.print("Multiple network drops are available.\n")

            selected_idx = Prompts.select_network_drop(networks_for_display)

            # Handle special selections
            if selected_idx == -1:
                return EngagementContext(
                    engagement_type="complex",
                    client_dir=self.client_dir,
                    scope_files=fallback_scope,
                    output_dir=fallback_output,
                    network_drop=None,
                    manual_entry_requested=True,
                )
            elif selected_idx == -2:
                return EngagementContext(
                    engagement_type="complex",
                    client_dir=self.client_dir,
                    scope_files=fallback_scope,
                    output_dir=fallback_output,
                    network_drop=None,
                    dhcp_requested=True,
                )

            selected = networks_for_display[selected_idx]

            # Physical gate - prompt for connection
            if not Prompts.physical_gate(selected["name"]):
                raise KeyboardInterrupt("User aborted at physical gate")
        else:
            # Non-interactive: use first network
            selected = networks_for_display[0]

        # Get full NetworkDropConfig if available
        network_drop = None
        if network_drops:
            for nd in network_drops:
                if nd.name == selected["name"]:
                    network_drop = nd
                    break

        # Resolve scope files and output_dir from the drop config
        if network_drop:
            scope_files = self._find_complex_network_scope(network_drop)
            output_dir = self.client_dir / network_drop.get_output_dir()
        elif selected.get("output_dir"):
            scope_files = fallback_scope
            output_dir = self.client_dir / selected["output_dir"]
        else:
            scope_files = fallback_scope
            output_dir = fallback_output

        return EngagementContext(
            engagement_type="complex",
            client_dir=self.client_dir,
            scope_files=scope_files,
            output_dir=output_dir,
            network_drop=network_drop,
        )
    
    def auto_detect_network_from_ip(self, current_ip: str) -> NetworkDropConfig | None:
        """Attempt to auto-detect the network drop based on current static IP.
        
        Args:
            current_ip: Currently configured static IP
            
        Returns:
            Matching NetworkDropConfig, or None if not found
        """
        for network_drop in self.config.engagement.network_drops:
            if network_drop.static_ip == current_ip:
                logger.info(f"Auto-detected network: {network_drop.name} from IP {current_ip}")
                return network_drop
        
        return None
