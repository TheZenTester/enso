"""Scan orchestrator for managing execution strategies."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from typing import Literal

from .config import EnsoConfig
from .context import EngagementContext
from .nmap_runner import NmapRunner, QualityGate, HostResult
from .nessus_bridge import NessusBridge
from .ui.dashboard import ScanDashboard, ScanStatus
from .ui.prompts import Prompts
from .utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ResumeState:
    """State recovered from a previous interrupted scan run."""

    completed_discovery: dict[str, HostResult] = field(default_factory=dict)
    completed_deep: dict[str, HostResult] = field(default_factory=dict)
    active_nessus_scan: dict | None = None
    pending_discovery: list[str] = field(default_factory=list)
    pending_deep_targets: dict[str, list[int]] = field(default_factory=dict)

    @property
    def has_previous_results(self) -> bool:
        return bool(
            self.completed_discovery
            or self.completed_deep
            or self.active_nessus_scan
        )


class ScanOrchestrator:
    """Orchestrates scanning workflow based on execution strategy."""
    
    def __init__(
        self,
        config: EnsoConfig,
        context: EngagementContext,
        skip_nessus: bool = False,
        top_ports: int | None = None,
    ):
        """Initialize the orchestrator.
        
        Args:
            config: ENSO configuration
            context: Engagement context
            skip_nessus: Whether to skip Nessus scanning
            top_ports: If set, limit port scanning to top N ports
        """
        self.config = config
        self.context = context
        self.skip_nessus = skip_nessus
        self.top_ports = top_ports
        
        # Initialize components
        self.dashboard = ScanDashboard()
        self.quality_gate = QualityGate(
            config.nmap.quality_gate.dead_host_threshold
        )
        
        # Resolve output directories from config
        gcfg = config.global_config
        self._discovery_dir = context.get_module_dir(gcfg.get_module_output_dir("nmap_discovery"))
        self._detailed_dir = context.get_module_dir(gcfg.get_module_output_dir("nmap_deep"))
        self._nmap_log_dir = context.get_module_dir(config.nmap.log_dir)

        # Nmap runner with progress callback
        self.nmap = NmapRunner(
            config=config.nmap,
            discovery_dir=self._discovery_dir,
            detailed_dir=self._detailed_dir,
            log_dir=self._nmap_log_dir,
            progress_callback=self._on_nmap_progress,
            exclude_file=context.scope_files.excluded,
        )
        
        # Nessus bridge (initialized on demand)
        self._nessus: NessusBridge | None = None
        
        # Tracking
        self._discovery_results: dict[str, HostResult] = {}
        self._deep_results: dict[str, HostResult] = {}
        self._discovery_complete = threading.Event()
        self._completed_counts = {"discovery": 0, "deep": 0, "nessus": 0}
        self._resume_state: ResumeState | None = None
    
    def _on_nmap_progress(
        self,
        ip: str,
        scan_type: str,
        status: ScanStatus,
        open_ports: list[int] | None,
    ) -> None:
        """Handle Nmap progress updates."""
        self.dashboard.update_host_status(ip, scan_type, status, open_ports)

        if status in (ScanStatus.COMPLETED, ScanStatus.TIMEOUT):
            self._completed_counts[scan_type] += 1
            self.dashboard.update_progress(scan_type, self._completed_counts[scan_type])
    
    def _on_nessus_progress(
        self,
        scan_name: str,
        status: ScanStatus,
        progress: int,
        host_progress: list[dict] | None = None,
    ) -> None:
        """Handle Nessus progress updates.

        Nessus runs a single scan covering all targets, so we map its
        overall percentage to an estimated host-completion count for the
        dashboard progress bar.  Per-host progress (from the Nessus API)
        is used to mark individual hosts as COMPLETED in the dashboard
        as soon as their scan finishes.
        """
        total = len(self.dashboard.hosts)

        if status == ScanStatus.COMPLETED:
            for ip in self.dashboard.hosts:
                self.dashboard.update_host_status(ip, "nessus", ScanStatus.COMPLETED)
            self._completed_counts["nessus"] = total
            self.dashboard.update_progress("nessus", total)

        elif status == ScanStatus.RUNNING:
            # Update per-host status from Nessus host_progress data
            completed_hosts = 0
            if host_progress:
                for hp in host_progress:
                    hostname = hp.get("hostname", "")
                    pct = hp.get("progress", 0)
                    if hostname in self.dashboard.hosts:
                        if pct >= 100:
                            self.dashboard.update_host_status(
                                hostname, "nessus", ScanStatus.COMPLETED
                            )
                            completed_hosts += 1

            # Use actual completed count when we have per-host data,
            # fall back to estimate from overall progress
            if host_progress:
                self._completed_counts["nessus"] = completed_hosts
            else:
                estimated = int(progress * total / 100) if total else 0
                self._completed_counts["nessus"] = estimated
            self.dashboard.update_progress("nessus", self._completed_counts["nessus"])

        elif status == ScanStatus.FAILED:
            for ip in self.dashboard.hosts:
                self.dashboard.update_host_status(ip, "nessus", ScanStatus.FAILED)
            self.dashboard.update_progress("nessus", total)
    
    def _get_nessus_bridge(self) -> NessusBridge:
        """Get or create Nessus bridge."""
        if self._nessus is None:
            self._nessus = NessusBridge(
                config=self.config.nessus,
                credentials=self.config.credentials,
                progress_callback=self._on_nessus_progress,
            )
        return self._nessus
    
    def _skip_deep_for_all_hosts(self) -> None:
        """Mark every host as SKIPPED for deep scan and fill the progress bar."""
        for ip in self.dashboard.hosts:
            self.dashboard.update_host_status(ip, "deep", ScanStatus.SKIPPED)
        self._completed_counts["deep"] = len(self.dashboard.hosts)
        self.dashboard.update_progress("deep", self._completed_counts["deep"])

    def _check_previous_results(self, hosts: list[str]) -> ResumeState:
        """Detect completed scans on disk and active Nessus scans.

        Filters results to the current host list so that scope changes
        between runs are handled correctly.

        Args:
            hosts: Current in-scope host list

        Returns:
            ResumeState with completed/pending breakdown
        """
        host_set = set(hosts)

        # Load completed discovery results, filtered to current scope
        all_discovery = self.nmap.load_completed_results(self._discovery_dir)
        completed_discovery = {
            ip: r for ip, r in all_discovery.items() if ip in host_set
        }
        pending_discovery = [ip for ip in hosts if ip not in completed_discovery]

        # Load completed deep results, filtered to current scope
        all_deep = self.nmap.load_completed_results(self._detailed_dir)
        completed_deep = {
            ip: r for ip, r in all_deep.items() if ip in host_set
        }

        # Determine which hosts still need deep scan: hosts with open ports
        # from completed discovery that don't have a completed deep scan
        pending_deep_targets: dict[str, list[int]] = {}
        for ip, result in completed_discovery.items():
            if result.open_ports and ip not in completed_deep:
                pending_deep_targets[ip] = result.open_ports

        # Check for an active Nessus scan
        active_nessus: dict | None = None
        if not self.skip_nessus and self._nessus is not None:
            if self.context.network_drop:
                network_id = self.context.network_drop.get_network_dir()
            else:
                network_id = self.context.output_dir.name
            active_nessus = self._nessus.find_running_scan(network_id)

        return ResumeState(
            completed_discovery=completed_discovery,
            completed_deep=completed_deep,
            active_nessus_scan=active_nessus,
            pending_discovery=pending_discovery,
            pending_deep_targets=pending_deep_targets,
        )

    def _apply_resume_to_dashboard(self) -> None:
        """Pre-populate dashboard with completed results from a previous run."""
        rs = self._resume_state
        if not rs:
            return

        for ip, result in rs.completed_discovery.items():
            self.dashboard.update_host_status(
                ip, "discovery", ScanStatus.COMPLETED, result.open_ports
            )
            self._completed_counts["discovery"] += 1
        self.dashboard.update_progress(
            "discovery", self._completed_counts["discovery"]
        )

        for ip, result in rs.completed_deep.items():
            self.dashboard.update_host_status(
                ip, "deep", ScanStatus.COMPLETED, result.open_ports
            )
            self._completed_counts["deep"] += 1
        self.dashboard.update_progress(
            "deep", self._completed_counts["deep"]
        )

    def _clear_previous_results(self) -> None:
        """Delete all previous Nmap scan artifacts (start fresh flow)."""
        self.nmap.delete_scan_artifacts(self._discovery_dir)
        self.nmap.delete_scan_artifacts(self._detailed_dir)

    def _run_discovery(self, hosts: list[str]) -> dict[str, HostResult]:
        """Run discovery scan phase (resume-aware)."""
        rs = self._resume_state
        results: dict[str, HostResult] = {}

        if rs and rs.completed_discovery:
            results.update(rs.completed_discovery)
            pending = rs.pending_discovery
            if not pending:
                logger.info("All discovery scans already completed — skipping")
                self._discovery_results = results
                self._discovery_complete.set()
                return results
            logger.info(
                f"Resuming discovery: {len(rs.completed_discovery)} done, "
                f"{len(pending)} remaining"
            )
        else:
            pending = hosts

        logger.info(f"Starting discovery scan on {len(pending)} hosts")
        self.dashboard.start_module("discovery")

        new_results = self.nmap.run_discovery_concurrent(
            targets=pending,
            top_ports=self.top_ports,
        )
        results.update(new_results)

        self._discovery_results = results
        self._discovery_complete.set()

        return results
    
    def _run_quality_gate(self, results: dict[str, HostResult]) -> bool:
        """Run quality gate analysis."""
        passed, dead_pct = self.quality_gate.analyze(results)
        
        if not passed:
            logger.warning(f"Quality gate failed: {dead_pct:.1%} hosts appear offline")
            
            # Prompt user
            proceed = Prompts.confirm_quality_gate(
                dead_pct,
                self.config.nmap.quality_gate.dead_host_threshold,
            )
            
            if not proceed:
                logger.info("User chose to abort after quality gate failure")
                return False
        
        return True
    
    def _run_deep_scan(self, discovery_results: dict[str, HostResult]) -> dict[str, HostResult]:
        """Run deep scan phase on discovered ports (resume-aware)."""
        rs = self._resume_state

        # Build targets with their open ports from ALL discovery results
        # (merged old + new when resuming)
        targets_with_ports = {
            ip: result.open_ports
            for ip, result in discovery_results.items()
            if result.open_ports
        }

        # Mark hosts that won't get a deep scan as skipped so the
        # dashboard doesn't leave them stuck on "pending".
        skipped = 0
        for ip in self.dashboard.hosts:
            if ip not in targets_with_ports:
                # Don't double-skip hosts already marked completed by resume
                if not (rs and ip in rs.completed_deep):
                    self.dashboard.update_host_status(ip, "deep", ScanStatus.SKIPPED)
                    skipped += 1
        if skipped:
            self._completed_counts["deep"] += skipped
            self.dashboard.update_progress("deep", self._completed_counts["deep"])

        if not targets_with_ports:
            logger.warning("No open ports found, skipping deep scan")
            return {}

        # Filter out already-completed deep scans when resuming
        results: dict[str, HostResult] = {}
        pending_targets = targets_with_ports

        if rs and rs.completed_deep:
            results.update(rs.completed_deep)
            pending_targets = {
                ip: ports for ip, ports in targets_with_ports.items()
                if ip not in rs.completed_deep
            }
            if not pending_targets:
                logger.info("All deep scans already completed — skipping")
                self._deep_results = results
                return results
            logger.info(
                f"Resuming deep scan: {len(rs.completed_deep)} done, "
                f"{len(pending_targets)} remaining"
            )

        logger.info(f"Starting deep scan on {len(pending_targets)} hosts with open ports")
        self.dashboard.start_module("deep")

        new_results = self.nmap.run_deep_concurrent(pending_targets)
        results.update(new_results)
        self._deep_results = results

        return results
    
    def _run_nessus_scan(self, hosts: list[str]) -> bool:
        """Run Nessus scan phase (resume-aware)."""
        if self.skip_nessus:
            logger.info("Skipping Nessus scan (--skip-nessus)")
            for ip in hosts:
                self.dashboard.update_host_status(ip, "nessus", ScanStatus.SKIPPED)
            return True

        # Filter out excluded hosts — nmap handles this via --excludefile
        # but Nessus receives the raw target list, so we filter here.
        excluded = set(self.context.scope_files.load_excluded_hosts())
        if excluded:
            before = len(hosts)
            removed = [ip for ip in hosts if ip in excluded]
            hosts = [ip for ip in hosts if ip not in excluded]

            if removed:
                logger.info(
                    f"Excluded {len(removed)} host(s) from Nessus scan "
                    f"(matched excluded list): {', '.join(removed)}"
                )
                for ip in removed:
                    self.dashboard.update_host_status(ip, "nessus", ScanStatus.SKIPPED)
                    self._completed_counts["nessus"] += 1
                self.dashboard.update_progress(
                    "nessus", self._completed_counts["nessus"]
                )
            else:
                logger.debug(
                    f"Excluded list has {len(excluded)} host(s) but none "
                    f"overlap with the {before} Nessus targets"
                )

        if not hosts:
            logger.warning("No Nessus targets remain after exclusion filtering")
            return True

        self.dashboard.start_module("nessus")
        bridge = self._get_nessus_bridge()

        # Check if we can reconnect to an active Nessus scan
        rs = self._resume_state
        if rs and rs.active_nessus_scan:
            scan_id = rs.active_nessus_scan["id"]
            logger.info(
                f"Reconnecting to active Nessus scan: "
                f"{rs.active_nessus_scan['name']} (id={scan_id})"
            )
            for ip in hosts:
                self.dashboard.update_host_status(ip, "nessus", ScanStatus.RUNNING)
            return bridge.poll_until_complete(scan_id)

        # Determine network ID for scan naming
        if self.context.network_drop:
            network_id = self.context.network_drop.get_network_dir()
        else:
            network_id = self.context.output_dir.name

        # Create and launch scan
        logger.info(f"Creating Nessus scan for {len(hosts)} targets")

        scan_id = bridge.create_scan(
            network_id=network_id,
            targets=hosts,
        )

        if not scan_id:
            logger.error("Failed to create Nessus scan")
            for ip in hosts:
                self.dashboard.update_host_status(ip, "nessus", ScanStatus.FAILED)
            return False

        if not bridge.launch_scan(scan_id):
            logger.error("Failed to launch Nessus scan")
            return False

        # Update dashboard
        for ip in hosts:
            self.dashboard.update_host_status(ip, "nessus", ScanStatus.RUNNING)

        # Poll until complete
        return bridge.poll_until_complete(scan_id)
    
    def run_linear(self, hosts: list[str]) -> bool:
        """Run linear execution strategy.
        
        Flow: Discovery -> Quality Gate -> Deep Scan -> Nessus
        """
        logger.info("Executing LINEAR strategy")
        
        # Phase 1: Discovery
        discovery_results = self._run_discovery(hosts)
        
        # Phase 2: Quality Gate
        if not self._run_quality_gate(discovery_results):
            return False
        
        # Phase 3: Deep Scan (if enabled)
        deep_module = self.config.global_config.get_module_by_name("nmap_deep")
        if deep_module and deep_module.enabled:
            self._run_deep_scan(discovery_results)
        else:
            logger.info("Skipping deep scan (nmap_deep module disabled)")
            self._skip_deep_for_all_hosts()

        # Phase 4: Nessus
        return self._run_nessus_scan(hosts)
    
    def run_concurrent(self, hosts: list[str]) -> bool:
        """Run concurrent execution strategy.
        
        Flow: (Nessus || Discovery) -> Quality Gate -> Deep Scan
        """
        logger.info("Executing CONCURRENT strategy")
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Launch Nessus and Discovery in parallel
            nessus_future: Future | None = None
            if not self.skip_nessus:
                nessus_future = executor.submit(self._run_nessus_scan, hosts)
            
            discovery_future = executor.submit(self._run_discovery, hosts)
            
            # Wait for discovery to complete
            discovery_results = discovery_future.result()
            
            # Run quality gate
            if not self._run_quality_gate(discovery_results):
                # Cancel Nessus if running
                if nessus_future:
                    nessus_future.cancel()
                return False

            # Run deep scan (if enabled)
            deep_module = self.config.global_config.get_module_by_name("nmap_deep")
            if deep_module and deep_module.enabled:
                self._run_deep_scan(discovery_results)
            else:
                logger.info("Skipping deep scan (nmap_deep module disabled)")
                self._skip_deep_for_all_hosts()

            # Wait for Nessus to complete
            if nessus_future:
                nessus_success = nessus_future.result()
                if not nessus_success:
                    logger.warning("Nessus scan did not complete successfully")
        
        return True
    
    def run(self, hosts: list[str]) -> bool:
        """Run the scanning workflow based on configured strategy.

        Args:
            hosts: List of target hosts

        Returns:
            True if all scans completed successfully
        """
        if not hosts:
            logger.error("No hosts to scan")
            return False

        # Validate sudo credentials before the dashboard takes over the TTY
        if self.nmap.needs_sudo:
            if not self.nmap.validate_sudo():
                logger.error("Cannot proceed without sudo — nmap flags require root")
                return False

        # Pre-connect Nessus so any interactive prompts (session auth
        # fallback) happen before the Rich Live dashboard takes the TTY
        if not self.skip_nessus:
            bridge = self._get_nessus_bridge()
            if not bridge.connect():
                logger.warning("Cannot connect to Nessus — skipping Nessus scans")
                self.skip_nessus = True

        # --- Resume detection ---
        resume_state = self._check_previous_results(hosts)

        if resume_state.has_previous_results:
            all_discovery_done = not resume_state.pending_discovery
            all_deep_done = not resume_state.pending_deep_targets
            no_active_nessus = resume_state.active_nessus_scan is None

            if all_discovery_done and all_deep_done and no_active_nessus:
                # Everything is already done
                if Prompts.confirm_fresh_start(len(hosts)):
                    self._clear_previous_results()
                    resume_state = ResumeState(pending_discovery=hosts)
                else:
                    logger.info("All scans already complete — nothing to do")
                    return True
            else:
                resume = Prompts.confirm_resume(
                    completed_discovery=len(resume_state.completed_discovery),
                    pending_discovery=len(resume_state.pending_discovery),
                    completed_deep=len(resume_state.completed_deep),
                    pending_deep=len(resume_state.pending_deep_targets),
                    active_nessus=resume_state.active_nessus_scan,
                )
                if not resume:
                    # User chose "start fresh"
                    self._clear_previous_results()
                    resume_state = ResumeState(pending_discovery=hosts)

        self._resume_state = resume_state

        # Initialize dashboard
        self.dashboard.add_hosts(hosts)
        self.dashboard.start(total_hosts=len(hosts))

        try:
            # Pre-populate dashboard with completed states from previous run
            if self._resume_state.has_previous_results:
                self._apply_resume_to_dashboard()

            strategy = self.config.global_config.execution_strategy

            if strategy == "concurrent":
                success = self.run_concurrent(hosts)
            else:
                success = self.run_linear(hosts)

            return success

        finally:
            self.dashboard.stop()
            self.dashboard.print_summary()
    
    def get_results(self) -> dict:
        """Get all scan results.
        
        Returns:
            Dict with discovery and deep scan results
        """
        return {
            "discovery": self._discovery_results,
            "deep": self._deep_results,
        }
