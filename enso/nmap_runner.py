"""Nmap scanning engine with concurrent execution and XML parsing."""

from __future__ import annotations

import os
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import NmapConfig
from .ui.dashboard import ScanStatus
from .utils.logging import get_logger, ScanLogger

logger = get_logger(__name__)

# Nmap flags that require raw sockets / root privileges
_ROOT_FLAGS = {
    "-sS", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX",
    "-sY", "-sZ", "-O", "--traceroute", "--send-eth",
}


def _flags_need_root(flags: str) -> bool:
    """Check if any nmap flags in the string require root privileges."""
    return bool(set(flags.split()) & _ROOT_FLAGS)


@dataclass
class PortInfo:
    """Information about a discovered port."""
    
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""


@dataclass
class HostResult:
    """Results from scanning a single host."""
    
    ip: str
    status: str = "unknown"  # up, down, unknown
    ports: list[PortInfo] = field(default_factory=list)
    os_match: str = ""
    scan_time: float = 0.0
    error: str | None = None
    
    @property
    def open_ports(self) -> list[int]:
        """Get list of open port numbers."""
        return [p.port for p in self.ports if p.state == "open"]


class NmapRunner:
    """Executes Nmap scans with concurrent threading and XML output parsing."""

    @staticmethod
    def is_xml_complete(xml_path: Path) -> bool:
        """Check if an Nmap XML file represents a completed scan.

        Nmap writes the XML file as soon as a scan starts, but only appends
        the ``<runstats>`` element when the scan finishes normally.  An
        interrupted scan will have the XML header but no ``<runstats>``.

        Args:
            xml_path: Path to the Nmap XML output file

        Returns:
            True if the XML contains a ``<runstats>`` element (scan completed)
        """
        if not xml_path.exists():
            return False
        try:
            tree = ET.parse(xml_path)
            return tree.getroot().find("runstats") is not None
        except (ET.ParseError, Exception):
            return False

    def load_completed_results(self, scan_dir: Path) -> dict[str, HostResult]:
        """Load previously completed scan results from disk.

        Globs XML files in the given directory, checks each for
        completeness via ``is_xml_complete()``, and parses completed ones
        with ``_parse_xml_results()``.

        Args:
            scan_dir: Absolute path to the scan output directory

        Returns:
            Dict mapping IP address to HostResult for all completed scans
        """
        results: dict[str, HostResult] = {}

        if not scan_dir.exists():
            return results

        dir_name = scan_dir.name
        for xml_path in scan_dir.glob("*.xml"):
            if not self.is_xml_complete(xml_path):
                logger.debug(f"Skipping incomplete XML: {xml_path}")
                continue

            result = self._parse_xml_results(xml_path)
            if result.ip and result.ip != "unknown" and not result.error:
                results[result.ip] = result
                logger.debug(
                    f"Loaded completed {dir_name} result for {result.ip} "
                    f"({len(result.open_ports)} open ports)"
                )

        if results:
            logger.info(
                f"Found {len(results)} completed {dir_name} scan(s) on disk"
            )

        return results

    def delete_scan_artifacts(self, scan_dir: Path) -> int:
        """Delete all files in a scan output directory.

        Used by the "start fresh" flow to clear previous results before
        re-scanning.

        Args:
            scan_dir: Absolute path to the scan output directory

        Returns:
            Number of files deleted
        """
        count = 0

        if not scan_dir.exists():
            return count

        dir_name = scan_dir.name
        for f in scan_dir.iterdir():
            if f.is_file():
                f.unlink()
                count += 1

        if count:
            logger.info(f"Deleted {count} {dir_name} artifact(s)")

        return count

    def __init__(
        self,
        config: NmapConfig,
        discovery_dir: Path,
        detailed_dir: Path,
        log_dir: Path,
        progress_callback: Callable[[str, str, ScanStatus, list[int] | None], None] | None = None,
        exclude_file: Path | None = None,
    ):
        """Initialize the Nmap runner.

        Args:
            config: Nmap configuration
            discovery_dir: Directory for discovery scan output files
            detailed_dir: Directory for deep scan output files
            log_dir: Directory for nmap command log files
            progress_callback: Callback function for progress updates
                              (ip, scan_type, status, open_ports)
            exclude_file: Optional path to file containing excluded hosts
        """
        self.config = config
        self.discovery_dir = discovery_dir
        self.detailed_dir = detailed_dir
        self.log_dir = log_dir
        self.progress_callback = progress_callback
        self.exclude_file = exclude_file

        # Determine if sudo is needed (not root + flags require raw sockets)
        self._use_sudo = os.geteuid() != 0 and (
            _flags_need_root(config.discovery.flags)
            or _flags_need_root(config.deep.flags)
        )

        # Ensure output directories exist
        self.discovery_dir.mkdir(parents=True, exist_ok=True)
        self.detailed_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    @property
    def needs_sudo(self) -> bool:
        """Whether scans require sudo for privileged nmap flags."""
        return self._use_sudo

    def validate_sudo(self) -> bool:
        """Prompt the user to cache sudo credentials before scanning.

        Runs ``sudo -v`` which prompts for a password (if needed) and
        refreshes the cached credential timestamp.  Must be called on an
        interactive TTY *before* the Rich Live dashboard starts.

        Returns:
            True if sudo credentials were validated successfully.
        """
        if not self._use_sudo:
            return True

        logger.info("Nmap flags require root privileges — requesting sudo")
        try:
            result = subprocess.run(
                ["sudo", "-v"],
                stdin=None,       # inherit TTY for password prompt
                check=False,
            )
            if result.returncode != 0:
                logger.error("sudo credential validation failed")
                return False
            return True
        except FileNotFoundError:
            logger.error("sudo not found on this system")
            return False
    
    def _build_discovery_command(
        self,
        target: str,
        output_base: Path,
        top_ports: int | None = None,
    ) -> list[str]:
        """Build the Nmap discovery scan command.

        Args:
            target: Target IP or hostname
            output_base: Base path for output files (without extension)
            top_ports: If set, use --top-ports instead of -p-

        Returns:
            Command as list of arguments
        """
        cmd = ["sudo", "nmap"] if self._use_sudo else ["nmap"]
        
        # Add configured flags
        cmd.extend(self.config.discovery.flags.split())
        
        # Port specification
        default_ports = self.config.discovery.default_ports
        if top_ports:
            # Override from function parameter
            cmd.extend(["--top-ports", str(top_ports)])
        elif default_ports == "all" or default_ports == "-":
            # Scan all 65535 ports
            cmd.append("-p-")
        elif isinstance(default_ports, int):
            # Top N ports
            cmd.extend(["--top-ports", str(default_ports)])
        elif isinstance(default_ports, str) and "," in default_ports:
            # Custom port list (e.g., "22,80,443,8080")
            cmd.extend(["-p", default_ports])
        elif isinstance(default_ports, str) and default_ports.isdigit():
            # String number - treat as top-ports
            cmd.extend(["--top-ports", default_ports])
        else:
            # Default to all ports
            cmd.append("-p-")
        
        # Host timeout
        if self.config.host_timeout:
            cmd.extend(["--host-timeout", self.config.host_timeout])

        # Exclude file
        if self.exclude_file and self.exclude_file.exists():
            cmd.extend(["--excludefile", str(self.exclude_file)])

        # Output formats
        cmd.extend(["-oA", str(output_base)])

        # Target
        cmd.append(target)

        return cmd

    def _build_deep_command(
        self,
        target: str,
        ports: list[int],
        output_base: Path,
    ) -> list[str]:
        """Build the Nmap deep scan command.

        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            output_base: Base path for output files

        Returns:
            Command as list of arguments
        """
        cmd = ["sudo", "nmap"] if self._use_sudo else ["nmap"]
        
        # Add configured flags
        cmd.extend(self.config.deep.flags.split())
        
        # Specific ports
        port_spec = ",".join(map(str, ports))
        cmd.extend(["-p", port_spec])

        # Host timeout
        if self.config.host_timeout:
            cmd.extend(["--host-timeout", self.config.host_timeout])

        # Exclude file
        if self.exclude_file and self.exclude_file.exists():
            cmd.extend(["--excludefile", str(self.exclude_file)])

        # Output formats
        cmd.extend(["-oA", str(output_base)])

        # Target
        cmd.append(target)

        return cmd
    
    def _run_nmap_command(
        self,
        cmd: list[str],
        target: str,
        scan_type: str,
    ) -> tuple[int, Path | None, bool]:
        """Execute an Nmap command and capture output.

        Args:
            cmd: Command to execute
            target: Target for logging
            scan_type: Type of scan for logging

        Returns:
            Tuple of (return_code, xml_output_path, host_timed_out)
        """
        logger.debug(f"Running: {' '.join(cmd)}")

        # Setup scan logger for raw output
        host_timed_out = False

        with ScanLogger(self.log_dir, f"nmap_{scan_type}", target) as scan_log:
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

                # Stream output to log file, keep tail for error reporting
                last_lines: list[str] = []
                for line in process.stdout:
                    scan_log.write(line)
                    stripped = line.rstrip()
                    if stripped:
                        last_lines.append(stripped)
                        if len(last_lines) > 5:
                            last_lines.pop(0)
                        # nmap prints "Skipping host <ip> due to host timeout"
                        if "host timeout" in stripped.lower():
                            host_timed_out = True

                return_code = process.wait()

                if return_code != 0:
                    logger.warning(
                        f"nmap {scan_type} for {target} exited with rc={return_code}"
                    )
                    for tail_line in last_lines:
                        logger.warning(f"  nmap: {tail_line}")

                # Find the XML output file via -oA flag
                xml_path = None
                for i, arg in enumerate(cmd):
                    if arg == "-oA" and i + 1 < len(cmd):
                        xml_path = Path(cmd[i + 1] + ".xml")
                        if xml_path.exists():
                            break

                return return_code, xml_path, host_timed_out

            except subprocess.SubprocessError as e:
                logger.error(f"Nmap execution failed for {target}: {e}")
                scan_log.write(f"\nError: {e}")
                return 1, None, False
    
    def _parse_xml_results(self, xml_path: Path) -> HostResult:
        """Parse Nmap XML output file.
        
        Args:
            xml_path: Path to the XML output file
            
        Returns:
            Parsed HostResult
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Find host element
            host_elem = root.find("host")
            if host_elem is None:
                return HostResult(ip="unknown", error="No host data in XML")
            
            # Get IP address
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"
            
            # Get host status
            status_elem = host_elem.find("status")
            status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
            
            # Parse ports
            ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_num = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")
                    
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    
                    service_elem = port_elem.find("service")
                    service = ""
                    version = ""
                    if service_elem is not None:
                        service = service_elem.get("name", "")
                        version = service_elem.get("product", "")
                        if service_elem.get("version"):
                            version += f" {service_elem.get('version')}"
                    
                    ports.append(PortInfo(
                        port=port_num,
                        protocol=protocol,
                        state=state,
                        service=service,
                        version=version.strip(),
                    ))
            
            # Parse OS detection
            os_match = ""
            os_elem = host_elem.find("os/osmatch")
            if os_elem is not None:
                os_match = os_elem.get("name", "")
            
            # Get scan time
            scan_time = 0.0
            runstats = root.find("runstats/finished")
            if runstats is not None:
                scan_time = float(runstats.get("elapsed", 0))
            
            return HostResult(
                ip=ip,
                status=status,
                ports=ports,
                os_match=os_match,
                scan_time=scan_time,
            )
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML {xml_path}: {e}")
            return HostResult(ip="unknown", error=f"XML parse error: {e}")
        except Exception as e:
            logger.error(f"Error parsing results from {xml_path}: {e}")
            return HostResult(ip="unknown", error=str(e))
    
    def discovery_scan(
        self,
        target: str,
        top_ports: int | None = None,
    ) -> HostResult:
        """Run a discovery scan on a single target.
        
        Args:
            target: Target IP or hostname
            top_ports: If set, limit to top N ports
            
        Returns:
            HostResult with discovered ports
        """
        sanitized = target.replace("/", "_").replace(":", "_")
        output_base = self.discovery_dir / sanitized

        if self.progress_callback:
            self.progress_callback(target, "discovery", ScanStatus.RUNNING, None)

        cmd = self._build_discovery_command(target, output_base, top_ports)
        return_code, xml_path, timed_out = self._run_nmap_command(cmd, target, "discovery")

        if return_code != 0 or xml_path is None or not xml_path.exists():
            detail = f"rc={return_code}"
            if xml_path and not xml_path.exists():
                detail += ", no XML output"
            logger.error(f"Discovery scan failed for {target}: {detail}")
            result = HostResult(ip=target, status="error", error=f"Scan failed ({detail})")
            if self.progress_callback:
                self.progress_callback(target, "discovery", ScanStatus.FAILED, None)
            return result

        result = self._parse_xml_results(xml_path)
        result.ip = target  # Ensure target IP is preserved

        if timed_out:
            logger.warning(f"Discovery scan timed out for {target}")
            result.error = "host timeout"
            status = ScanStatus.TIMEOUT
        else:
            status = ScanStatus.COMPLETED

        if self.progress_callback:
            self.progress_callback(target, "discovery", status, result.open_ports)

        return result
    
    def deep_scan(self, target: str, ports: list[int]) -> HostResult:
        """Run a deep scan on a single target with specific ports.
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            
        Returns:
            HostResult with detailed service information
        """
        if not ports:
            logger.warning(f"No ports to deep scan for {target}")
            return HostResult(ip=target, status="skipped", error="No open ports")
        
        sanitized = target.replace("/", "_").replace(":", "_")
        output_base = self.detailed_dir / sanitized

        if self.progress_callback:
            self.progress_callback(target, "deep", ScanStatus.RUNNING, None)
        
        cmd = self._build_deep_command(target, ports, output_base)
        return_code, xml_path, timed_out = self._run_nmap_command(cmd, target, "deep")

        if return_code != 0 or xml_path is None or not xml_path.exists():
            detail = f"rc={return_code}"
            if xml_path and not xml_path.exists():
                detail += ", no XML output"
            logger.error(f"Deep scan failed for {target}: {detail}")
            result = HostResult(ip=target, status="error", error=f"Deep scan failed ({detail})")
            if self.progress_callback:
                self.progress_callback(target, "deep", ScanStatus.FAILED, None)
            return result

        result = self._parse_xml_results(xml_path)
        result.ip = target

        if timed_out:
            logger.warning(f"Deep scan timed out for {target}")
            result.error = "host timeout"
            status = ScanStatus.TIMEOUT
        else:
            status = ScanStatus.COMPLETED

        if self.progress_callback:
            self.progress_callback(target, "deep", status, result.open_ports)

        return result
    
    def run_discovery_concurrent(
        self,
        targets: list[str],
        top_ports: int | None = None,
    ) -> dict[str, HostResult]:
        """Run discovery scans on multiple targets concurrently.
        
        Args:
            targets: List of target IPs/hostnames
            top_ports: If set, limit to top N ports
            
        Returns:
            Dict mapping target to HostResult
        """
        results: dict[str, HostResult] = {}
        
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = {
                executor.submit(self.discovery_scan, target, top_ports): target
                for target in targets
            }
            
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results[target] = result
                    logger.info(
                        f"Discovery complete: {target} - "
                        f"{len(result.open_ports)} open ports"
                    )
                except Exception as e:
                    logger.error(f"Discovery failed for {target}: {e}")
                    results[target] = HostResult(ip=target, status="error", error=str(e))
        
        return results
    
    def run_deep_concurrent(
        self,
        targets_with_ports: dict[str, list[int]],
    ) -> dict[str, HostResult]:
        """Run deep scans on multiple targets concurrently.
        
        Args:
            targets_with_ports: Dict mapping target to list of ports to scan
            
        Returns:
            Dict mapping target to HostResult
        """
        results: dict[str, HostResult] = {}
        
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = {
                executor.submit(self.deep_scan, target, ports): target
                for target, ports in targets_with_ports.items()
                if ports  # Skip hosts with no open ports
            }
            
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results[target] = result
                    logger.info(f"Deep scan complete: {target}")
                except Exception as e:
                    logger.error(f"Deep scan failed for {target}: {e}")
                    results[target] = HostResult(ip=target, status="error", error=str(e))
        
        return results


class QualityGate:
    """Analyzes scan results to detect potential network issues."""
    
    def __init__(self, dead_threshold: float = 0.7):
        """Initialize the quality gate.
        
        Args:
            dead_threshold: Threshold for dead host percentage (0.0 - 1.0)
        """
        self.dead_threshold = dead_threshold
    
    def analyze(self, results: dict[str, HostResult]) -> tuple[bool, float]:
        """Analyze discovery results for potential issues.

        Args:
            results: Discovery scan results

        Returns:
            Tuple of (passed, offline_percentage)
        """
        if not results:
            return False, 1.0

        total = len(results)
        offline = sum(
            1 for r in results.values()
            if r.status == "down" or not r.open_ports
        )

        offline_pct = offline / total
        passed = offline_pct < self.dead_threshold

        msg = (
            f"Quality Gate: {offline}/{total} hosts appear offline "
            f"({offline_pct:.1%}), threshold: {self.dead_threshold:.1%}"
        )

        if not passed:
            logger.warning(f"[bold red]{msg}[/bold red]", extra={"markup": True})
        elif offline_pct >= 0.5:
            logger.warning(f"[yellow]{msg}[/yellow]", extra={"markup": True})
        else:
            logger.info(f"[green]{msg}[/green]", extra={"markup": True})

        return passed, offline_pct
