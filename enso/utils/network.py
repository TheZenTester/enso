"""Network connectivity utilities for validation."""

from __future__ import annotations

import random
import subprocess
from pathlib import Path

import dns.resolver
import netifaces

from .logging import get_logger

logger = get_logger(__name__)


def check_interface_link(interface: str) -> dict[str, str | bool]:
    """Check physical link state of a network interface.

    Reads carrier and operstate from ``/sys/class/net/<iface>/``.
    Does **not** require an IP address — only checks layer-1 link.

    Args:
        interface: Interface name (e.g. ``eth0``, ``enxd8ec5e11983b``)

    Returns:
        Dict with keys:
        - ``exists`` (bool): Interface exists in sysfs
        - ``carrier`` (bool): Cable physically connected (link detected)
        - ``operstate`` (str): Kernel operstate (``"up"``, ``"down"``,
          ``"unknown"``, or ``""`` if unreadable)
    """
    sys_path = Path(f"/sys/class/net/{interface}")

    if not sys_path.is_dir():
        return {"exists": False, "carrier": False, "operstate": ""}

    # operstate is always readable
    operstate = ""
    try:
        operstate = (sys_path / "operstate").read_text().strip()
    except OSError:
        pass

    # carrier requires the interface to be admin-up; if it's admin-down
    # the read raises OSError / returns "0".
    carrier = False
    try:
        carrier = (sys_path / "carrier").read_text().strip() == "1"
    except OSError:
        pass

    return {"exists": True, "carrier": carrier, "operstate": operstate}


def get_available_interfaces() -> list[str]:
    """Get list of available network interfaces, excluding loopback and virtual.
    
    Returns:
        List of interface names suitable for network configuration
    """
    interfaces = []
    for iface in netifaces.interfaces():
        # Skip loopback and common virtual interfaces
        if iface == "lo" or iface.startswith(("docker", "veth", "br-", "virbr")):
            continue
        # Only include interfaces that have at least an IPv4 or can receive one
        addrs = netifaces.ifaddresses(iface)
        # Include if it exists (even without current IP, we can assign one)
        interfaces.append(iface)
    
    return sorted(interfaces)


class ConnectivityValidator:
    """Validates network connectivity before scanning operations."""
    
    def __init__(self):
        """Initialize the connectivity validator."""
        pass
    
    def ping_host(self, host: str, count: int = 3, timeout: int = 2) -> bool:
        """Ping a single host to verify connectivity.
        
        Args:
            host: IP address or hostname to ping
            count: Number of ping attempts
            timeout: Timeout in seconds per ping
            
        Returns:
            True if at least one ping succeeds
        """
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), host],
                capture_output=True,
                text=True,
                timeout=count * timeout + 5,
            )
            success = result.returncode == 0
            if success:
                logger.debug(f"Ping to {host} succeeded")
            else:
                logger.debug(f"Ping to {host} failed: {result.stderr.strip()}")
            return success
        except subprocess.TimeoutExpired:
            logger.warning(f"Ping to {host} timed out")
            return False
        except Exception as e:
            logger.error(f"Ping error for {host}: {e}")
            return False
    
    def ping_gateway(self, gateway: str, retries: int = 3) -> bool:
        """Validate connectivity to the network gateway.
        
        Args:
            gateway: Gateway IP address
            retries: Number of ping attempts
            
        Returns:
            True if gateway is reachable
        """
        logger.info(f"Validating gateway connectivity: {gateway}")
        return self.ping_host(gateway, count=retries)
    
    def resolve_fqdn(self, fqdn: str, nameserver: str | None = None) -> str | None:
        """Resolve a Fully Qualified Domain Name to validate DNS.
        
        Args:
            fqdn: The FQDN to resolve
            nameserver: Optional specific nameserver to use
            
        Returns:
            Resolved IP address, or None if resolution fails
        """
        logger.info(f"Resolving FQDN: {fqdn}")
        
        try:
            resolver = dns.resolver.Resolver()
            if nameserver:
                resolver.nameservers = [nameserver]
            
            answers = resolver.resolve(fqdn, "A")
            if answers:
                ip = str(answers[0])
                logger.info(f"Resolved {fqdn} -> {ip}")
                return ip
        except dns.resolver.NXDOMAIN:
            logger.warning(f"FQDN not found: {fqdn}")
        except dns.resolver.NoAnswer:
            logger.warning(f"No A record for: {fqdn}")
        except dns.resolver.Timeout:
            logger.warning(f"DNS resolution timed out for: {fqdn}")
        except Exception as e:
            logger.error(f"DNS resolution error for {fqdn}: {e}")
        
        return None
    
    def ping_random_hosts(
        self,
        scope_file: Path,
        count: int = 5,
    ) -> tuple[int, int]:
        """Ping random hosts from a scope file to validate network reach.
        
        Args:
            scope_file: Path to file containing one IP per line
            count: Number of random hosts to ping
            
        Returns:
            Tuple of (successful_pings, total_attempted)
        """
        if not scope_file.exists():
            logger.error(f"Scope file not found: {scope_file}")
            return 0, 0
        
        # Read hosts from scope file
        with open(scope_file, "r") as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        if not hosts:
            logger.warning(f"No hosts found in scope file: {scope_file}")
            return 0, 0
        
        # Select random sample
        sample_size = min(count, len(hosts))
        sample_hosts = random.sample(hosts, sample_size)
        
        logger.info(f"Pinging {sample_size} random hosts from scope")
        
        successful = 0
        for host in sample_hosts:
            if self.ping_host(host, count=1):
                successful += 1
        
        logger.info(f"Random host ping results: {successful}/{sample_size} reachable")
        return successful, sample_size
    
    def full_validation(
        self,
        gateway: str,
        scope_file: Path,
        fqdn: str | None = None,
        dns_server: str | None = None,
    ) -> dict[str, bool]:
        """Perform full connectivity validation sequence.
        
        Args:
            gateway: Gateway IP address
            scope_file: Path to in_scope.txt file
            fqdn: Optional FQDN to resolve (prompts user if not provided)
            dns_server: Optional DNS server IP
            
        Returns:
            Dict with validation results for each step
        """
        results = {
            "gateway": False,
            "hosts": False,
            "dns": True,  # Default to True if no FQDN provided
        }

        # Step 1: Gateway ping
        results["gateway"] = self.ping_gateway(gateway)
        if not results["gateway"]:
            logger.error("Gateway unreachable - aborting validation")
            return results

        # Step 2: Random host pings
        successful, total = self.ping_random_hosts(scope_file)
        results["hosts"] = successful > 0

        # Step 3: DNS (if FQDN provided)
        if fqdn:
            resolved = self.resolve_fqdn(fqdn, dns_server)
            results["dns"] = resolved is not None

        return results
