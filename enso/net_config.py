"""Netplan configuration wrapper for network interface management."""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import yaml

from .utils.logging import get_logger

logger = get_logger(__name__)


class NetplanManager:
    """Manages Netplan configuration for network interface setup."""
    
    NETPLAN_DIR = Path("/etc/netplan")
    BACKUP_DIR = Path("/etc/netplan/backup")
    
    def __init__(self, interface: str | None = None):
        """Initialize the Netplan manager.
        
        Args:
            interface: Network interface name (auto-detected if not provided)
        """
        self.interface = interface or self._detect_interface()
        self._backup_path: Path | None = None
    
    def _detect_interface(self) -> str:
        """Auto-detect the primary network interface.
        
        Returns:
            Interface name (e.g., 'eth0', 'enp0s3')
        """
        try:
            import netifaces
            
            # Get default gateway interface
            gateways = netifaces.gateways()
            if netifaces.AF_INET in gateways.get("default", {}):
                return gateways["default"][netifaces.AF_INET][1]
            
            # Fall back to first non-loopback interface
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface != "lo" and not iface.startswith("veth"):
                    return iface
        except Exception as e:
            logger.warning(f"Failed to auto-detect interface: {e}")
        
        # Last resort default
        return "eth0"
    
    def _find_config_file(self) -> Path | None:
        """Find the current netplan configuration file.
        
        Returns:
            Path to the config file, or None if not found
        """
        for yaml_file in sorted(self.NETPLAN_DIR.glob("*.yaml")):
            return yaml_file
        return None
    
    def backup(self) -> Path:
        """Backup the current netplan configuration.
        
        Uses sudo to create backup directory and copy files since /etc/netplan
        requires root permissions.
        
        Returns:
            Path to the backup directory
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.BACKUP_DIR / f"backup_{timestamp}"
        
        try:
            # Create backup directory with sudo
            subprocess.run(
                ["sudo", "mkdir", "-p", str(backup_path)],
                check=True,
                capture_output=True,
            )
            
            # Copy all YAML files with sudo
            for yaml_file in self.NETPLAN_DIR.glob("*.yaml"):
                subprocess.run(
                    ["sudo", "cp", "-p", str(yaml_file), str(backup_path / yaml_file.name)],
                    check=True,
                    capture_output=True,
                )
                logger.debug(f"Backed up {yaml_file.name}")
            
            self._backup_path = backup_path
            logger.info(f"Netplan configuration backed up to {backup_path}")
            return backup_path
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to backup netplan config: {e}")
            raise RuntimeError(f"Backup failed: {e.stderr.decode() if e.stderr else e}")
    
    def restore(self, backup_path: Path | None = None) -> None:
        """Restore netplan configuration from backup.
        
        Uses sudo for file operations since /etc/netplan requires root.
        
        Args:
            backup_path: Path to backup directory (uses last backup if not provided)
        """
        restore_from = backup_path or self._backup_path
        
        if not restore_from or not restore_from.exists():
            raise ValueError("No backup available to restore")
        
        try:
            # Remove current configs with sudo
            for yaml_file in self.NETPLAN_DIR.glob("*.yaml"):
                subprocess.run(
                    ["sudo", "rm", "-f", str(yaml_file)],
                    check=True,
                    capture_output=True,
                )
            
            # Restore from backup with sudo
            for yaml_file in restore_from.glob("*.yaml"):
                subprocess.run(
                    ["sudo", "cp", "-p", str(yaml_file), str(self.NETPLAN_DIR / yaml_file.name)],
                    check=True,
                    capture_output=True,
                )
            
            # Apply restored config
            self._apply_netplan()
            logger.info(f"Netplan configuration restored from {restore_from}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restore netplan config: {e}")
            raise RuntimeError(f"Restore failed: {e.stderr.decode() if e.stderr else e}")
    
    def generate_config(
        self,
        ip: str,
        subnet: str,
        gateway: str,
        dns: list[str] | None = None,
    ) -> dict:
        """Generate a netplan configuration dictionary.

        Args:
            ip: Static IP address
            subnet: Subnet in CIDR notation (e.g., "24")
            gateway: Gateway IP address
            dns: List of DNS server IPs

        Returns:
            Netplan configuration dictionary
        """
        interface_config = {
            "dhcp4": False,
            "addresses": [f"{ip}/{subnet}"],
            "routes": [{"to": "default", "via": gateway}],
        }

        if dns:
            interface_config["nameservers"] = {"addresses": dns}

        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {
                    self.interface: interface_config,
                },
            }
        }

        return config
    
    def apply_config(
        self,
        ip: str,
        subnet: str,
        gateway: str,
        dns: list[str] | None = None,
    ) -> None:
        """Generate and apply a new netplan configuration.

        Uses sudo to write config files since /etc/netplan requires root.

        Args:
            ip: Static IP address
            subnet: Subnet in CIDR notation
            gateway: Gateway IP address
            dns: List of DNS server IPs
        """
        import tempfile

        config = self.generate_config(ip, subnet, gateway, dns)
        
        # Determine config file path
        config_file = self._find_config_file()
        target_file = config_file or self.NETPLAN_DIR / "01-enso-config.yaml"
        
        try:
            # Write to temp file first
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                yaml.dump(config, f, default_flow_style=False)
                temp_path = f.name
            
            # Move to destination with sudo
            subprocess.run(
                ["sudo", "mv", temp_path, str(target_file)],
                check=True,
                capture_output=True,
            )
            
            # Set proper permissions
            subprocess.run(
                ["sudo", "chmod", "600", str(target_file)],
                check=True,
                capture_output=True,
            )
            
            logger.info(f"Wrote netplan configuration to {target_file}")
            
            # Apply the configuration
            self._apply_netplan()
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply netplan config: {e}")
            raise RuntimeError(f"Config apply failed: {e.stderr.decode() if e.stderr else e}")
    
    def apply_dhcp_config(self) -> None:
        """Apply a DHCP configuration to the interface.
        
        Uses sudo to write config files since /etc/netplan requires root.
        """
        import tempfile
        
        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {
                    self.interface: {
                        "dhcp4": True,
                    },
                },
            }
        }
        
        # Determine config file path
        config_file = self._find_config_file()
        target_file = config_file or self.NETPLAN_DIR / "01-enso-config.yaml"
        
        try:
            # Write to temp file first
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                yaml.dump(config, f, default_flow_style=False)
                temp_path = f.name
            
            # Move to destination with sudo
            subprocess.run(
                ["sudo", "mv", temp_path, str(target_file)],
                check=True,
                capture_output=True,
            )
            
            # Set proper permissions
            subprocess.run(
                ["sudo", "chmod", "600", str(target_file)],
                check=True,
                capture_output=True,
            )
            
            logger.info(f"Wrote DHCP netplan configuration to {target_file}")
            
            # Apply the configuration
            self._apply_netplan()
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply DHCP config: {e}")
            raise RuntimeError(f"DHCP config failed: {e.stderr.decode() if e.stderr else e}")
    
    def _apply_netplan(self) -> None:
        """Apply the current netplan configuration.
        
        Uses sudo netplan apply directly since netplan try requires
        interactive confirmation which doesn't work in automated scenarios.
        """
        try:
            result = subprocess.run(
                ["sudo", "netplan", "apply"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode != 0:
                logger.error(f"netplan apply failed: {result.stderr}")
                raise RuntimeError(f"netplan apply failed: {result.stderr}")
            
            logger.info("Netplan configuration applied successfully")
            
        except subprocess.TimeoutExpired:
            logger.error("Netplan apply timed out")
            raise RuntimeError("Netplan configuration apply timed out")
        except Exception as e:
            logger.error(f"Failed to apply netplan: {e}")
            raise
    
    def get_current_ip(self) -> str | None:
        """Get the current IP address of the interface.
        
        Returns:
            Current IP address, or None if not assigned
        """
        try:
            import netifaces
            
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]["addr"]
        except Exception as e:
            logger.debug(f"Failed to get current IP: {e}")
        
        return None
