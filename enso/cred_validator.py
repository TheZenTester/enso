"""Credential validation using nxc (NetExec).

Validates Windows and Linux credentials against in-scope hosts
before running Nessus authenticated scans.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .config import CredentialsConfig
from .ui.prompts import Prompts
from .utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of credential validation for a single credential set."""
    
    credential_name: str
    credential_type: str  # "ssh" or "smb"
    username: str
    domain: str | None = None
    
    total_hosts: int = 0
    successful_hosts: list[str] = field(default_factory=list)
    failed_hosts: list[str] = field(default_factory=list)
    
    @property
    def success_count(self) -> int:
        return len(self.successful_hosts)
    
    @property
    def failure_count(self) -> int:
        return len(self.failed_hosts)
    
    @property
    def success_rate(self) -> float:
        if self.total_hosts == 0:
            return 0.0
        return (self.success_count / self.total_hosts) * 100


@dataclass
class CredentialValidationReport:
    """Full report of all credential validations."""
    
    timestamp: datetime = field(default_factory=datetime.now)
    results: list[ValidationResult] = field(default_factory=list)
    output_file: Path | None = None
    
    @property
    def total_linux_success(self) -> int:
        return sum(r.success_count for r in self.results if r.credential_type == "ssh")
    
    @property
    def total_linux_failed(self) -> int:
        return sum(r.failure_count for r in self.results if r.credential_type == "ssh")
    
    @property
    def total_windows_success(self) -> int:
        return sum(r.success_count for r in self.results if r.credential_type == "smb")
    
    @property
    def total_windows_failed(self) -> int:
        return sum(r.failure_count for r in self.results if r.credential_type == "smb")


class CredentialValidator:
    """Validate credentials against target hosts using nxc."""
    
    def __init__(
        self,
        credentials: CredentialsConfig,
        targets: list[str],
        output_dir: Path | None = None,
        cred_check_subdir: str = "cred_checks",
    ):
        """Initialize the credential validator.

        Args:
            credentials: Credentials configuration
            targets: List of target IP addresses/hostnames
            output_dir: Directory for output files
            cred_check_subdir: Subdirectory name for credential check reports
        """
        self.credentials = credentials
        self.targets = targets
        self.output_dir = output_dir or Path(".")
        self.cred_check_subdir = cred_check_subdir
        self._nxc_available: bool | None = None
    
    def check_nxc_available(self) -> bool:
        """Check if nxc is available on the system."""
        if self._nxc_available is not None:
            return self._nxc_available

        try:
            # nxc --version returns exit code 1 despite working correctly,
            # so just check that it executes without FileNotFoundError
            subprocess.run(
                ["nxc", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self._nxc_available = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._nxc_available = False

        return self._nxc_available
    
    def _create_targets_file(self) -> Path:
        """Create a temporary file with target hosts."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
        ) as f:
            for target in self.targets:
                f.write(f"{target}\n")
            return Path(f.name)
    
    def _parse_nxc_output(self, output: str, targets: list[str]) -> tuple[list[str], list[str]]:
        """Parse nxc output to extract successful and failed hosts.
        
        Args:
            output: nxc command output
            targets: List of targets that were tested
            
        Returns:
            Tuple of (successful_hosts, failed_hosts)
        """
        successful = []
        failed = []
        
        for line in output.splitlines():
            # nxc output format: PROTOCOL  IP  PORT  STATUS  MESSAGE
            # Success: [+] or green coloring
            # Failure: [-] or red coloring
            
            # Extract IP from the line
            parts = line.split()
            if len(parts) < 2:
                continue
            
            # Try to find an IP address in the line
            ip = None
            for part in parts:
                # Simple IP check - starts with digit and contains dots
                if part and part[0].isdigit() and "." in part:
                    ip = part
                    break
            
            if not ip:
                continue
            
            if "[+]" in line or "Pwn3d!" in line:
                if ip not in successful:
                    successful.append(ip)
            elif "[-]" in line:
                if ip not in failed:
                    failed.append(ip)
        
        return successful, failed
    
    def validate_ssh_credential(
        self,
        cred_name: str,
        username: str,
        password: str,
    ) -> ValidationResult:
        """Validate SSH credentials against targets.
        
        Args:
            cred_name: Name of the credential set
            username: SSH username
            password: SSH password
            
        Returns:
            ValidationResult with success/failure counts
        """
        result = ValidationResult(
            credential_name=cred_name,
            credential_type="ssh",
            username=username,
            total_hosts=len(self.targets),
        )
        
        if not self.targets:
            logger.warning("No targets to validate")
            return result
        
        targets_file = self._create_targets_file()
        
        try:
            cmd = [
                "nxc", "ssh",
                str(targets_file),
                "-u", username,
                "-p", password,
                "--no-bruteforce",
                "--no-progress",
            ]
            
            logger.debug(f"Running: nxc ssh {targets_file} -u {username} -p ***")
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            
            output = proc.stdout + proc.stderr
            successful, failed = self._parse_nxc_output(output, self.targets)
            
            result.successful_hosts = successful
            result.failed_hosts = failed
            
        except subprocess.TimeoutExpired:
            logger.error("SSH validation timed out")
            result.failed_hosts = list(self.targets)
        except Exception as e:
            logger.error(f"SSH validation error: {e}")
            result.failed_hosts = list(self.targets)
        finally:
            targets_file.unlink(missing_ok=True)
        
        return result
    
    def validate_smb_credential(
        self,
        cred_name: str,
        username: str,
        password: str,
        domain: str,
    ) -> ValidationResult:
        """Validate SMB credentials against targets.
        
        Args:
            cred_name: Name of the credential set
            username: Windows username
            password: Windows password
            domain: Windows domain
            
        Returns:
            ValidationResult with success/failure counts
        """
        result = ValidationResult(
            credential_name=cred_name,
            credential_type="smb",
            username=username,
            domain=domain,
            total_hosts=len(self.targets),
        )
        
        if not self.targets:
            logger.warning("No targets to validate")
            return result
        
        targets_file = self._create_targets_file()
        
        try:
            cmd = [
                "nxc", "smb",
                str(targets_file),
                "-u", username,
                "-p", password,
            ]

            # Local accounts (empty or "." domain) need --local-auth
            if not domain or domain == ".":
                cmd.append("--local-auth")
                logger.debug(f"Running: nxc smb {targets_file} -u {username} -p *** --local-auth")
            else:
                cmd.extend(["-d", domain])
                logger.debug(f"Running: nxc smb {targets_file} -u {username} -p *** -d {domain}")

            cmd.extend(["--no-bruteforce", "--no-progress"])
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            
            output = proc.stdout + proc.stderr
            successful, failed = self._parse_nxc_output(output, self.targets)
            
            result.successful_hosts = successful
            result.failed_hosts = failed
            
        except subprocess.TimeoutExpired:
            logger.error("SMB validation timed out")
            result.failed_hosts = list(self.targets)
        except Exception as e:
            logger.error(f"SMB validation error: {e}")
            result.failed_hosts = list(self.targets)
        finally:
            targets_file.unlink(missing_ok=True)
        
        return result
    
    def _resolve_password(self, cred_obj, cred_name: str, cred_type: str) -> str | None:
        """Resolve password from credential object, prompting if needed.
        
        Args:
            cred_obj: Credential object (WindowsCredential or LinuxCredential)
            cred_name: Name of the credential for display
            cred_type: Type ("Windows" or "SSH") for display
            
        Returns:
            Resolved password or None if cancelled
        """
        password = cred_obj.password
        
        if cred_obj.needs_runtime_prompt():
            password = Prompts.prompt_secret(
                f"{cred_type} password for {cred_name}",
                f"{cred_type.upper()}_PASSWORD",
            )
        
        return password
    
    def run_full_validation(self) -> CredentialValidationReport:
        """Run validation for all configured credentials.
        
        Returns:
            Full validation report
        """
        report = CredentialValidationReport()
        
        # Validate Linux/SSH credentials
        for cred_name, linux_cred in self.credentials.linux.items():
            password = self._resolve_password(linux_cred, cred_name, "SSH")
            if password:
                result = self.validate_ssh_credential(
                    cred_name,
                    linux_cred.username,
                    password,
                )
                report.results.append(result)
        
        # Validate Windows/SMB credentials
        for cred_name, win_cred in self.credentials.windows.items():
            password = self._resolve_password(win_cred, cred_name, "Windows")
            if password:
                result = self.validate_smb_credential(
                    cred_name,
                    win_cred.username,
                    password,
                    win_cred.domain,
                )
                report.results.append(result)
        
        # Write failure report
        if any(r.failed_hosts for r in report.results):
            report.output_file = self._write_failure_report(report)
        
        return report
    
    def _write_full_report(self, result: ValidationResult, timestamp: datetime | None = None) -> Path:
        """Write a full pass/fail report for a single credential.

        Args:
            result: Validation result for one credential
            timestamp: Override timestamp (defaults to now)

        Returns:
            Path to the written report file
        """
        ts = timestamp or datetime.now()
        ts_file = ts.strftime("%Y%m%d_%H%M%S")
        ts_display = ts.strftime("%Y-%m-%d %H:%M:%S")

        fname = f"{result.credential_type}_{result.credential_name}_{ts_file}.txt"
        report_dir = self.output_dir / self.cred_check_subdir
        report_dir.mkdir(parents=True, exist_ok=True)
        output_file = report_dir / fname

        responded = result.success_count + result.failure_count

        with open(output_file, "w") as f:
            f.write(f"# Credential Check: {result.credential_name} ({result.credential_type.upper()})\n")
            if result.credential_type == "smb" and result.domain:
                f.write(f"# Username: {result.username} | Domain: {result.domain}\n")
            else:
                f.write(f"# Username: {result.username}\n")
            f.write(f"# Tested: {ts_display}\n")
            f.write(
                f"# Targets: {result.total_hosts} | Responded: {responded}"
                f" | Passed: {result.success_count} | Failed: {result.failure_count}\n"
            )
            f.write("\n# PASSED\n")
            for ip in sorted(result.successful_hosts):
                f.write(f"{ip}\n")
            f.write("\n# FAILED\n")
            for ip in sorted(result.failed_hosts):
                f.write(f"{ip}\n")

        logger.info(f"Wrote credential report to: {output_file}")
        return output_file

    def _write_failure_report(self, report: CredentialValidationReport) -> Path:
        """Write failed hosts to a file.
        
        Args:
            report: Validation report
            
        Returns:
            Path to the output file
        """
        timestamp = report.timestamp.strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"cred_failures_{timestamp}.txt"
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            f.write(f"# Credential Validation Failures - {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#\n")
            
            # Group by credential type
            ssh_results = [r for r in report.results if r.credential_type == "ssh"]
            smb_results = [r for r in report.results if r.credential_type == "smb"]
            
            if ssh_results:
                for result in ssh_results:
                    if result.failed_hosts:
                        f.write(f"\n# LINUX (SSH) - {result.credential_name} ({result.username})\n")
                        for host in sorted(result.failed_hosts):
                            f.write(f"{host}\n")
            
            if smb_results:
                for result in smb_results:
                    if result.failed_hosts:
                        domain_info = f"@{result.domain}" if result.domain else ""
                        f.write(f"\n# WINDOWS (SMB) - {result.credential_name} ({result.username}{domain_info})\n")
                        for host in sorted(result.failed_hosts):
                            f.write(f"{host}\n")
        
        logger.info(f"Wrote failure report to: {output_file}")
        return output_file
