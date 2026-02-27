"""Tests for credential validation (cred_validator.py) and cli_helpers.run_credential_check()."""

import subprocess
import textwrap
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from enso.cred_validator import CredentialValidator, ValidationResult


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_validator(tmp_path, targets=None):
    """Return a CredentialValidator with stubbed credentials and temp output_dir."""
    from enso.config.models import CredentialsConfig

    creds = CredentialsConfig()
    return CredentialValidator(
        credentials=creds,
        targets=targets or ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        output_dir=tmp_path,
    )


def _nxc_success_output(ips):
    """Generate nxc stdout lines for successful auth on given IPs."""
    return "\n".join(f"SMB  {ip}  445  [+] CORP\\admin:pass (Pwn3d!)" for ip in ips)


def _nxc_failure_output(ips):
    """Generate nxc stdout lines for failed auth on given IPs."""
    return "\n".join(f"SMB  {ip}  445  [-] CORP\\admin:pass" for ip in ips)


def _nxc_ssh_success(ips):
    return "\n".join(f"SSH  {ip}  22  [+] scanuser:pass" for ip in ips)


def _nxc_ssh_failure(ips):
    return "\n".join(f"SSH  {ip}  22  [-] scanuser:pass" for ip in ips)


# ===========================================================================
# Tests: validate_smb_credential -- local-auth flag
# ===========================================================================

class TestSMBLocalAuth:
    """validate_smb_credential() must use --local-auth for local accounts."""

    def _capture_cmd(self, monkeypatch):
        """Patch subprocess.run and return a list that captures the command."""
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return SimpleNamespace(stdout="", stderr="", returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        return captured

    def test_domain_account_uses_dash_d(self, monkeypatch, tmp_path):
        """Domain account → -d CORP, no --local-auth."""
        v = _make_validator(tmp_path)
        captured = self._capture_cmd(monkeypatch)

        v.validate_smb_credential("admin", "administrator", "pass", "CORP")

        cmd = captured[0]
        assert "-d" in cmd
        assert "CORP" in cmd
        assert "--local-auth" not in cmd

    def test_empty_domain_uses_local_auth(self, monkeypatch, tmp_path):
        """Empty domain → --local-auth, no -d."""
        v = _make_validator(tmp_path)
        captured = self._capture_cmd(monkeypatch)

        v.validate_smb_credential("localadmin", "admin", "pass", "")

        cmd = captured[0]
        assert "--local-auth" in cmd
        assert "-d" not in cmd

    def test_dot_domain_uses_local_auth(self, monkeypatch, tmp_path):
        """Domain '.' → --local-auth, no -d."""
        v = _make_validator(tmp_path)
        captured = self._capture_cmd(monkeypatch)

        v.validate_smb_credential("localadmin", "admin", "pass", ".")

        cmd = captured[0]
        assert "--local-auth" in cmd
        assert "-d" not in cmd

    def test_no_bruteforce_always_present(self, monkeypatch, tmp_path):
        """--no-bruteforce and --no-progress are always appended."""
        v = _make_validator(tmp_path)
        captured = self._capture_cmd(monkeypatch)

        v.validate_smb_credential("x", "u", "p", "")

        cmd = captured[0]
        assert "--no-bruteforce" in cmd
        assert "--no-progress" in cmd


# ===========================================================================
# Tests: _write_full_report
# ===========================================================================

class TestCredCheckSubdir:
    """Tests for the cred_check_subdir parameter."""

    def test_default_subdir(self, tmp_path):
        """Default cred_check_subdir is 'cred_checks'."""
        v = _make_validator(tmp_path)
        assert v.cred_check_subdir == "cred_checks"

    def test_custom_subdir(self, tmp_path):
        """Custom cred_check_subdir routes reports to custom directory."""
        from enso.config.models import CredentialsConfig
        v = CredentialValidator(
            credentials=CredentialsConfig(),
            targets=["10.0.0.1"],
            output_dir=tmp_path,
            cred_check_subdir="custom_checks",
        )
        result = ValidationResult(
            credential_name="ssh_test",
            credential_type="ssh",
            username="user",
            total_hosts=1,
            successful_hosts=["10.0.0.1"],
        )
        path = v._write_full_report(result)
        assert path.parent.name == "custom_checks"
        assert path.exists()


class TestWriteFullReport:
    """_write_full_report() writes a per-credential pass/fail report."""

    def test_creates_cred_checks_dir(self, tmp_path):
        """Report file is written inside output_dir/cred_checks/."""
        v = _make_validator(tmp_path)
        result = ValidationResult(
            credential_name="ssh_usr",
            credential_type="ssh",
            username="scanuser",
            total_hosts=3,
            successful_hosts=["10.0.0.1", "10.0.0.2"],
            failed_hosts=["10.0.0.3"],
        )

        path = v._write_full_report(result)

        assert path.exists()
        assert path.parent.name == "cred_checks"
        assert path.parent.parent == tmp_path

    def test_filename_format(self, tmp_path):
        """Filename: {type}_{name}_{timestamp}.txt."""
        v = _make_validator(tmp_path)
        result = ValidationResult(
            credential_name="mykey",
            credential_type="ssh",
            username="u",
            total_hosts=1,
        )
        ts = datetime(2026, 2, 10, 19, 0, 0)

        path = v._write_full_report(result, timestamp=ts)

        assert path.name == "ssh_mykey_20260210_190000.txt"

    def test_report_contents_ssh(self, tmp_path):
        """SSH report has correct header and sections."""
        v = _make_validator(tmp_path)
        result = ValidationResult(
            credential_name="ssh_usr",
            credential_type="ssh",
            username="scanuser",
            total_hosts=11,
            successful_hosts=["10.0.0.1", "10.0.0.2"],
            failed_hosts=["10.0.0.9"],
        )
        ts = datetime(2026, 2, 10, 19, 0, 0)

        path = v._write_full_report(result, timestamp=ts)
        content = path.read_text()

        assert "# Credential Check: ssh_usr (SSH)" in content
        assert "# Username: scanuser" in content
        assert "# Tested: 2026-02-10 19:00:00" in content
        assert "# Targets: 11 | Responded: 3 | Passed: 2 | Failed: 1" in content
        assert "# PASSED" in content
        assert "10.0.0.1" in content
        assert "10.0.0.2" in content
        assert "# FAILED" in content
        assert "10.0.0.9" in content

    def test_report_contents_smb_with_domain(self, tmp_path):
        """SMB report includes domain in header."""
        v = _make_validator(tmp_path)
        result = ValidationResult(
            credential_name="admin",
            credential_type="smb",
            username="administrator",
            domain="CORP",
            total_hosts=6,
            successful_hosts=["10.0.0.1"],
            failed_hosts=["10.0.0.7"],
        )
        ts = datetime(2026, 2, 10, 19, 0, 0)

        path = v._write_full_report(result, timestamp=ts)
        content = path.read_text()

        assert "# Credential Check: admin (SMB)" in content
        assert "# Username: administrator | Domain: CORP" in content

    def test_report_contents_smb_no_domain(self, tmp_path):
        """SMB report without domain omits domain field."""
        v = _make_validator(tmp_path)
        result = ValidationResult(
            credential_name="localadmin",
            credential_type="smb",
            username="admin",
            domain="",
            total_hosts=3,
            successful_hosts=["10.0.0.1"],
            failed_hosts=[],
        )

        path = v._write_full_report(result)
        content = path.read_text()

        # No domain → plain Username line
        assert "# Username: admin\n" in content
        assert "Domain" not in content

    def test_report_empty_results(self, tmp_path):
        """Report with no successes or failures still writes sections."""
        v = _make_validator(tmp_path)
        result = ValidationResult(
            credential_name="x",
            credential_type="ssh",
            username="u",
            total_hosts=5,
        )

        path = v._write_full_report(result)
        content = path.read_text()

        assert "# PASSED" in content
        assert "# FAILED" in content
        assert "Responded: 0" in content


# ===========================================================================
# Tests: EngagementContext.scans_dir
# ===========================================================================

class TestEngagementContextScansDir:
    """EngagementContext.scans_dir returns output_dir / 'scans'."""

    def test_scans_dir_property(self, tmp_path):
        from enso.context import EngagementContext, ScopeFiles

        ctx = EngagementContext(
            engagement_type="simple",
            client_dir=tmp_path,
            scope_files=ScopeFiles(in_scope=tmp_path / "inscope.txt"),
            output_dir=tmp_path / "client" / "internal",
        )

        assert ctx.scans_dir == tmp_path / "client" / "internal" / "scans"


# ===========================================================================
# Tests: run_credential_check (cli_helpers)
# ===========================================================================

class TestRunCredentialCheck:
    """Tests for run_credential_check() in cli_helpers."""

    def _make_context(self, tmp_path):
        """Build a minimal EngagementContext with a scope file."""
        from enso.context import EngagementContext, ScopeFiles

        scope_file = tmp_path / "inscope.txt"
        scope_file.write_text("10.0.0.1\n10.0.0.2\n10.0.0.3\n")

        return EngagementContext(
            engagement_type="simple",
            client_dir=tmp_path,
            scope_files=ScopeFiles(in_scope=scope_file),
            output_dir=tmp_path,
        )

    def _make_config_with_creds(self, ssh_pass="secret", win_pass="secret",
                                 ssh_enabled=True, win_enabled=True):
        """Build an EnsoConfig with test credentials."""
        from enso.config.models import (
            CredentialsConfig,
            EnsoConfig,
            LinuxCredential,
            WindowsCredential,
            set_credentials_file_security,
        )

        # Mark file as secure so passwords resolve as literals
        set_credentials_file_security(True)

        linux = {}
        if ssh_pass is not None:
            linux["ssh_usr"] = LinuxCredential(
                username="scanuser", password=ssh_pass, enabled=ssh_enabled
            )

        windows = {}
        if win_pass is not None:
            windows["admin"] = WindowsCredential(
                username="administrator", password=win_pass,
                domain="CORP", enabled=win_enabled,
            )

        creds = CredentialsConfig(linux=linux, windows=windows)
        config = EnsoConfig(credentials=creds)
        return config

    def test_returns_true_when_user_declines(self, monkeypatch, tmp_path):
        """User answers No → returns True immediately."""
        from enso import cli_helpers

        monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: False)

        config = self._make_config_with_creds()
        context = self._make_context(tmp_path)

        assert cli_helpers.run_credential_check(config, context) is True

    def test_returns_true_when_nxc_missing(self, monkeypatch, tmp_path):
        """nxc not found → warns and returns True."""
        from enso import cli_helpers
        from enso.cred_validator import CredentialValidator

        monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: True)
        monkeypatch.setattr(
            CredentialValidator, "check_nxc_available", lambda self: False
        )

        config = self._make_config_with_creds()
        context = self._make_context(tmp_path)

        assert cli_helpers.run_credential_check(config, context) is True

    def test_returns_true_when_no_hosts(self, monkeypatch, tmp_path):
        """Empty scope file → warns and returns True."""
        from enso import cli_helpers
        from enso.cred_validator import CredentialValidator

        monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: True)
        monkeypatch.setattr(
            CredentialValidator, "check_nxc_available", lambda self: True
        )

        config = self._make_config_with_creds()
        context = self._make_context(tmp_path)

        # Empty the scope file
        context.scope_files.in_scope.write_text("")

        assert cli_helpers.run_credential_check(config, context) is True

    def test_skips_disabled_credentials(self, monkeypatch, tmp_path):
        """Disabled credentials are skipped."""
        from enso import cli_helpers
        from enso.cred_validator import CredentialValidator

        monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: True)
        monkeypatch.setattr(
            CredentialValidator, "check_nxc_available", lambda self: True
        )

        config = self._make_config_with_creds(
            ssh_enabled=False, win_enabled=False
        )
        context = self._make_context(tmp_path)

        assert cli_helpers.run_credential_check(config, context) is True

    def test_runs_validation_and_writes_reports(self, monkeypatch, tmp_path):
        """Full run: validates credentials, writes reports, returns True."""
        from enso import cli_helpers
        from enso.cred_validator import CredentialValidator

        monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: True)
        monkeypatch.setattr(
            CredentialValidator, "check_nxc_available", lambda self: True
        )

        # Stub nxc subprocess calls
        call_count = {"n": 0}

        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            # Return success for first two IPs, failure for third
            stdout = (
                _nxc_ssh_success(["10.0.0.1", "10.0.0.2"])
                + "\n"
                + _nxc_ssh_failure(["10.0.0.3"])
            )
            return SimpleNamespace(stdout=stdout, stderr="", returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        config = self._make_config_with_creds(win_pass=None)  # SSH only
        context = self._make_context(tmp_path)

        result = cli_helpers.run_credential_check(config, context)

        assert result is True
        assert call_count["n"] >= 1

        # Check report files were created
        report_dir = tmp_path / "scans" / "cred_checks"
        assert report_dir.exists()
        report_files = list(report_dir.glob("ssh_*.txt"))
        assert len(report_files) == 1

    def test_always_returns_true(self, monkeypatch, tmp_path):
        """run_credential_check always returns True (non-blocking)."""
        from enso import cli_helpers
        from enso.cred_validator import CredentialValidator

        monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: True)
        monkeypatch.setattr(
            CredentialValidator, "check_nxc_available", lambda self: True
        )

        # All failures — still returns True
        def fake_run(cmd, **kwargs):
            stdout = _nxc_ssh_failure(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
            return SimpleNamespace(stdout=stdout, stderr="", returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)

        config = self._make_config_with_creds(win_pass=None)
        context = self._make_context(tmp_path)

        assert cli_helpers.run_credential_check(config, context) is True
