"""Tests for scan resume feature.

Covers:
- NmapRunner.is_xml_complete()
- NmapRunner.load_completed_results()
- NmapRunner.delete_scan_artifacts()
- NessusBridge.find_running_scan()
- ResumeState dataclass
- ScanOrchestrator._check_previous_results()
- Resume-aware _run_discovery(), _run_deep_scan(), _run_nessus_scan()
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from enso.nmap_runner import NmapRunner, HostResult, PortInfo
from enso.nessus_bridge import NessusBridge
from enso.orchestrator import ResumeState, ScanOrchestrator
from enso.config.models import NmapConfig, NessusConfig, CredentialsConfig


# ---------------------------------------------------------------------------
# XML fixtures
# ---------------------------------------------------------------------------

COMPLETE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890" version="7.92">
<host starttime="1234567891" endtime="1234567945">
  <status state="up" reason="user-set"/>
  <address addr="{ip}" addrtype="ipv4"/>
  <ports>
    {ports}
  </ports>
</host>
<runstats>
  <finished time="1234567950" elapsed="60.25" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

INCOMPLETE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890" version="7.92">
<host starttime="1234567891">
  <status state="up" reason="user-set"/>
  <address addr="{ip}" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" method="table" conf="10"/>
    </port>
  </ports>
</host>
</nmaprun>
"""

MALFORMED_XML = "<nmaprun><broken"


def _port_xml(port: int, service: str = "") -> str:
    svc = f'<service name="{service}" method="table" conf="10"/>' if service else ""
    return (
        f'<port protocol="tcp" portid="{port}">'
        f'<state state="open" reason="syn-ack"/>'
        f"{svc}"
        f"</port>"
    )


def _write_complete_xml(
    directory: Path, ip: str, ports: list[int] | None = None
) -> Path:
    """Write a complete nmap XML to directory/{sanitized_ip}.xml."""
    ports = ports or [22, 80]
    ports_xml = "\n    ".join(_port_xml(p) for p in ports)
    content = COMPLETE_XML.format(ip=ip, ports=ports_xml)
    sanitized = ip.replace("/", "_").replace(":", "_")
    xml_path = directory / f"{sanitized}.xml"
    xml_path.write_text(content)
    return xml_path


def _write_incomplete_xml(directory: Path, ip: str) -> Path:
    content = INCOMPLETE_XML.format(ip=ip)
    sanitized = ip.replace("/", "_").replace(":", "_")
    xml_path = directory / f"{sanitized}.xml"
    xml_path.write_text(content)
    return xml_path


def _make_nmap_config() -> NmapConfig:
    return NmapConfig()


def _make_runner(tmp_path: Path) -> NmapRunner:
    """Create an NmapRunner with discovery/detailed/logs dirs under tmp_path."""
    config = _make_nmap_config()
    return NmapRunner(
        config=config,
        discovery_dir=tmp_path / "discovery",
        detailed_dir=tmp_path / "detailed",
        log_dir=tmp_path / "logs",
    )


# ===========================================================================
# Tests: is_xml_complete
# ===========================================================================


class TestIsXmlComplete:

    def test_complete_xml_returns_true(self, tmp_path):
        xml = _write_complete_xml(tmp_path, "10.0.0.1")
        assert NmapRunner.is_xml_complete(xml) is True

    def test_incomplete_xml_returns_false(self, tmp_path):
        xml = _write_incomplete_xml(tmp_path, "10.0.0.1")
        assert NmapRunner.is_xml_complete(xml) is False

    def test_missing_file_returns_false(self, tmp_path):
        assert NmapRunner.is_xml_complete(tmp_path / "nonexistent.xml") is False

    def test_malformed_xml_returns_false(self, tmp_path):
        xml = tmp_path / "bad.xml"
        xml.write_text(MALFORMED_XML)
        assert NmapRunner.is_xml_complete(xml) is False

    def test_empty_file_returns_false(self, tmp_path):
        xml = tmp_path / "empty.xml"
        xml.write_text("")
        assert NmapRunner.is_xml_complete(xml) is False


# ===========================================================================
# Tests: load_completed_results
# ===========================================================================


class TestLoadCompletedResults:

    def test_loads_completed_xmls(self, tmp_path):
        runner = _make_runner(tmp_path)
        discovery_dir = tmp_path / "discovery"
        discovery_dir.mkdir(exist_ok=True)

        _write_complete_xml(discovery_dir, "10.0.0.1", [22, 80])
        _write_complete_xml(discovery_dir, "10.0.0.2", [443])

        results = runner.load_completed_results(tmp_path / "discovery")
        assert len(results) == 2
        assert "10.0.0.1" in results
        assert "10.0.0.2" in results
        assert 22 in results["10.0.0.1"].open_ports
        assert 80 in results["10.0.0.1"].open_ports
        assert 443 in results["10.0.0.2"].open_ports

    def test_skips_incomplete_xmls(self, tmp_path):
        runner = _make_runner(tmp_path)
        discovery_dir = tmp_path / "discovery"
        discovery_dir.mkdir(exist_ok=True)

        _write_complete_xml(discovery_dir, "10.0.0.1", [22])
        _write_incomplete_xml(discovery_dir, "10.0.0.2")

        results = runner.load_completed_results(tmp_path / "discovery")
        assert len(results) == 1
        assert "10.0.0.1" in results
        assert "10.0.0.2" not in results

    def test_empty_directory_returns_empty(self, tmp_path):
        runner = _make_runner(tmp_path)
        (tmp_path / "discovery").mkdir(exist_ok=True)

        results = runner.load_completed_results(tmp_path / "discovery")
        assert results == {}

    def test_missing_directory_returns_empty(self, tmp_path):
        runner = _make_runner(tmp_path)
        results = runner.load_completed_results(tmp_path / "nonexistent")
        assert results == {}

    def test_skips_malformed_xmls(self, tmp_path):
        runner = _make_runner(tmp_path)
        discovery_dir = tmp_path / "discovery"
        discovery_dir.mkdir(exist_ok=True)

        bad = discovery_dir / "bad.xml"
        bad.write_text(MALFORMED_XML)

        results = runner.load_completed_results(tmp_path / "discovery")
        assert results == {}

    def test_loads_detailed_type(self, tmp_path):
        runner = _make_runner(tmp_path)
        detailed_dir = tmp_path / "detailed"
        detailed_dir.mkdir(exist_ok=True)

        _write_complete_xml(detailed_dir, "10.0.0.5", [22, 80, 443])

        results = runner.load_completed_results(tmp_path / "detailed")
        assert len(results) == 1
        assert "10.0.0.5" in results


# ===========================================================================
# Tests: delete_scan_artifacts
# ===========================================================================


class TestDeleteScanArtifacts:

    def test_deletes_all_files(self, tmp_path):
        runner = _make_runner(tmp_path)
        discovery_dir = tmp_path / "discovery"
        discovery_dir.mkdir(exist_ok=True)

        (discovery_dir / "host1.xml").write_text("<xml/>")
        (discovery_dir / "host1.gnmap").write_text("data")
        (discovery_dir / "host2.xml").write_text("<xml/>")

        count = runner.delete_scan_artifacts(tmp_path / "discovery")
        assert count == 3
        assert list(discovery_dir.iterdir()) == []

    def test_empty_directory_returns_zero(self, tmp_path):
        runner = _make_runner(tmp_path)
        (tmp_path / "discovery").mkdir(exist_ok=True)
        assert runner.delete_scan_artifacts(tmp_path / "discovery") == 0

    def test_missing_directory_returns_zero(self, tmp_path):
        runner = _make_runner(tmp_path)
        assert runner.delete_scan_artifacts(tmp_path / "nonexistent") == 0

    def test_preserves_directory(self, tmp_path):
        runner = _make_runner(tmp_path)
        discovery_dir = tmp_path / "discovery"
        discovery_dir.mkdir(exist_ok=True)
        (discovery_dir / "host.xml").write_text("<xml/>")

        runner.delete_scan_artifacts(tmp_path / "discovery")
        assert discovery_dir.exists()


# ===========================================================================
# Tests: find_running_scan
# ===========================================================================


def _make_bridge(monkeypatch) -> NessusBridge:
    monkeypatch.setattr(
        "enso.config.models.load_nessus_keys", lambda: None, raising=False
    )
    config = NessusConfig(url="https://nessus:8834")
    bridge = NessusBridge(config=config)
    bridge._nessus = MagicMock()  # prevent real connection
    return bridge


class TestFindRunningScan:

    def test_finds_running_scan(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.scans.list.return_value = {
            "scans": [
                {"id": 10, "name": "internal_20260225_120000", "status": "running", "progress": 45},
                {"id": 11, "name": "other_20260225_130000", "status": "running", "progress": 20},
            ]
        }
        result = bridge.find_running_scan("internal")
        assert result is not None
        assert result["id"] == 10
        assert result["status"] == "running"

    def test_finds_paused_scan(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.scans.list.return_value = {
            "scans": [
                {"id": 15, "name": "internal_20260225_120000", "status": "paused", "progress": 60},
            ]
        }
        result = bridge.find_running_scan("internal")
        assert result is not None
        assert result["status"] == "paused"

    def test_ignores_completed_scan(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.scans.list.return_value = {
            "scans": [
                {"id": 10, "name": "internal_20260225_120000", "status": "completed", "progress": 100},
            ]
        }
        assert bridge.find_running_scan("internal") is None

    def test_ignores_different_network(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.scans.list.return_value = {
            "scans": [
                {"id": 10, "name": "dmz_20260225_120000", "status": "running", "progress": 30},
            ]
        }
        assert bridge.find_running_scan("internal") is None

    def test_returns_none_when_no_scans(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.scans.list.return_value = {"scans": []}
        assert bridge.find_running_scan("internal") is None

    def test_returns_first_match(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.scans.list.return_value = {
            "scans": [
                {"id": 10, "name": "internal_20260225_120000", "status": "running", "progress": 45},
                {"id": 11, "name": "internal_20260225_130000", "status": "running", "progress": 20},
            ]
        }
        result = bridge.find_running_scan("internal")
        assert result["id"] == 10


# ===========================================================================
# Tests: ResumeState
# ===========================================================================


class TestResumeState:

    def test_empty_state_has_no_previous(self):
        rs = ResumeState()
        assert rs.has_previous_results is False

    def test_completed_discovery_has_previous(self):
        rs = ResumeState(
            completed_discovery={"10.0.0.1": HostResult(ip="10.0.0.1")}
        )
        assert rs.has_previous_results is True

    def test_completed_deep_has_previous(self):
        rs = ResumeState(
            completed_deep={"10.0.0.1": HostResult(ip="10.0.0.1")}
        )
        assert rs.has_previous_results is True

    def test_active_nessus_has_previous(self):
        rs = ResumeState(active_nessus_scan={"id": 42, "name": "test", "status": "running"})
        assert rs.has_previous_results is True

    def test_pending_only_no_previous(self):
        rs = ResumeState(pending_discovery=["10.0.0.1", "10.0.0.2"])
        assert rs.has_previous_results is False


# ===========================================================================
# Tests: _check_previous_results
# ===========================================================================


def _make_orchestrator(tmp_path, monkeypatch, skip_nessus=True):
    """Create a ScanOrchestrator with minimal config and tmp_path output."""
    from enso.config.models import EnsoConfig, GlobalConfig, NmapConfig, NessusConfig, CredentialsConfig, EngagementConfig

    monkeypatch.setattr(
        "enso.config.models.load_nessus_keys", lambda: None, raising=False
    )

    config = EnsoConfig(
        global_config=GlobalConfig(),
        nmap=NmapConfig(),
        nessus=NessusConfig(),
        credentials=CredentialsConfig(),
        engagement=EngagementConfig(),
    )

    context = SimpleNamespace(
        scans_dir=tmp_path,
        scope_files=SimpleNamespace(
            excluded=None,
            load_excluded_hosts=lambda: [],
        ),
        output_dir=tmp_path / "internal",
        network_drop=None,
        get_module_dir=lambda d: tmp_path / d,
    )

    orch = ScanOrchestrator(
        config=config,
        context=context,
        skip_nessus=skip_nessus,
    )
    return orch


class TestCheckPreviousResults:

    def test_no_previous_results(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        hosts = ["10.0.0.1", "10.0.0.2"]
        rs = orch._check_previous_results(hosts)

        assert rs.has_previous_results is False
        assert rs.pending_discovery == hosts
        assert rs.completed_discovery == {}

    def test_partial_discovery(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        discovery_dir = tmp_path / "nmap" / "discovery"
        discovery_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(discovery_dir, "10.0.0.1", [22, 80])

        hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        rs = orch._check_previous_results(hosts)

        assert len(rs.completed_discovery) == 1
        assert "10.0.0.1" in rs.completed_discovery
        assert rs.pending_discovery == ["10.0.0.2", "10.0.0.3"]

    def test_filters_out_of_scope_results(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        discovery_dir = tmp_path / "nmap" / "discovery"
        discovery_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(discovery_dir, "10.0.0.1", [22])
        _write_complete_xml(discovery_dir, "10.0.0.99", [80])  # not in scope

        hosts = ["10.0.0.1", "10.0.0.2"]
        rs = orch._check_previous_results(hosts)

        assert len(rs.completed_discovery) == 1
        assert "10.0.0.99" not in rs.completed_discovery

    def test_pending_deep_targets(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        discovery_dir = tmp_path / "nmap" / "discovery"
        discovery_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(discovery_dir, "10.0.0.1", [22, 80])
        _write_complete_xml(discovery_dir, "10.0.0.2", [443])

        hosts = ["10.0.0.1", "10.0.0.2"]
        rs = orch._check_previous_results(hosts)

        # Both hosts have open ports and no deep scans → both pending
        assert len(rs.pending_deep_targets) == 2
        assert 22 in rs.pending_deep_targets["10.0.0.1"]
        assert 443 in rs.pending_deep_targets["10.0.0.2"]

    def test_completed_deep_reduces_pending(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)

        discovery_dir = tmp_path / "nmap" / "discovery"
        discovery_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(discovery_dir, "10.0.0.1", [22, 80])
        _write_complete_xml(discovery_dir, "10.0.0.2", [443])

        detailed_dir = tmp_path / "nmap" / "detailed"
        detailed_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(detailed_dir, "10.0.0.1", [22, 80])

        hosts = ["10.0.0.1", "10.0.0.2"]
        rs = orch._check_previous_results(hosts)

        assert "10.0.0.1" in rs.completed_deep
        assert len(rs.pending_deep_targets) == 1
        assert "10.0.0.2" in rs.pending_deep_targets

    def test_all_complete(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)

        discovery_dir = tmp_path / "nmap" / "discovery"
        discovery_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(discovery_dir, "10.0.0.1", [22])

        detailed_dir = tmp_path / "nmap" / "detailed"
        detailed_dir.mkdir(parents=True, exist_ok=True)
        _write_complete_xml(detailed_dir, "10.0.0.1", [22])

        hosts = ["10.0.0.1"]
        rs = orch._check_previous_results(hosts)

        assert not rs.pending_discovery
        assert not rs.pending_deep_targets
        assert rs.has_previous_results is True


# ===========================================================================
# Tests: Resume-aware _run_discovery
# ===========================================================================


class TestResumeDiscovery:

    def test_full_resume_skips_nmap(self, tmp_path, monkeypatch):
        """When all hosts have completed discovery, nmap is not called."""
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()
        orch.dashboard.hosts = {"10.0.0.1": {}}

        completed = {
            "10.0.0.1": HostResult(
                ip="10.0.0.1",
                status="up",
                ports=[PortInfo(port=22)],
            )
        }
        orch._resume_state = ResumeState(
            completed_discovery=completed,
            pending_discovery=[],
        )

        # Mock nmap so we can verify it's NOT called
        orch.nmap.run_discovery_concurrent = MagicMock(return_value={})

        results = orch._run_discovery(["10.0.0.1"])

        orch.nmap.run_discovery_concurrent.assert_not_called()
        assert "10.0.0.1" in results
        assert results["10.0.0.1"].open_ports == [22]

    def test_partial_resume_scans_remaining(self, tmp_path, monkeypatch):
        """When some hosts are done, only pending hosts are scanned."""
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()
        orch.dashboard.hosts = {"10.0.0.1": {}, "10.0.0.2": {}}

        completed = {
            "10.0.0.1": HostResult(
                ip="10.0.0.1",
                status="up",
                ports=[PortInfo(port=22)],
            )
        }
        orch._resume_state = ResumeState(
            completed_discovery=completed,
            pending_discovery=["10.0.0.2"],
        )

        new_result = HostResult(
            ip="10.0.0.2",
            status="up",
            ports=[PortInfo(port=80)],
        )
        orch.nmap.run_discovery_concurrent = MagicMock(
            return_value={"10.0.0.2": new_result}
        )

        results = orch._run_discovery(["10.0.0.1", "10.0.0.2"])

        # Only pending host scanned
        orch.nmap.run_discovery_concurrent.assert_called_once()
        call_args = orch.nmap.run_discovery_concurrent.call_args
        assert call_args[1]["targets"] == ["10.0.0.2"]

        # Both hosts in merged results
        assert "10.0.0.1" in results
        assert "10.0.0.2" in results

    def test_no_resume_scans_all(self, tmp_path, monkeypatch):
        """With no resume state, all hosts are scanned."""
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()
        orch._resume_state = ResumeState(pending_discovery=["10.0.0.1"])

        orch.nmap.run_discovery_concurrent = MagicMock(
            return_value={
                "10.0.0.1": HostResult(ip="10.0.0.1", status="up")
            }
        )

        results = orch._run_discovery(["10.0.0.1"])
        orch.nmap.run_discovery_concurrent.assert_called_once()
        assert "10.0.0.1" in results


# ===========================================================================
# Tests: Resume-aware _run_deep_scan
# ===========================================================================


class TestResumeDeepScan:

    def test_full_resume_skips_nmap(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()
        orch.dashboard.hosts = {"10.0.0.1": {}}

        completed_deep = {
            "10.0.0.1": HostResult(
                ip="10.0.0.1",
                status="up",
                ports=[PortInfo(port=22), PortInfo(port=80)],
            )
        }
        orch._resume_state = ResumeState(completed_deep=completed_deep)

        orch.nmap.run_deep_concurrent = MagicMock(return_value={})

        discovery_results = {
            "10.0.0.1": HostResult(
                ip="10.0.0.1",
                status="up",
                ports=[PortInfo(port=22), PortInfo(port=80)],
            )
        }
        results = orch._run_deep_scan(discovery_results)

        orch.nmap.run_deep_concurrent.assert_not_called()
        assert "10.0.0.1" in results

    def test_partial_resume_scans_remaining(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()
        orch.dashboard.hosts = {"10.0.0.1": {}, "10.0.0.2": {}}

        completed_deep = {
            "10.0.0.1": HostResult(
                ip="10.0.0.1",
                status="up",
                ports=[PortInfo(port=22)],
            )
        }
        orch._resume_state = ResumeState(completed_deep=completed_deep)

        new_deep = HostResult(
            ip="10.0.0.2",
            status="up",
            ports=[PortInfo(port=80)],
        )
        orch.nmap.run_deep_concurrent = MagicMock(
            return_value={"10.0.0.2": new_deep}
        )

        discovery_results = {
            "10.0.0.1": HostResult(
                ip="10.0.0.1", status="up", ports=[PortInfo(port=22)]
            ),
            "10.0.0.2": HostResult(
                ip="10.0.0.2", status="up", ports=[PortInfo(port=80)]
            ),
        }
        results = orch._run_deep_scan(discovery_results)

        # Only 10.0.0.2 should be in the deep scan call
        call_args = orch.nmap.run_deep_concurrent.call_args[0][0]
        assert "10.0.0.1" not in call_args
        assert "10.0.0.2" in call_args

        assert "10.0.0.1" in results
        assert "10.0.0.2" in results


# ===========================================================================
# Tests: Resume-aware _run_nessus_scan
# ===========================================================================


class TestResumeNessusScan:

    def test_reconnects_to_active_scan(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch, skip_nessus=False)
        orch.dashboard = MagicMock()
        orch.dashboard.hosts = {"10.0.0.1": {}}

        active_scan = {
            "id": 42,
            "name": "internal_20260225_120000",
            "status": "running",
            "progress": 50,
        }
        orch._resume_state = ResumeState(active_nessus_scan=active_scan)

        mock_bridge = MagicMock()
        mock_bridge.poll_until_complete.return_value = True
        orch._nessus = mock_bridge

        result = orch._run_nessus_scan(["10.0.0.1"])

        assert result is True
        mock_bridge.poll_until_complete.assert_called_once_with(42)
        # Should NOT call create_scan
        mock_bridge.create_scan.assert_not_called()

    def test_creates_new_scan_without_active(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch, skip_nessus=False)
        orch.dashboard = MagicMock()
        orch.dashboard.hosts = {"10.0.0.1": {}}
        orch._resume_state = ResumeState()

        mock_bridge = MagicMock()
        mock_bridge.create_scan.return_value = 99
        mock_bridge.launch_scan.return_value = True
        mock_bridge.poll_until_complete.return_value = True
        orch._nessus = mock_bridge

        result = orch._run_nessus_scan(["10.0.0.1"])

        assert result is True
        mock_bridge.create_scan.assert_called_once()


# ===========================================================================
# Tests: _apply_resume_to_dashboard
# ===========================================================================


class TestApplyResumeToDashboard:

    def test_pre_populates_completed_hosts(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()

        orch._resume_state = ResumeState(
            completed_discovery={
                "10.0.0.1": HostResult(
                    ip="10.0.0.1",
                    status="up",
                    ports=[PortInfo(port=22)],
                ),
            },
            completed_deep={
                "10.0.0.1": HostResult(
                    ip="10.0.0.1",
                    status="up",
                    ports=[PortInfo(port=22)],
                ),
            },
        )

        orch._apply_resume_to_dashboard()

        # discovery + deep = 2 update_host_status calls
        assert orch.dashboard.update_host_status.call_count == 2
        assert orch._completed_counts["discovery"] == 1
        assert orch._completed_counts["deep"] == 1

    def test_no_resume_state_is_noop(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)
        orch.dashboard = MagicMock()
        orch._resume_state = None

        orch._apply_resume_to_dashboard()
        orch.dashboard.update_host_status.assert_not_called()


# ===========================================================================
# Tests: _clear_previous_results
# ===========================================================================


class TestClearPreviousResults:

    def test_deletes_both_directories(self, tmp_path, monkeypatch):
        orch = _make_orchestrator(tmp_path, monkeypatch)

        for d in ("nmap/discovery", "nmap/detailed"):
            (tmp_path / d).mkdir(parents=True, exist_ok=True)
            (tmp_path / d / "host.xml").write_text("<xml/>")

        orch._clear_previous_results()

        assert list((tmp_path / "nmap" / "discovery").iterdir()) == []
        assert list((tmp_path / "nmap" / "detailed").iterdir()) == []
