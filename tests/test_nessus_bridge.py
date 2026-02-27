"""Tests for the Nessus API bridge (curl-based API contract)."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from enso.config.models import (
    CredentialsConfig,
    NessusConfig,
    NessusUICredential,
    set_nessus_file_security,
)
from enso.nessus_bridge import NessusBridge
from enso.ui.dashboard import ScanStatus


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_proc(stdout, returncode=0):
    """Return a SimpleNamespace mimicking subprocess.CompletedProcess."""
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


def _make_nessus_mock(url="https://nessus:8834", api_keys="accessKey=a;secretKey=s",
                      properties_data=None):
    """Return a nested SimpleNamespace mimicking a pyTenable Nessus client."""
    if properties_data is None:
        properties_data = {"features": {}, "nessus_type": "Nessus Professional"}

    policies_data = []

    return SimpleNamespace(
        _url=url,
        _session=SimpleNamespace(headers={"X-APIKeys": api_keys}),
        server=SimpleNamespace(
            status=lambda: {"status": "ready"},
            properties=lambda: properties_data,
        ),
        policies=SimpleNamespace(
            list=lambda: policies_data,
            details=lambda pid: {},
        ),
    )


def _make_bridge(monkeypatch, credentials=None, nessus_mock=None):
    """Construct a NessusBridge with a real NessusConfig (keys stubbed out)."""
    # Prevent key-file and file-security lookups from touching the real FS
    monkeypatch.setattr("enso.config.models.load_nessus_keys", lambda: None,
                        raising=False)
    set_nessus_file_security(True)

    config = NessusConfig(url="https://nessus:8834")
    bridge = NessusBridge(config=config, credentials=credentials)
    bridge._nessus = nessus_mock or _make_nessus_mock()
    return bridge


# ===================================================================
# 1. NessusUICredential
# ===================================================================

class TestNessusUICredential:
    """Tests for NessusUICredential model behaviour."""

    def test_needs_prompt_empty_username(self):
        cred = NessusUICredential(username="", password="pass")
        assert cred.needs_runtime_prompt() is True

    def test_needs_prompt_empty_password(self):
        cred = NessusUICredential(username="admin", password="")
        assert cred.needs_runtime_prompt() is True

    def test_needs_prompt_unresolved_env_var(self):
        cred = NessusUICredential(username="admin", password="${UNSET_VAR}")
        assert cred.needs_runtime_prompt() is True

    def test_needs_prompt_false_when_resolved(self, monkeypatch):
        monkeypatch.setenv("NESSUS_PW", "secret")
        cred = NessusUICredential(username="admin", password="${NESSUS_PW}")
        assert cred.needs_runtime_prompt() is False

    def test_resolve_interpolates_env_var(self, monkeypatch):
        monkeypatch.setenv("NESSUS_PW", "secret123")
        cred = NessusUICredential(username="admin", password="${NESSUS_PW}")
        assert cred.password == "secret123"

    def test_credentials_config_nessus_ui_default_none(self):
        cc = CredentialsConfig()
        assert cc.nessus_ui is None


# ===================================================================
# 2. _obtain_api_token
# ===================================================================

class TestObtainApiToken:
    """Tests for CSRF token extraction from /nessus6.js."""

    def test_curl_command_shape(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["timeout"] = kw.get("timeout")
            return _make_proc("")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._obtain_api_token()

        assert captured["cmd"] == ["curl", "-sk", "https://nessus:8834/nessus6.js"]
        assert captured["timeout"] == 30

    def test_extracts_valid_uuid_v4(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        uuid = "abcdef01-2345-4678-9abc-def012345678"
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(f"var token='{uuid}';"))
        bridge._obtain_api_token()
        assert bridge._api_token == uuid

    def test_extracts_first_uuid_when_multiple(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        first = "11111111-1111-4111-8111-111111111111"
        second = "22222222-2222-4222-8222-222222222222"
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(f"a={first} b={second}"))
        bridge._obtain_api_token()
        assert bridge._api_token == first

    def test_no_match_leaves_token_none(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc("no uuid here"))
        bridge._obtain_api_token()
        assert bridge._api_token is None

    def test_subprocess_failure_leaves_token_none(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="curl", timeout=30)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        bridge._obtain_api_token()
        assert bridge._api_token is None

    def test_nonzero_returncode_still_extracts(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        uuid = "deadbeef-dead-4ead-beef-deadbeefbeef"
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(f"t={uuid}", returncode=1))
        bridge._obtain_api_token()
        assert bridge._api_token == uuid


# ===================================================================
# 3. _obtain_session_token
# ===================================================================

class TestObtainSessionToken:
    """Tests for session auth via POST /session."""

    def test_uses_config_creds_when_available(self, monkeypatch):
        nessus_ui = NessusUICredential(username="admin", password="s3cret")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)

        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc(json.dumps({"token": "tok"}))

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._obtain_session_token()

        # Should have used creds from config — verify the -d payload
        d_idx = captured["cmd"].index("-d")
        payload = json.loads(captured["cmd"][d_idx + 1])
        assert payload == {"username": "admin", "password": "s3cret"}

    def test_falls_back_to_prompt_when_no_nessus_ui(self, monkeypatch):
        bridge = _make_bridge(monkeypatch, credentials=None)
        prompted = []

        # Mock rich.prompt.Prompt.ask
        monkeypatch.setattr("rich.prompt.Prompt.ask",
                            lambda msg, **kw: prompted.append(msg) or "val")
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(json.dumps({"token": "t"})))

        bridge._obtain_session_token()
        assert len(prompted) == 2  # username + password

    def test_falls_back_when_nessus_ui_needs_prompt(self, monkeypatch):
        nessus_ui = NessusUICredential(username="", password="pw")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)
        prompted = []

        monkeypatch.setattr("rich.prompt.Prompt.ask",
                            lambda msg, **kw: prompted.append(msg) or "val")
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(json.dumps({"token": "t"})))

        bridge._obtain_session_token()
        assert len(prompted) == 2

    def test_curl_without_api_token(self, monkeypatch):
        nessus_ui = NessusUICredential(username="u", password="p")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)
        bridge._api_token = None

        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc(json.dumps({"token": "t"}))

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._obtain_session_token()

        # No X-Api-Token header anywhere in the command
        assert not any("X-Api-Token" in str(c) for c in captured["cmd"])

    def test_curl_with_api_token(self, monkeypatch):
        nessus_ui = NessusUICredential(username="u", password="p")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)
        bridge._api_token = "csrf-tok"

        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc(json.dumps({"token": "t"}))

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._obtain_session_token()

        assert "X-Api-Token: csrf-tok" in captured["cmd"]

    def test_successful_response_sets_token(self, monkeypatch):
        nessus_ui = NessusUICredential(username="u", password="p")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)

        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(json.dumps({"token": "abc"})))
        bridge._obtain_session_token()
        assert bridge._session_token == "abc"

    def test_response_missing_token_field(self, monkeypatch):
        nessus_ui = NessusUICredential(username="u", password="p")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)

        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(json.dumps({"error": "bad"})))
        bridge._obtain_session_token()
        assert bridge._session_token is None

    def test_malformed_json_response(self, monkeypatch):
        nessus_ui = NessusUICredential(username="u", password="p")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)

        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc("not json"))
        bridge._obtain_session_token()
        assert bridge._session_token is None

    def test_subprocess_timeout(self, monkeypatch):
        nessus_ui = NessusUICredential(username="u", password="p")
        creds = CredentialsConfig(nessus_ui=nessus_ui)
        bridge = _make_bridge(monkeypatch, credentials=creds)

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="curl", timeout=15)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        bridge._obtain_session_token()
        assert bridge._session_token is None


# ===================================================================
# 4. _curl_nessus — most contract-critical
# ===================================================================

class TestCurlNessus:
    """Tests for the _curl_nessus() helper that builds curl commands."""

    def test_session_auth_header(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess123"
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("body\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/test")

        assert "X-Cookie: token=sess123" in captured["cmd"]

    def test_api_key_auth_header(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = None  # no session → API keys
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("body\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/test")

        assert "X-APIKeys: accessKey=a;secretKey=s" in captured["cmd"]

    def test_csrf_token_included(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._api_token = "csrf-uuid"
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/x")

        assert "X-Api-Token: csrf-uuid" in captured["cmd"]

    def test_csrf_token_omitted_when_none(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._api_token = None
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/x")

        assert not any("X-Api-Token" in str(c) for c in captured["cmd"])

    def test_get_no_payload(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/path")

        assert "-d" not in captured["cmd"]

    def test_post_with_payload(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("POST", "/path", payload={"key": "val"})

        d_idx = captured["cmd"].index("-d")
        assert json.loads(captured["cmd"][d_idx + 1]) == {"key": "val"}

    def test_url_construction(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/scans/42")

        assert "https://nessus:8834/scans/42" in captured["cmd"]

    def test_write_out_flag(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("GET", "/x")

        w_idx = captured["cmd"].index("-w")
        assert captured["cmd"][w_idx + 1] == "\n%{http_code}"

    def test_parses_status_and_body(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc("body\n200"))

        status, body = bridge._curl_nessus("GET", "/x")
        assert status == 200
        assert body == "body"

    def test_parses_multiline_body(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc("line1\nline2\n201"))

        status, body = bridge._curl_nessus("GET", "/x")
        assert status == 201
        assert body == "line1\nline2"

    def test_empty_stdout(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(""))

        status, body = bridge._curl_nessus("GET", "/x")
        assert status == 0
        assert body == ""

    def test_non_numeric_status(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc("body\nabc"))

        status, body = bridge._curl_nessus("GET", "/x")
        assert status == 0

    def test_subprocess_exception(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)

        def raise_os(*a, **kw):
            raise OSError("curl not found")

        monkeypatch.setattr(subprocess, "run", raise_os)

        status, body = bridge._curl_nessus("GET", "/x")
        assert status == 0
        assert body == ""

    def test_full_command_with_session_and_csrf(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"
        bridge._api_token = "csrf"
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc("ok\n200")

        monkeypatch.setattr(subprocess, "run", fake_run)
        bridge._curl_nessus("POST", "/scans", payload={"a": 1})

        cmd = captured["cmd"]
        assert cmd[0] == "curl"
        assert cmd[1] == "-sk"
        assert cmd[2] == "-X"
        assert cmd[3] == "POST"
        assert cmd[4] == "https://nessus:8834/scans"
        assert "-H" in cmd
        assert "X-Cookie: token=sess" in cmd
        assert "Content-Type: application/json" in cmd
        assert "\n%{http_code}" in cmd
        assert "X-Api-Token: csrf" in cmd
        d_idx = cmd.index("-d")
        assert json.loads(cmd[d_idx + 1]) == {"a": 1}


# ===================================================================
# 5. create_scan
# ===================================================================

class TestCreateScan:
    """Tests for scan creation payload construction."""

    def _make_bridge_with_policy(self, monkeypatch, policy_list=None):
        """Build a bridge whose mock Nessus has a resolvable policy."""
        bridge = _make_bridge(monkeypatch)
        if policy_list is None:
            policy_list = [
                {"name": "Advanced Network Scan", "id": 42,
                 "template_uuid": "tmpl-uuid-1234"},
            ]
        bridge._nessus.policies.list = lambda: policy_list
        return bridge

    def test_payload_shape(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["payload"] = payload
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("net1", ["10.0.0.1", "10.0.0.2"])

        p = captured["payload"]
        assert "uuid" in p
        assert "settings" in p
        assert p["uuid"] == "tmpl-uuid-1234"
        assert p["settings"]["name"].startswith("net1_")

    def test_policy_id_is_string(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["payload"] = payload
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["1.2.3.4"])

        assert captured["payload"]["settings"]["policy_id"] == "42"

    def test_scanner_id_is_string_one(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["payload"] = payload
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["1.2.3.4"])

        assert captured["payload"]["settings"]["scanner_id"] == "1"

    def test_folder_id_is_int_three(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["payload"] = payload
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["1.2.3.4"])

        assert captured["payload"]["settings"]["folder_id"] == 3
        assert isinstance(captured["payload"]["settings"]["folder_id"], int)

    def test_launch_now_is_true(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["payload"] = payload
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["1.2.3.4"])

        assert captured["payload"]["settings"]["launch_now"] is True

    def test_targets_comma_joined(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["payload"] = payload
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["a", "b", "c"])

        assert captured["payload"]["settings"]["text_targets"] == "a,b,c"

    def test_retry_without_uuid(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        calls = []

        def fake_curl(method, path, payload=None):
            calls.append(payload)
            if len(calls) == 1:
                return 500, "error"  # first attempt fails (_post_scan → None)
            return 200, json.dumps({"scan": {"id": 2}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        # _post_scan checks status != 200 → returns None on first call
        result = bridge.create_scan("n", ["1.2.3.4"])

        assert len(calls) == 2
        assert "uuid" in calls[0]      # first attempt has uuid
        assert "uuid" not in calls[1]   # retry has no uuid

    def test_returns_none_both_fail(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)

        def fake_curl(method, path, payload=None):
            return 500, "error"

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        result = bridge.create_scan("n", ["1.2.3.4"])

        assert result is None
        assert bridge._launched is False

    def test_sets_launched_flag(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)

        def fake_curl(method, path, payload=None):
            return 200, json.dumps({"scan": {"id": 99}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["1.2.3.4"])

        assert bridge._launched is True

    def test_returns_scan_id(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)

        def fake_curl(method, path, payload=None):
            return 200, json.dumps({"scan": {"id": 77}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        result = bridge.create_scan("n", ["1.2.3.4"])

        assert result == 77

    def test_uses_default_policy(self, monkeypatch):
        bridge = self._make_bridge_with_policy(monkeypatch)
        resolved = []

        original_resolve = bridge._resolve_policy

        def spy_resolve(name):
            resolved.append(name)
            return original_resolve(name)

        monkeypatch.setattr(bridge, "_resolve_policy", spy_resolve)

        def fake_curl(method, path, payload=None):
            return 200, json.dumps({"scan": {"id": 1}})

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.create_scan("n", ["1.2.3.4"], policy=None)

        assert resolved[0] == "Advanced Network Scan"


# ===================================================================
# 6. get_scan_status (curl-based)
# ===================================================================

class TestGetScanStatus:
    """Tests for curl-based get_scan_status."""

    def _nessus_details_body(self, status="running", hostcount=4,
                              hosts=None):
        """Build a realistic GET /scans/{id} JSON response.

        Uses the real Nessus Pro 10.x format where progress comes from
        per-host scanprogresscurrent/scanprogresstotal fields.
        """
        body = {
            "info": {
                "name": "test_scan",
                "status": status,
                "hostcount": hostcount,
            },
        }
        if hosts is not None:
            body["hosts"] = hosts
        return json.dumps(body)

    def test_uses_curl_not_pytenable(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["method"] = method
            captured["path"] = path
            return 200, self._nessus_details_body()

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.get_scan_status(42)

        assert captured["method"] == "GET"
        assert captured["path"] == "/scans/42"

    def test_parses_running_status(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        hosts = [
            {"scanprogresscurrent": 100, "scanprogresstotal": 100},
            {"scanprogresscurrent": 30, "scanprogresstotal": 100},
        ]
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, self._nessus_details_body(
                                status="running", hosts=hosts)))

        result = bridge.get_scan_status(1)
        assert result["status"] == "running"
        assert result["progress"] == 65  # (100 + 30) / 2

    def test_parses_completed_status(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, self._nessus_details_body(
                                status="completed")))

        result = bridge.get_scan_status(1)
        assert result["status"] == "completed"
        assert result["progress"] == 100

    def test_non_200_returns_error(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (403, "Forbidden"))

        result = bridge.get_scan_status(1)
        assert "error" in result

    def test_malformed_json_returns_error(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, "not json"))

        result = bridge.get_scan_status(1)
        assert "error" in result

    def test_no_scan_id_returns_error(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._scan_id = None
        result = bridge.get_scan_status()
        assert "error" in result

    def test_host_progress_averaging(self, monkeypatch):
        """Progress is averaged from scanprogresscurrent across hosts."""
        bridge = _make_bridge(monkeypatch)
        hosts = [
            {"scanprogresscurrent": 100, "scanprogresstotal": 100},
            {"scanprogresscurrent": 100, "scanprogresstotal": 100},
            {"scanprogresscurrent": 50, "scanprogresstotal": 100},
            {"scanprogresscurrent": 0, "scanprogresstotal": 100},
        ]
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 4},
            "hosts": hosts,
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["progress"] == 62  # (100+100+50+0)/4

    def test_uses_stored_scan_id_when_none_given(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._scan_id = 99
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["path"] = path
            return 200, self._nessus_details_body()

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.get_scan_status()

        assert captured["path"] == "/scans/99"


# ===================================================================
# 7. poll_until_complete (with retry)
# ===================================================================

class TestPollUntilComplete:
    """Tests for poll_until_complete retry and callback behaviour."""

    def test_returns_true_on_completed(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._scan_id = 1

        monkeypatch.setattr(bridge, "get_scan_status",
                            lambda sid: {"status": "completed", "progress": 100})

        assert bridge.poll_until_complete(1, poll_interval=0) is True

    def test_returns_false_on_canceled(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(bridge, "get_scan_status",
                            lambda sid: {"status": "canceled", "progress": 40})

        assert bridge.poll_until_complete(1, poll_interval=0) is False

    def test_retries_transient_errors(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        call_count = [0]

        def fake_status(sid):
            call_count[0] += 1
            if call_count[0] <= 2:
                return {"error": "timeout"}
            return {"status": "completed", "progress": 100}

        monkeypatch.setattr(bridge, "get_scan_status", fake_status)

        result = bridge.poll_until_complete(1, poll_interval=0, max_errors=5)
        assert result is True
        assert call_count[0] == 3  # 2 errors + 1 success

    def test_aborts_after_max_errors(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        monkeypatch.setattr(bridge, "get_scan_status",
                            lambda sid: {"error": "always fail"})

        result = bridge.poll_until_complete(1, poll_interval=0, max_errors=3)
        assert result is False

    def test_fires_running_callback(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        cb_args = []
        bridge.progress_callback = lambda *a: cb_args.append(a)
        call_count = [0]

        def fake_status(sid):
            call_count[0] += 1
            if call_count[0] < 3:
                return {"status": "running", "progress": 50}
            return {"status": "completed", "progress": 100}

        monkeypatch.setattr(bridge, "get_scan_status", fake_status)
        bridge.poll_until_complete(1, poll_interval=0)

        # Should have RUNNING callbacks followed by COMPLETED
        running = [a for a in cb_args if a[1] == ScanStatus.RUNNING]
        completed = [a for a in cb_args if a[1] == ScanStatus.COMPLETED]
        assert len(running) == 2
        assert len(completed) == 1
        assert running[0][2] == 50  # progress passed through

    def test_no_scan_id_returns_false(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._scan_id = None
        assert bridge.poll_until_complete(poll_interval=0) is False

    def test_consecutive_errors_reset_on_success(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        call_count = [0]

        def fake_status(sid):
            call_count[0] += 1
            # Error, error, success, error, error, success, completed
            pattern = ["error", "error", "running", "error", "error",
                       "running", "completed"]
            idx = min(call_count[0] - 1, len(pattern) - 1)
            if pattern[idx] == "error":
                return {"error": "transient"}
            return {"status": pattern[idx], "progress": 50}

        monkeypatch.setattr(bridge, "get_scan_status", fake_status)
        result = bridge.poll_until_complete(1, poll_interval=0, max_errors=3)
        assert result is True


# ===================================================================
# 8. _post_scan
# ===================================================================

class TestPostScan:
    """Tests for _post_scan response parsing."""

    def test_success_returns_scan_dict(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        scan_dict = {"id": 10, "name": "test"}

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, payload=None: (200, json.dumps({"scan": scan_dict})))
        result = bridge._post_scan({"settings": {}})
        assert result == scan_dict

    def test_non_200_returns_none(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, payload=None: (412, "Precondition Failed"))
        result = bridge._post_scan({"settings": {}})
        assert result is None

    def test_malformed_json_returns_none(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, payload=None: (200, "not json"))
        result = bridge._post_scan({"settings": {}})
        assert result is None

    def test_missing_scan_key_returns_none(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, payload=None: (200, json.dumps({"error": "oops"})))
        result = bridge._post_scan({"settings": {}})
        assert result is None


# ===================================================================
# 9. launch_scan
# ===================================================================

class TestLaunchScan:
    """Tests for launch_scan behaviour."""

    def test_shortcircuits_when_launched(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = True
        bridge._scan_id = 5
        curl_called = []

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda *a, **kw: curl_called.append(1) or (200, ""))

        result = bridge.launch_scan(5)
        assert result is True
        assert len(curl_called) == 0

    def test_shortcircuit_fires_callback(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = True
        bridge._scan_id = 5
        cb_args = []
        bridge.progress_callback = lambda *a: cb_args.append(a)

        result = bridge.launch_scan(5)
        assert result is True
        assert cb_args == [("5", ScanStatus.RUNNING, 0, [])]

    def test_normal_launch_200(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = False
        bridge._scan_id = 10

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, payload=None: (200, "ok"))

        result = bridge.launch_scan(10)
        assert result is True

    def test_launch_failure_non_200(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = False
        bridge._scan_id = 10

        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, payload=None: (500, "error"))

        result = bridge.launch_scan(10)
        assert result is False

    def test_uses_provided_scan_id(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = False
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["path"] = path
            return 200, "ok"

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.launch_scan(99)

        assert "/scans/99/launch" in captured["path"]

    def test_uses_stored_scan_id(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = False
        bridge._scan_id = 42
        captured = {}

        def fake_curl(method, path, payload=None):
            captured["path"] = path
            return 200, "ok"

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        bridge.launch_scan()

        assert "/scans/42/launch" in captured["path"]

    def test_no_scan_id_returns_false(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._launched = False
        bridge._scan_id = None

        result = bridge.launch_scan()
        assert result is False


# ===================================================================
# 10. _check_scan_api_feature
# ===================================================================

class TestCheckScanApiFeature:
    """Tests for scan_api feature detection and session auth fallback."""

    def test_api_enabled_no_fallback(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.server.properties = lambda: {
            "features": {"scan_api": True}, "nessus_type": "Nessus"}
        calls = []
        monkeypatch.setattr(bridge, "_obtain_api_token",
                            lambda: calls.append("api"))
        monkeypatch.setattr(bridge, "_obtain_session_token",
                            lambda: calls.append("session"))

        bridge._check_scan_api_feature()
        assert calls == []

    def test_api_missing_no_fallback(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.server.properties = lambda: {
            "features": {}, "nessus_type": "Nessus"}
        calls = []
        monkeypatch.setattr(bridge, "_obtain_api_token",
                            lambda: calls.append("api"))
        monkeypatch.setattr(bridge, "_obtain_session_token",
                            lambda: calls.append("session"))

        bridge._check_scan_api_feature()
        assert calls == []

    def test_api_false_triggers_fallback(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.server.properties = lambda: {
            "features": {"scan_api": False}, "nessus_type": "Nessus Professional"}
        calls = []
        monkeypatch.setattr(bridge, "_obtain_api_token",
                            lambda: calls.append("api"))
        monkeypatch.setattr(bridge, "_obtain_session_token",
                            lambda: calls.append("session"))

        bridge._check_scan_api_feature()
        assert "api" in calls
        assert "session" in calls

    def test_api_token_called_before_session(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._nessus.server.properties = lambda: {
            "features": {"scan_api": False}, "nessus_type": "Nessus Professional"}
        calls = []
        monkeypatch.setattr(bridge, "_obtain_api_token",
                            lambda: calls.append("api"))
        monkeypatch.setattr(bridge, "_obtain_session_token",
                            lambda: calls.append("session"))

        bridge._check_scan_api_feature()
        assert calls.index("api") < calls.index("session")

    def test_properties_exception_swallowed(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)

        def raise_err():
            raise RuntimeError("network down")

        bridge._nessus.server.properties = raise_err

        # Should not raise
        bridge._check_scan_api_feature()


# ===================================================================
# 11. _host_progress_pct (static helper)
# ===================================================================

class TestHostProgressPct:
    """Tests for NessusBridge._host_progress_pct.

    The Nessus API provides per-host progress as integer fields:
    - scanprogresscurrent: 0-100 (current percent)
    - scanprogresstotal: 100 (always 100)
    """

    def test_complete_host(self):
        host = {"scanprogresscurrent": 100, "scanprogresstotal": 100}
        assert NessusBridge._host_progress_pct(host) == 100

    def test_partial_host(self):
        host = {"scanprogresscurrent": 45, "scanprogresstotal": 100}
        assert NessusBridge._host_progress_pct(host) == 45

    def test_zero_progress(self):
        host = {"scanprogresscurrent": 0, "scanprogresstotal": 100}
        assert NessusBridge._host_progress_pct(host) == 0

    def test_missing_fields_returns_zero(self):
        assert NessusBridge._host_progress_pct({}) == 0

    def test_missing_total_returns_zero(self):
        assert NessusBridge._host_progress_pct({"scanprogresscurrent": 50}) == 0

    def test_zero_total_returns_zero(self):
        host = {"scanprogresscurrent": 50, "scanprogresstotal": 0}
        assert NessusBridge._host_progress_pct(host) == 0

    def test_caps_at_100(self):
        """Progress should never exceed 100%."""
        host = {"scanprogresscurrent": 150, "scanprogresstotal": 100}
        assert NessusBridge._host_progress_pct(host) == 100


# ===================================================================
# 12. get_scan_status — progress from real Nessus host data
# ===================================================================

class TestGetScanStatusProgress:
    """Tests for get_scan_status progress computation.

    Progress is computed by averaging scanprogresscurrent/scanprogresstotal
    across all hosts in the response.
    """

    def test_completed_status_forces_100(self, monkeypatch):
        """Even if hosts show partial progress, completed → 100%."""
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "completed", "hostcount": 4},
            "hosts": [
                {"scanprogresscurrent": 100, "scanprogresstotal": 100},
                {"scanprogresscurrent": 50, "scanprogresstotal": 100},
            ],
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["progress"] == 100

    def test_average_across_hosts(self, monkeypatch):
        """Progress is average of per-host scanprogresscurrent."""
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 4},
            "hosts": [
                {"scanprogresscurrent": 45, "scanprogresstotal": 100},
                {"scanprogresscurrent": 100, "scanprogresstotal": 100},
                {"scanprogresscurrent": 100, "scanprogresstotal": 100},
                {"scanprogresscurrent": 99, "scanprogresstotal": 100},
            ],
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        # (45 + 100 + 100 + 99) / 4 = 86
        assert result["progress"] == 86

    def test_all_hosts_complete_gives_100(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 3},
            "hosts": [
                {"scanprogresscurrent": 100, "scanprogresstotal": 100},
                {"scanprogresscurrent": 100, "scanprogresstotal": 100},
                {"scanprogresscurrent": 100, "scanprogresstotal": 100},
            ],
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["progress"] == 100

    def test_no_hosts_gives_zero(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 4},
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["progress"] == 0

    def test_single_host_partial(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 1},
            "hosts": [
                {"scanprogresscurrent": 72, "scanprogresstotal": 100},
            ],
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["progress"] == 72

    def test_host_progress_returned(self, monkeypatch):
        """get_scan_status returns per-host progress list."""
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 2},
            "hosts": [
                {"hostname": "192.168.1.10", "scanprogresscurrent": 100, "scanprogresstotal": 100},
                {"hostname": "192.168.1.20", "scanprogresscurrent": 50, "scanprogresstotal": 100},
            ],
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        hp = result["host_progress"]
        assert len(hp) == 2
        assert hp[0] == {"hostname": "192.168.1.10", "progress": 100}
        assert hp[1] == {"hostname": "192.168.1.20", "progress": 50}

    def test_host_progress_empty_when_no_hosts(self, monkeypatch):
        """host_progress is empty list when no hosts in response."""
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 0},
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["host_progress"] == []

    def test_host_progress_uses_host_ip_fallback(self, monkeypatch):
        """Falls back to host_ip when hostname is missing."""
        bridge = _make_bridge(monkeypatch)
        body = json.dumps({
            "info": {"name": "s", "status": "running", "hostcount": 1},
            "hosts": [
                {"host_ip": "10.0.0.1", "scanprogresscurrent": 80, "scanprogresstotal": 100},
            ],
        })
        monkeypatch.setattr(bridge, "_curl_nessus",
                            lambda m, p, **kw: (200, body))

        result = bridge.get_scan_status(1)
        assert result["host_progress"][0]["hostname"] == "10.0.0.1"


# ===================================================================
# 13. NessusPolicyManager credential removal
# ===================================================================

class TestPolicyManagerCurl:
    """Tests for NessusPolicyManager curl-based API calls."""

    def _make_manager(self, monkeypatch):
        """Build a NessusPolicyManager with resolved keys and mock pyTenable."""
        from enso.nessus_policy import NessusPolicyManager

        monkeypatch.setattr("enso.config.models.load_nessus_keys",
                            lambda: None, raising=False)
        set_nessus_file_security(True)

        config = NessusConfig(url="https://nessus:8834")
        manager = NessusPolicyManager(config)
        manager._resolved_keys = ("ak_test", "sk_test")
        manager._nessus = SimpleNamespace(
            server=SimpleNamespace(status=lambda: {"status": "ready"}),
            policies=SimpleNamespace(
                list=lambda: [{"name": "TestPolicy", "id": 42}],
                details=lambda pid: {},
                edit=lambda pid, **kw: kw,
            ),
        )
        return manager

    def test_curl_nessus_command_shape(self, monkeypatch):
        """Verify exact curl command with API key auth header."""
        manager = self._make_manager(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc('{"ok": true}\n200')

        monkeypatch.setattr(subprocess, "run", fake_run)

        status, body = manager._curl_nessus("GET", "/policies/42")

        assert status == 200
        assert captured["cmd"][0] == "curl"
        assert "-sk" in captured["cmd"]
        assert "GET" in captured["cmd"]
        assert "https://nessus:8834/policies/42" in captured["cmd"]
        # API key header
        auth_idx = captured["cmd"].index("X-APIKeys: accessKey=ak_test; secretKey=sk_test")
        assert captured["cmd"][auth_idx - 1] == "-H"

    def test_curl_nessus_post_with_payload(self, monkeypatch):
        """POST includes -d with JSON payload."""
        manager = self._make_manager(monkeypatch)
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return _make_proc('{}\n200')

        monkeypatch.setattr(subprocess, "run", fake_run)

        manager._curl_nessus("PUT", "/policies/42", {"credentials": {"add": {}}})

        assert "PUT" in captured["cmd"]
        assert "-d" in captured["cmd"]
        d_idx = captured["cmd"].index("-d")
        payload = json.loads(captured["cmd"][d_idx + 1])
        assert "credentials" in payload

    def test_curl_nessus_no_keys_returns_zero(self, monkeypatch):
        """No resolved keys → returns (0, '')."""
        manager = self._make_manager(monkeypatch)
        manager._resolved_keys = None

        status, body = manager._curl_nessus("GET", "/policies/1")
        assert status == 0
        assert body == ""

    def test_curl_nessus_subprocess_exception(self, monkeypatch):
        """Subprocess failure → returns (0, '')."""
        manager = self._make_manager(monkeypatch)

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(OSError("fail")))

        status, body = manager._curl_nessus("GET", "/policies/1")
        assert status == 0

    def test_get_policy_by_name_prefers_curl(self, monkeypatch):
        """get_policy_by_name uses curl for details, not pyTenable."""
        manager = self._make_manager(monkeypatch)
        pytenable_called = {"called": False}

        def spy_details(pid):
            pytenable_called["called"] = True
            return {}

        manager._nessus.policies.details = spy_details

        raw_details = {
            "credentials": {"current": {"Host": {
                "SSH": [{"id": 5, "username": "root"}],
            }}}
        }

        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(json.dumps(raw_details) + "\n200"))

        result = manager.get_policy_by_name("TestPolicy")

        assert result is not None
        policy_id, details = result
        assert policy_id == 42
        assert details == raw_details
        assert not pytenable_called["called"]

    def test_get_policy_by_name_falls_back_to_pytenable(self, monkeypatch):
        """When curl fails, falls back to pyTenable details."""
        manager = self._make_manager(monkeypatch)
        pytenable_details = {"pytenable": True}
        manager._nessus.policies.details = lambda pid: pytenable_details

        # Curl returns HTTP 403
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc('Forbidden\n403'))

        result = manager.get_policy_by_name("TestPolicy")

        assert result is not None
        policy_id, details = result
        assert policy_id == 42
        assert details == pytenable_details

    def test_get_policy_by_name_not_found(self, monkeypatch):
        """Policy name not in list → returns None."""
        manager = self._make_manager(monkeypatch)

        result = manager.get_policy_by_name("NonExistent")
        assert result is None


class TestPolicyCredentialIds:
    """Tests for credential parsing and ID extraction from real Nessus format.

    The raw Nessus API (GET /policies/{id}) returns credentials as::

        {"credentials": {"edit": {"48": {cred_data}, "24": {cred_data}}}}

    where each key is the credential ID and auth_method case determines type:
    - "Password" (capital P) → Windows
    - "password" (lowercase) → SSH
    """

    def _make_manager_with_policy(self, monkeypatch, policy_details):
        """Build a NessusPolicyManager that returns raw policy details."""
        from enso.nessus_policy import NessusPolicyManager

        monkeypatch.setattr("enso.config.models.load_nessus_keys",
                            lambda: None, raising=False)
        set_nessus_file_security(True)

        config = NessusConfig(url="https://nessus:8834")
        manager = NessusPolicyManager(config)
        manager._resolved_keys = ("ak", "sk")
        manager._nessus = SimpleNamespace(
            server=SimpleNamespace(status=lambda: {"status": "ready"}),
            policies=SimpleNamespace(
                list=lambda: [{"name": "TestPolicy", "id": 1}],
                details=lambda pid: policy_details,
                edit=lambda pid, **kw: kw,
            ),
        )
        # Mock curl to return the raw policy details
        raw_body = json.dumps(policy_details)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: _make_proc(raw_body + "\n200"))
        return manager

    def test_extracts_credential_ids_from_edit_keys(self, monkeypatch):
        """IDs are the keys of credentials.edit dict."""
        details = {
            "credentials": {"edit": {
                "48": {"username": "admin", "auth_method": "Password", "domain": "CORP"},
                "24": {"username": "root", "auth_method": "password"},
            }},
        }
        manager = self._make_manager_with_policy(monkeypatch, details)

        ids = manager.get_policy_credential_ids("TestPolicy")
        assert sorted(ids) == [24, 48]

    def test_parses_windows_credential(self, monkeypatch):
        """auth_method 'Password' (capital P) → windows type."""
        details = {
            "credentials": {"edit": {
                "10": {
                    "username": "administrator",
                    "auth_method": "Password",
                    "domain": "CORP",
                },
            }},
        }
        manager = self._make_manager_with_policy(monkeypatch, details)

        creds = manager.get_policy_credentials("TestPolicy")
        assert len(creds) == 1
        assert creds[0].credential_type == "windows"
        assert creds[0].username == "administrator"
        assert creds[0].domain == "CORP"

    def test_parses_ssh_credential(self, monkeypatch):
        """auth_method 'password' (lowercase) → ssh type."""
        details = {
            "credentials": {"edit": {
                "20": {
                    "username": "scanuser",
                    "auth_method": "password",
                    "elevate_privileges_with": "sudo",
                },
            }},
        }
        manager = self._make_manager_with_policy(monkeypatch, details)

        creds = manager.get_policy_credentials("TestPolicy")
        assert len(creds) == 1
        assert creds[0].credential_type == "ssh"
        assert creds[0].username == "scanuser"

    def test_parses_mixed_credentials(self, monkeypatch):
        """Both Windows and SSH parsed correctly from one edit dict."""
        details = {
            "credentials": {"edit": {
                "48": {"username": "admin", "auth_method": "Password", "domain": "CORP"},
                "24": {"username": "root", "auth_method": "password"},
            }},
        }
        manager = self._make_manager_with_policy(monkeypatch, details)

        creds = manager.get_policy_credentials("TestPolicy")
        assert len(creds) == 2
        types = {c.credential_type for c in creds}
        assert types == {"windows", "ssh"}

    def test_empty_edit_returns_no_ids(self, monkeypatch):
        details = {"credentials": {"edit": {}}}
        manager = self._make_manager_with_policy(monkeypatch, details)

        ids = manager.get_policy_credential_ids("TestPolicy")
        assert ids == []

    def test_missing_credentials_key_returns_no_ids(self, monkeypatch):
        details = {}
        manager = self._make_manager_with_policy(monkeypatch, details)

        ids = manager.get_policy_credential_ids("TestPolicy")
        assert ids == []

    def test_no_edit_key_returns_no_ids(self, monkeypatch):
        """credentials exists but has no 'edit' key."""
        details = {"credentials": {"add": {}}}
        manager = self._make_manager_with_policy(monkeypatch, details)

        ids = manager.get_policy_credential_ids("TestPolicy")
        assert ids == []

    def test_update_with_delete_ids(self, monkeypatch):
        details = {
            "credentials": {"edit": {
                "10": {"username": "old_admin", "auth_method": "Password"},
            }},
        }
        manager = self._make_manager_with_policy(monkeypatch, details)
        captured = {}

        def fake_edit(pid, **kw):
            captured["pid"] = pid
            captured["credentials"] = kw.get("credentials")

        manager._nessus.policies.edit = fake_edit

        from enso.config.models import CredentialsConfig, WindowsCredential
        creds = CredentialsConfig(
            windows={"new": WindowsCredential(username="new_admin", password="pw")},
        )

        manager.update_policy_credentials(
            "TestPolicy", creds, delete_ids=[10]
        )

        assert captured["credentials"]["delete"] == [10]
        assert "add" in captured["credentials"]

    def test_update_without_delete_ids(self, monkeypatch):
        details = {"credentials": {"edit": {}}}
        manager = self._make_manager_with_policy(monkeypatch, details)
        captured = {}

        def fake_edit(pid, **kw):
            captured["credentials"] = kw.get("credentials")

        manager._nessus.policies.edit = fake_edit

        from enso.config.models import CredentialsConfig, LinuxCredential
        creds = CredentialsConfig(
            linux={"user": LinuxCredential(username="user1", password="pw")},
        )

        manager.update_policy_credentials("TestPolicy", creds)

        assert "delete" not in captured["credentials"]
        assert "add" in captured["credentials"]

    def test_update_falls_back_to_curl_on_pytenable_failure(self, monkeypatch):
        """When pyTenable edit raises, curl PUT is tried as fallback."""
        details = {"credentials": {"edit": {}}}
        manager = self._make_manager_with_policy(monkeypatch, details)
        curl_calls = []

        def failing_edit(pid, **kw):
            raise RuntimeError("pyTenable exploded")

        manager._nessus.policies.edit = failing_edit

        def tracking_curl(method, path, payload=None):
            curl_calls.append((method, path, payload))
            return (200, '{}')

        manager._curl_nessus = tracking_curl

        from enso.config.models import CredentialsConfig, LinuxCredential
        creds = CredentialsConfig(
            linux={"user": LinuxCredential(username="user1", password="pw")},
        )

        result = manager.update_policy_credentials("TestPolicy", creds)

        assert result is True
        methods = [c[0] for c in curl_calls]
        assert "GET" in methods
        assert "PUT" in methods


# ===================================================================
# 14. poll_until_complete — host_progress passed through callback
# ===================================================================

class TestPollHostProgress:
    """Tests that poll_until_complete passes host_progress to the callback."""

    def test_callback_receives_host_progress(self, monkeypatch):
        """Callback 4th argument is the host_progress list from get_scan_status."""
        bridge = _make_bridge(monkeypatch)
        bridge._scan_id = 1

        poll_count = {"n": 0}
        cb_calls = []

        def fake_get_status(sid):
            poll_count["n"] += 1
            if poll_count["n"] == 1:
                return {
                    "status": "running", "progress": 50,
                    "host_progress": [
                        {"hostname": "10.0.0.1", "progress": 100},
                        {"hostname": "10.0.0.2", "progress": 0},
                    ],
                }
            return {
                "status": "completed", "progress": 100,
                "host_progress": [
                    {"hostname": "10.0.0.1", "progress": 100},
                    {"hostname": "10.0.0.2", "progress": 100},
                ],
            }

        bridge.get_scan_status = fake_get_status
        bridge.progress_callback = lambda *a: cb_calls.append(a)

        # No sleep needed since we complete in 2 polls
        monkeypatch.setattr("time.sleep", lambda _: None)

        bridge.poll_until_complete(1, poll_interval=0)

        # First call: running with mixed host progress
        assert cb_calls[0][0] == "1"
        assert cb_calls[0][1] == ScanStatus.RUNNING
        assert cb_calls[0][2] == 50
        assert len(cb_calls[0][3]) == 2
        assert cb_calls[0][3][0]["hostname"] == "10.0.0.1"

        # Second call: completed
        assert cb_calls[1][1] == ScanStatus.COMPLETED
        assert cb_calls[1][2] == 100

    def test_callback_gets_empty_list_on_no_hosts(self, monkeypatch):
        """When get_scan_status has no host_progress, callback gets []."""
        bridge = _make_bridge(monkeypatch)
        bridge._scan_id = 1

        def fake_get_status(sid):
            return {"status": "completed", "progress": 100}

        bridge.get_scan_status = fake_get_status
        bridge.progress_callback = lambda *a: cb_calls.append(a)

        cb_calls = []
        monkeypatch.setattr("time.sleep", lambda _: None)

        bridge.poll_until_complete(1, poll_interval=0)

        assert cb_calls[0][3] == []


# ===================================================================
# 15. Orchestrator _on_nessus_progress — per-host status updates
# ===================================================================

class TestOrchestratorPerHostNessus:
    """Tests that _on_nessus_progress updates per-host dashboard status."""

    def _make_orchestrator(self, monkeypatch, hosts):
        """Build a minimal ScanOrchestrator with a mock dashboard."""
        from enso.orchestrator import ScanOrchestrator

        monkeypatch.setattr("enso.config.models.load_nessus_keys",
                            lambda: None, raising=False)
        set_nessus_file_security(True)

        config = SimpleNamespace(
            nmap=SimpleNamespace(
                quality_gate=SimpleNamespace(dead_host_threshold=0.5),
            ),
            nessus=NessusConfig(url="https://nessus:8834"),
            credentials=None,
            global_config=SimpleNamespace(
                execution_strategy="linear",
                get_module_by_name=lambda name: None,
            ),
        )
        context = SimpleNamespace(
            scans_nmap_dir="/tmp/nmap",
            scope_files=SimpleNamespace(excluded=None),
            network_drop=None,
            engagement_type="simple",
        )

        # Avoid full __init__ — just set the fields we need
        orch = object.__new__(ScanOrchestrator)
        orch.config = config
        orch.context = context
        orch.skip_nessus = False

        # Mock dashboard with host tracking
        host_statuses = {}
        progress_updates = {}

        class MockDashboard:
            def __init__(self):
                self.hosts = {ip: {} for ip in hosts}

            def update_host_status(self, ip, scan_type, status, open_ports=None):
                host_statuses[(ip, scan_type)] = status

            def update_progress(self, scan_type, count):
                progress_updates[scan_type] = count

        orch.dashboard = MockDashboard()
        orch._completed_counts = {"discovery": 0, "deep": 0, "nessus": 0}

        return orch, host_statuses, progress_updates

    def test_running_marks_complete_hosts(self, monkeypatch):
        """Hosts at 100% are marked COMPLETED in the dashboard."""
        hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        orch, host_statuses, _ = self._make_orchestrator(monkeypatch, hosts)

        host_progress = [
            {"hostname": "10.0.0.1", "progress": 100},
            {"hostname": "10.0.0.2", "progress": 50},
            {"hostname": "10.0.0.3", "progress": 100},
        ]

        orch._on_nessus_progress("scan1", ScanStatus.RUNNING, 83, host_progress)

        assert host_statuses[("10.0.0.1", "nessus")] == ScanStatus.COMPLETED
        assert ("10.0.0.2", "nessus") not in host_statuses
        assert host_statuses[("10.0.0.3", "nessus")] == ScanStatus.COMPLETED

    def test_running_updates_completed_count(self, monkeypatch):
        """Completed count reflects actual per-host completions."""
        hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        orch, _, progress_updates = self._make_orchestrator(monkeypatch, hosts)

        host_progress = [
            {"hostname": "10.0.0.1", "progress": 100},
            {"hostname": "10.0.0.2", "progress": 100},
            {"hostname": "10.0.0.3", "progress": 50},
            {"hostname": "10.0.0.4", "progress": 0},
        ]

        orch._on_nessus_progress("scan1", ScanStatus.RUNNING, 62, host_progress)

        assert orch._completed_counts["nessus"] == 2
        assert progress_updates["nessus"] == 2

    def test_running_without_host_progress_uses_estimate(self, monkeypatch):
        """Without host_progress, falls back to estimate from overall %."""
        hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        orch, _, progress_updates = self._make_orchestrator(monkeypatch, hosts)

        orch._on_nessus_progress("scan1", ScanStatus.RUNNING, 50, [])

        assert orch._completed_counts["nessus"] == 2  # 50% of 4
        assert progress_updates["nessus"] == 2

    def test_completed_marks_all_hosts(self, monkeypatch):
        """COMPLETED status marks every host as COMPLETED."""
        hosts = ["10.0.0.1", "10.0.0.2"]
        orch, host_statuses, progress_updates = self._make_orchestrator(monkeypatch, hosts)

        orch._on_nessus_progress("scan1", ScanStatus.COMPLETED, 100, [])

        assert host_statuses[("10.0.0.1", "nessus")] == ScanStatus.COMPLETED
        assert host_statuses[("10.0.0.2", "nessus")] == ScanStatus.COMPLETED
        assert progress_updates["nessus"] == 2

    def test_failed_marks_all_hosts(self, monkeypatch):
        """FAILED status marks every host as FAILED."""
        hosts = ["10.0.0.1", "10.0.0.2"]
        orch, host_statuses, progress_updates = self._make_orchestrator(monkeypatch, hosts)

        orch._on_nessus_progress("scan1", ScanStatus.FAILED, 50, [])

        assert host_statuses[("10.0.0.1", "nessus")] == ScanStatus.FAILED
        assert host_statuses[("10.0.0.2", "nessus")] == ScanStatus.FAILED

    def test_unknown_host_in_progress_is_ignored(self, monkeypatch):
        """Hostnames not in dashboard are silently skipped."""
        hosts = ["10.0.0.1"]
        orch, host_statuses, _ = self._make_orchestrator(monkeypatch, hosts)

        host_progress = [
            {"hostname": "10.0.0.1", "progress": 100},
            {"hostname": "10.0.0.99", "progress": 100},  # not in dashboard
        ]

        orch._on_nessus_progress("scan1", ScanStatus.RUNNING, 100, host_progress)

        assert host_statuses[("10.0.0.1", "nessus")] == ScanStatus.COMPLETED
        assert ("10.0.0.99", "nessus") not in host_statuses


# ===================================================================
# TestCurlNessusDownload
# ===================================================================

class TestCurlNessusDownload:
    """Tests for the _curl_nessus_download() binary download helper."""

    def test_download_uses_session_auth(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess123"
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            # Create the output file to simulate download
            for i, arg in enumerate(cmd):
                if arg == "-o" and i + 1 < len(cmd):
                    from pathlib import Path
                    Path(cmd[i + 1]).write_text("<nessus/>")
            return _make_proc("200")

        monkeypatch.setattr(subprocess, "run", fake_run)

        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "test.nessus"
            result = bridge._curl_nessus_download("/tokens/abc/download", out)

            assert result is True
            assert "X-Cookie: token=sess123" in captured["cmd"]
            assert "-o" in captured["cmd"]

    def test_download_uses_api_key_auth(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = None
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            for i, arg in enumerate(cmd):
                if arg == "-o" and i + 1 < len(cmd):
                    from pathlib import Path
                    Path(cmd[i + 1]).write_text("<nessus/>")
            return _make_proc("200")

        monkeypatch.setattr(subprocess, "run", fake_run)

        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "test.nessus"
            result = bridge._curl_nessus_download("/tokens/abc/download", out)

            assert result is True
            assert "X-APIKeys: accessKey=a;secretKey=s" in captured["cmd"]

    def test_download_returns_false_on_failure(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _make_proc("404"))

        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "test.nessus"
            result = bridge._curl_nessus_download("/tokens/abc/download", out)
            assert result is False

    def test_download_includes_csrf_token(self, monkeypatch):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"
        bridge._api_token = "csrf-uuid"
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            for i, arg in enumerate(cmd):
                if arg == "-o" and i + 1 < len(cmd):
                    from pathlib import Path
                    Path(cmd[i + 1]).write_text("<nessus/>")
            return _make_proc("200")

        monkeypatch.setattr(subprocess, "run", fake_run)

        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "test.nessus"
            bridge._curl_nessus_download("/tokens/abc/download", out)
            assert "X-Api-Token: csrf-uuid" in captured["cmd"]


# ===================================================================
# TestExportScan
# ===================================================================

class TestExportScan:
    """Tests for the export_scan() token-based export flow."""

    def test_export_requests_token(self, monkeypatch, tmp_path):
        """POST /scans/{id}/export is called with correct format payload."""
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"
        calls = []

        def fake_curl(method, path, payload=None, _retried=False):
            calls.append((method, path, payload))
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok123", "file": 12345})
            if "/tokens/tok123/status" in path:
                return 200, json.dumps({"status": "ready"})
            return 200, ""

        def fake_download(path, output_path):
            output_path.write_text("<nessus/>")
            return True

        # HEAD request for Content-Disposition
        monkeypatch.setattr(subprocess, "run",
            lambda cmd, **kw: _make_proc('Content-Disposition: attachment; filename="scan.nessus"\n\n'))

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr(bridge, "_curl_nessus_download", fake_download)

        bridge.export_scan(86, tmp_path)

        post_call = calls[0]
        assert post_call[0] == "POST"
        assert "/scans/86/export" in post_call[1]
        assert post_call[2] == {"format": "nessus"}

    def test_export_polls_until_ready(self, monkeypatch, tmp_path):
        """GET /tokens/{token}/status is polled until status=ready."""
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"
        poll_count = 0

        def fake_curl(method, path, payload=None, _retried=False):
            nonlocal poll_count
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok", "file": 1})
            if "/tokens/tok/status" in path:
                poll_count += 1
                if poll_count < 3:
                    return 200, json.dumps({"status": "loading"})
                return 200, json.dumps({"status": "ready"})
            return 200, ""

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr(bridge, "_curl_nessus_download",
            lambda path, out: (out.write_text("<n/>"), True)[1])
        monkeypatch.setattr(subprocess, "run",
            lambda cmd, **kw: _make_proc(""))
        monkeypatch.setattr("time.sleep", lambda s: None)

        bridge.export_scan(86, tmp_path)
        assert poll_count == 3

    def test_export_downloads_file(self, monkeypatch, tmp_path):
        """The exported file is written to the output directory."""
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        def fake_curl(method, path, payload=None, _retried=False):
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok", "file": 1})
            if "/tokens/tok/status" in path:
                return 200, json.dumps({"status": "ready"})
            return 200, ""

        def fake_download(path, output_path):
            output_path.write_text("<nessus data/>")
            return True

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr(bridge, "_curl_nessus_download", fake_download)
        monkeypatch.setattr(subprocess, "run",
            lambda cmd, **kw: _make_proc(
                'Content-Disposition: attachment; filename="internal_scan.nessus"\n\n'
            ))

        result = bridge.export_scan(86, tmp_path)

        assert result is not None
        assert result.exists()
        assert result.name == "internal_scan.nessus"

    def test_export_returns_none_on_post_failure(self, monkeypatch, tmp_path):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        monkeypatch.setattr(bridge, "_curl_nessus",
            lambda m, p, payload=None, _retried=False: (500, "error"))

        result = bridge.export_scan(86, tmp_path)
        assert result is None

    def test_export_returns_none_on_poll_timeout(self, monkeypatch, tmp_path):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        def fake_curl(method, path, payload=None, _retried=False):
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok", "file": 1})
            if "/tokens/tok/status" in path:
                return 200, json.dumps({"status": "loading"})
            return 200, ""

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = bridge.export_scan(86, tmp_path)
        assert result is None

    def test_export_fallback_filename_no_scan_name(self, monkeypatch, tmp_path):
        """Without scan_name or Content-Disposition, falls back to scan_{id}.nessus."""
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        def fake_curl(method, path, payload=None, _retried=False):
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok", "file": 1})
            if "/tokens/tok/status" in path:
                return 200, json.dumps({"status": "ready"})
            return 200, ""

        def fake_download(path, output_path):
            output_path.write_text("<nessus/>")
            return True

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr(bridge, "_curl_nessus_download", fake_download)
        # HEAD returns no Content-Disposition
        monkeypatch.setattr(subprocess, "run",
            lambda cmd, **kw: _make_proc("HTTP/1.1 200 OK\n\n"))

        result = bridge.export_scan(86, tmp_path)

        assert result is not None
        assert result.name == "scan_86.nessus"

    def test_export_scan_name_fallback(self, monkeypatch, tmp_path):
        """With scan_name provided and no Content-Disposition, uses scan name as filename."""
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        def fake_curl(method, path, payload=None, _retried=False):
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok", "file": 1})
            if "/tokens/tok/status" in path:
                return 200, json.dumps({"status": "ready"})
            return 200, ""

        def fake_download(path, output_path):
            output_path.write_text("<nessus/>")
            return True

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr(bridge, "_curl_nessus_download", fake_download)
        monkeypatch.setattr(subprocess, "run",
            lambda cmd, **kw: _make_proc("HTTP/1.1 200 OK\n\n"))

        result = bridge.export_scan(
            86, tmp_path, scan_name="internal_20260213_112204"
        )

        assert result is not None
        assert result.name == "internal_20260213_112204.nessus"

    def test_export_returns_none_on_download_failure(self, monkeypatch, tmp_path):
        bridge = _make_bridge(monkeypatch)
        bridge._session_token = "sess"

        def fake_curl(method, path, payload=None, _retried=False):
            if method == "POST" and "/export" in path:
                return 200, json.dumps({"token": "tok", "file": 1})
            if "/tokens/tok/status" in path:
                return 200, json.dumps({"status": "ready"})
            return 200, ""

        monkeypatch.setattr(bridge, "_curl_nessus", fake_curl)
        monkeypatch.setattr(bridge, "_curl_nessus_download",
            lambda path, out: False)
        monkeypatch.setattr(subprocess, "run",
            lambda cmd, **kw: _make_proc(""))

        result = bridge.export_scan(86, tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# Output directory routing for multi-scan export
# ---------------------------------------------------------------------------

class TestResolveNessusOutputDir:
    """Tests for _resolve_nessus_output_dir() scan-name routing."""

    def _make_config(self, network_drops=None, simple_output_dir="internal"):
        """Build a minimal config-like object for routing tests."""
        drops = network_drops or []
        return SimpleNamespace(
            engagement=SimpleNamespace(
                network_drops=drops,
                simple=SimpleNamespace(output_dir=simple_output_dir),
            ),
            global_config=SimpleNamespace(
                get_module_output_dir=lambda name: "nessus" if name == "nessus" else name,
            ),
        )

    def _make_drop(self, name, network_dir=None, output_dir=None):
        """Build a minimal network drop with get_network_dir/get_output_dir."""
        nd = network_dir or name.lower().replace(" ", "_")
        od = output_dir or nd
        return SimpleNamespace(
            name=name,
            get_network_dir=lambda _nd=nd: _nd,
            get_output_dir=lambda _od=od: _od,
        )

    def test_matches_network_drop(self, tmp_path):
        from enso.cli import _resolve_nessus_output_dir

        drop = self._make_drop("Server Room", network_dir="server_room")
        config = self._make_config(network_drops=[drop])

        result = _resolve_nessus_output_dir(
            "server_room_20260213_112204", config, tmp_path
        )
        assert result == tmp_path / "server_room" / "scans" / "nessus"

    def test_falls_back_to_simple(self, tmp_path):
        from enso.cli import _resolve_nessus_output_dir

        config = self._make_config(network_drops=[], simple_output_dir="internal")

        result = _resolve_nessus_output_dir(
            "internal_20260213_112204", config, tmp_path
        )
        assert result == tmp_path / "internal" / "scans" / "nessus"

    def test_no_match_falls_back(self, tmp_path):
        from enso.cli import _resolve_nessus_output_dir

        drop = self._make_drop("Server Room", network_dir="server_room")
        config = self._make_config(
            network_drops=[drop], simple_output_dir="internal"
        )

        result = _resolve_nessus_output_dir(
            "unknown_net_20260213_112204", config, tmp_path
        )
        assert result == tmp_path / "internal" / "scans" / "nessus"

    def test_handles_non_standard_name(self, tmp_path):
        """Scan name without timestamp pattern falls back to simple."""
        from enso.cli import _resolve_nessus_output_dir

        drop = self._make_drop("Internal", network_dir="internal")
        config = self._make_config(
            network_drops=[drop], simple_output_dir="internal"
        )

        result = _resolve_nessus_output_dir(
            "my_custom_scan", config, tmp_path
        )
        assert result == tmp_path / "internal" / "scans" / "nessus"

    def test_matches_correct_drop_among_multiple(self, tmp_path):
        """With multiple drops, routes to the correct one."""
        from enso.cli import _resolve_nessus_output_dir

        drops = [
            self._make_drop("Internal", network_dir="internal"),
            self._make_drop("Server Room", network_dir="server_room"),
            self._make_drop("DMZ", network_dir="dmz"),
        ]
        config = self._make_config(network_drops=drops)

        result = _resolve_nessus_output_dir(
            "dmz_20260226_143022", config, tmp_path
        )
        assert result == tmp_path / "dmz" / "scans" / "nessus"
