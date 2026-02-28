"""Nessus API bridge using pyTenable."""

from __future__ import annotations

import json as _json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import NessusConfig, CredentialsConfig
from .ui.prompts import Prompts
from .ui.dashboard import ScanStatus
from .utils.logging import get_logger

logger = get_logger(__name__)


class NessusBridge:
    """Bridge to Nessus scanner via pyTenable API."""
    
    def __init__(
        self,
        config: NessusConfig,
        credentials: CredentialsConfig | None = None,
        progress_callback: Callable[[str, ScanStatus, int, list[dict]], None] | None = None,
    ):
        """Initialize the Nessus bridge.
        
        Args:
            config: Nessus configuration
            credentials: Optional credentials for authenticated scanning
            progress_callback: Callback for progress updates (scan_name, status, progress_pct, host_progress)
        """
        self.config = config
        self.credentials = credentials
        self.progress_callback = progress_callback
        self._nessus = None
        self._scan_id: int | None = None
        self._launched: bool = False
        self._session_token: str | None = None
        self._api_token: str | None = None
        self._session_username: str | None = None
        self._session_password: str | None = None
    
    def _ensure_credentials(self) -> tuple[str, str]:
        """Ensure API credentials are available, prompting if needed.
        
        Returns:
            Tuple of (access_key, secret_key)
        """
        access_key = self.config.access_key
        secret_key = self.config.secret_key
        
        needs_prompt = self.config.needs_runtime_prompt()
        
        if needs_prompt["access_key"]:
            access_key = Prompts.prompt_secret("Nessus Access Key", "NESSUS_ACCESS_KEY")
        
        if needs_prompt["secret_key"]:
            secret_key = Prompts.prompt_secret("Nessus Secret Key", "NESSUS_SECRET_KEY")
        
        return access_key, secret_key
    
    def connect(self) -> bool:
        """Connect to the Nessus API.
        
        Returns:
            True if connection successful
        """
        try:
            from tenable.nessus import Nessus
        except ImportError:
            logger.error("pytenable not installed. Run: pip install pytenable")
            return False
        
        access_key, secret_key = self._ensure_credentials()
        
        try:
            self._nessus = Nessus(
                url=self.config.url,
                access_key=access_key,
                secret_key=secret_key,
            )
            # Test connection and check readiness
            server_status = self._nessus.server.status()
            status_str = server_status.get("status", "unknown")
            logger.info(f"Connected to Nessus at {self.config.url} (status: {status_str})")

            if status_str != "ready":
                progress = server_status.get("progress")
                msg = f"Nessus is not ready (status: {status_str})"
                if progress is not None:
                    msg += f", progress: {progress}%"
                msg += " — scan API will be unavailable until ready"
                logger.warning(msg)

            # Check if the scan API feature is enabled in the license
            self._check_scan_api_feature()

            return True
        except Exception as e:
            logger.error(f"Failed to connect to Nessus: {e}")
            return False

    def _check_scan_api_feature(self) -> None:
        """Check scan API access; fall back to session auth if disabled."""
        try:
            props = self._nessus.server.properties()
            features = props.get("features", {})
            nessus_type = props.get("nessus_type", "unknown")

            if features.get("scan_api") is not False:
                return  # API key auth is fine

            logger.warning(
                f"Nessus scan API is disabled for API-key auth "
                f"(edition: {nessus_type}). Falling back to session auth."
            )
            self._obtain_api_token()       # CSRF token first
            self._obtain_session_token()   # then session (needs CSRF)

        except Exception as e:
            logger.debug(f"Could not check Nessus features: {e}")

    def _obtain_api_token(self) -> None:
        """Extract the X-Api-Token (CSRF) from /nessus6.js.

        The Nessus web UI embeds a static UUID v4 in nessus6.js that must be
        sent as ``X-Api-Token`` on every API request (including POST /session).
        No authentication is required to fetch this resource.
        """
        import re

        try:
            proc = subprocess.run(
                ["curl", "-sk", f"{self.config.url}/nessus6.js"],
                capture_output=True, text=True, timeout=30,
            )
            match = re.search(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                proc.stdout,
            )
            if match:
                self._api_token = match.group(0)
                logger.info("Obtained Nessus API token (CSRF) from /nessus6.js")
            else:
                logger.error("Could not extract API token from /nessus6.js")
        except Exception as e:
            logger.error(f"Failed to fetch /nessus6.js: {e}")

    def _obtain_session_token(self) -> None:
        """Authenticate with Nessus username/password to get a session token.

        Session auth (``X-Cookie``) bypasses the ``scan_api`` feature gate
        that blocks API-key auth on Nessus Professional 10.x.

        Credentials are resolved in order:
        1. ``nessus_ui`` section in credentials.yaml
        2. Interactive prompt at runtime
        """
        # Re-use saved credentials from a previous successful auth
        if self._session_username and self._session_password:
            username = self._session_username
            password = self._session_password
        else:
            # Check credentials.yaml first
            nessus_ui = getattr(self.credentials, "nessus_ui", None) if self.credentials else None
            if nessus_ui and not nessus_ui.needs_runtime_prompt():
                username = nessus_ui.username
                password = nessus_ui.password
                logger.info("Using Nessus web-UI credentials from credentials.yaml")
            else:
                from rich.prompt import Prompt

                logger.info("Nessus web-UI credentials required for scan operations")
                username = Prompt.ask("[cyan]Nessus username[/cyan]")
                password = Prompt.ask("[cyan]Nessus password[/cyan]", password=True)

        cmd = [
            "curl", "-sk",
            "-X", "POST", f"{self.config.url}/session",
            "-H", "Content-Type: application/json",
        ]
        if self._api_token:
            cmd.extend(["-H", f"X-Api-Token: {self._api_token}"])
        cmd.extend(["-d", _json.dumps({"username": username, "password": password})])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            data = _json.loads(proc.stdout)
            token = data.get("token")
            if token:
                self._session_token = token
                self._session_username = username
                self._session_password = password
                logger.info("Nessus session token obtained successfully")
            else:
                logger.error(f"Session auth failed: {proc.stdout[:200]}")
        except Exception as e:
            logger.error(f"Failed to obtain session token: {e}")
    
    def _resolve_policy(self, policy_name: str) -> tuple[int, str] | None:
        """Look up a Nessus policy ID and its template UUID by name.

        The Nessus scan creation API requires both a policy_id (in settings)
        and the template UUID (top-level) that the policy was created from.

        Args:
            policy_name: Name of the policy

        Returns:
            Tuple of (policy_id, template_uuid), or None if not found
        """
        try:
            policies = self._nessus.policies.list()
            available_names = []
            for p in policies:
                available_names.append(p["name"])
                if p["name"] == policy_name:
                    policy_id = p["id"]
                    template_uuid = p.get("template_uuid")

                    if not template_uuid:
                        # Fall back to full policy details
                        try:
                            details = self._nessus.policies.details(policy_id)
                            template_uuid = details.get("uuid") or details.get("template_uuid")
                        except Exception:
                            pass

                    if not template_uuid:
                        logger.error(
                            f"Policy '{policy_name}' found (id={policy_id}) "
                            "but could not resolve its template UUID"
                        )
                        return None

                    return policy_id, template_uuid

            logger.error(
                f"Policy '{policy_name}' not found on Nessus server. "
                f"Available policies: {', '.join(available_names) or '(none)'}"
            )
        except Exception as e:
            logger.error(f"Failed to look up policy '{policy_name}': {e}")
        return None

    def _curl_nessus(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        _retried: bool = False,
    ) -> tuple[int, str]:
        """Make a Nessus API request via curl.

        Uses session token auth when available, falling back to API keys.
        Automatically re-authenticates once on HTTP 401 (expired session).

        Returns:
            Tuple of (http_status, response_body).
        """
        url = f"{self._nessus._url}/{path.lstrip('/')}"

        if self._session_token:
            auth_header = f"X-Cookie: token={self._session_token}"
        else:
            api_keys = self._nessus._session.headers.get("X-APIKeys", "")
            auth_header = f"X-APIKeys: {api_keys}"

        cmd = [
            "curl", "-sk",
            "-X", method, url,
            "-H", auth_header,
            "-H", "Content-Type: application/json",
            "-w", "\n%{http_code}",
        ]
        if self._api_token:
            cmd.extend(["-H", f"X-Api-Token: {self._api_token}"])
        if payload is not None:
            cmd.extend(["-d", _json.dumps(payload)])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception as e:
            logger.error(f"{method} {path} curl failed: {e}")
            return 0, ""

        parts = proc.stdout.rsplit("\n", 1)
        body = parts[0] if len(parts) > 1 else proc.stdout
        try:
            status = int(parts[-1])
        except (ValueError, IndexError):
            status = 0

        # Auto-renew expired session token on 401
        if status == 401 and self._session_token and not _retried:
            logger.warning("Session token expired (HTTP 401), re-authenticating...")
            self._obtain_session_token()
            if self._session_token:
                logger.info("Session renewed, retrying request")
                return self._curl_nessus(method, path, payload, _retried=True)

        return status, body

    def _post_scan(self, payload: dict) -> dict | None:
        """POST /scans via curl to reliably capture error responses.

        Args:
            payload: JSON body for POST /scans

        Returns:
            The ``scan`` dict from the response, or None on failure.
        """
        status, body = self._curl_nessus("POST", "/scans", payload)

        if status != 200:
            logger.error(f"POST /scans → HTTP {status}: {body}")
            return None

        try:
            return _json.loads(body)["scan"]
        except Exception as e:
            logger.error(f"POST /scans unexpected response: {body[:200]} ({e})")
            return None

    def create_scan(
        self,
        network_id: str,
        targets: list[str],
        policy: str | None = None,
    ) -> int | None:
        """Create a new Nessus scan.

        Args:
            network_id: Network identifier for naming
            targets: List of target IPs/hostnames
            policy: Policy name (optional)

        Returns:
            Scan ID, or None if creation failed
        """
        if not self._nessus:
            if not self.connect():
                return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_name = f"{network_id}_{timestamp}"

        try:
            # Resolve policy name to ID and template UUID
            policy_name = policy or self.config.policy_mapping.default
            result = self._resolve_policy(policy_name)
            if not result:
                logger.error(f"Policy not found or missing template UUID: {policy_name}")
                return None

            policy_id, template_uuid = result

            settings = {
                "name": scan_name,
                "text_targets": ",".join(targets),
                "policy_id": str(policy_id),
                "scanner_id": "1",
                "folder_id": 3,
                "launch_now": True,
            }

            # Attempt 1: uuid + settings (standard Nessus API format)
            payload = {"uuid": template_uuid, "settings": settings}
            logger.debug(f"Scan creation payload: {payload}")

            scan_data = self._post_scan(payload)

            # Attempt 2: settings only (some Nessus versions reject uuid
            # when policy_id is present)
            if scan_data is None:
                logger.info("Retrying scan creation without template UUID")
                scan_data = self._post_scan({"settings": settings})

            if scan_data is None:
                logger.error("All scan creation attempts failed")
                return None

            self._scan_id = scan_data["id"]
            self._launched = True  # launch_now: True already started it
            logger.info(f"Created Nessus scan: {scan_name} (ID: {self._scan_id})")
            return self._scan_id

        except Exception as e:
            logger.error(f"Failed to create Nessus scan: {e}")
            return None
    
    def launch_scan(self, scan_id: int | None = None) -> bool:
        """Launch a Nessus scan.

        Args:
            scan_id: Scan ID to launch (uses last created if not provided)

        Returns:
            True if launch successful
        """
        target_id = scan_id or self._scan_id
        if not target_id:
            logger.error("No scan ID provided or available")
            return False

        # create_scan() uses launch_now: True, so the scan is already running
        if self._launched:
            logger.info(f"Scan {target_id} already launched at creation time")
            if self.progress_callback:
                self.progress_callback(str(target_id), ScanStatus.RUNNING, 0, [])
            return True

        if not self._nessus:
            if not self.connect():
                return False

        status, body = self._curl_nessus("POST", f"/scans/{target_id}/launch")

        if status != 200:
            logger.error(f"Failed to launch scan {target_id}: HTTP {status}: {body}")
            return False

        logger.info(f"Launched Nessus scan ID: {target_id}")

        if self.progress_callback:
            self.progress_callback(str(target_id), ScanStatus.RUNNING, 0, [])

        return True
    
    @staticmethod
    def _host_progress_pct(host: dict) -> int:
        """Return 0-100 scan progress for a single host entry.

        The Nessus API (GET /scans/{id}) provides per-host progress as
        integer fields ``scanprogresscurrent`` and ``scanprogresstotal``
        (e.g. 45/100 = 45 %).  The ``progress`` string is a compound
        format like ``"45-100/51382-114139"`` that is harder to parse
        and redundant with the integer fields.
        """
        current = host.get("scanprogresscurrent")
        total = host.get("scanprogresstotal")
        if current is not None and total is not None:
            try:
                c, t = int(current), int(total)
                if t > 0:
                    return min(int(c * 100 / t), 100)
            except (ValueError, TypeError):
                pass
        return 0

    def get_scan_status(self, scan_id: int | str | None = None) -> dict:
        """Get the status of a Nessus scan via curl.

        Uses ``_curl_nessus`` so that session-auth (X-Cookie) works on
        Nessus Pro 10.x where the pyTenable API-key path is blocked.

        Progress is computed from per-host ``scanprogresscurrent`` /
        ``scanprogresstotal`` fields (averages across all hosts).

        Args:
            scan_id: Scan ID to check

        Returns:
            Dict with status information
        """
        target_id = int(scan_id) if scan_id else self._scan_id
        if not target_id:
            return {"error": "No scan ID"}

        if not self._nessus:
            if not self.connect():
                return {"error": "Not connected"}

        http_status, body = self._curl_nessus("GET", f"/scans/{target_id}")

        if http_status != 200:
            logger.error(f"GET /scans/{target_id} → HTTP {http_status}: {body[:200]}")
            return {"error": f"HTTP {http_status}"}

        try:
            details = _json.loads(body)
        except Exception as e:
            logger.error(f"Failed to parse scan details: {e}")
            return {"error": str(e)}

        info = details.get("info", {})
        scan_status = info.get("status", "unknown")
        hosts_list = details.get("hosts", [])

        # Definitive: Nessus says completed → 100 %
        if scan_status == "completed":
            progress = 100
        elif hosts_list:
            # Average per-host progress (scanprogresscurrent / scanprogresstotal)
            total_pct = sum(self._host_progress_pct(h) for h in hosts_list)
            progress = int(total_pct / len(hosts_list))
            logger.debug(
                f"Scan {target_id}: per-host progress "
                f"{[self._host_progress_pct(h) for h in hosts_list]} "
                f"→ avg {progress}%"
            )
        else:
            progress = 0

        # Per-host progress for dashboard updates
        host_progress = []
        for h in hosts_list:
            hostname = h.get("hostname") or h.get("host_ip", "")
            pct = self._host_progress_pct(h)
            host_progress.append({"hostname": hostname, "progress": pct})

        return {
            "id": target_id,
            "name": info.get("name", "Unknown"),
            "status": scan_status,
            "progress": progress,
            "host_count": info.get("hostcount", 0),
            "host_progress": host_progress,
        }
    
    def poll_until_complete(
        self,
        scan_id: int | None = None,
        poll_interval: int = 30,
        max_errors: int = 5,
    ) -> bool:
        """Poll scan status until completion.

        Transient API errors are retried up to *max_errors* consecutive
        times before giving up.

        Args:
            scan_id: Scan ID to poll
            poll_interval: Seconds between polls
            max_errors: Consecutive error limit before aborting

        Returns:
            True if scan completed successfully
        """
        import time

        target_id = scan_id or self._scan_id
        if not target_id:
            return False

        consecutive_errors = 0

        while True:
            status = self.get_scan_status(target_id)

            if "error" in status:
                consecutive_errors += 1
                logger.warning(
                    f"Poll error ({consecutive_errors}/{max_errors}): "
                    f"{status['error']}"
                )
                if consecutive_errors >= max_errors:
                    logger.error("Too many consecutive poll errors, aborting")
                    return False
                time.sleep(poll_interval)
                continue

            consecutive_errors = 0  # reset on success
            
            scan_status = status.get("status", "unknown")
            progress = status.get("progress", 0)
            
            logger.debug(f"Scan {target_id}: {scan_status} ({progress}%)")
            
            if self.progress_callback:
                host_progress = status.get("host_progress", [])
                if scan_status == "completed":
                    self.progress_callback(str(target_id), ScanStatus.COMPLETED, 100, host_progress)
                elif scan_status in ("canceled", "aborted"):
                    self.progress_callback(str(target_id), ScanStatus.FAILED, progress, host_progress)
                else:
                    self.progress_callback(str(target_id), ScanStatus.RUNNING, progress, host_progress)
            
            if scan_status == "completed":
                logger.info(f"Nessus scan {target_id} completed")
                return True
            elif scan_status in ("canceled", "aborted", "stopped"):
                logger.warning(f"Nessus scan {target_id} {scan_status}")
                return False
            
            time.sleep(poll_interval)
    
    def find_running_scan(self, network_id: str) -> dict | None:
        """Find an active Nessus scan matching the given network ID.

        Checks recent scans for one whose name starts with
        ``{network_id}_`` and whose status indicates it is still running.
        This is the same data ``enso status`` shows.

        Args:
            network_id: Network identifier prefix (e.g. ``"internal"``)

        Returns:
            Dict with ``id``, ``name``, ``status``, ``progress`` keys,
            or None if no active scan matches.
        """
        prefix = f"{network_id}_"
        active_statuses = {"running", "paused", "resuming"}

        for scan in self.list_recent_scans(limit=20):
            name = scan.get("name", "")
            status = scan.get("status", "")
            if name.startswith(prefix) and status in active_statuses:
                logger.info(
                    f"Found active Nessus scan: {name} "
                    f"(id={scan['id']}, status={status})"
                )
                return scan

        return None

    def list_recent_scans(self, limit: int = 10) -> list[dict]:
        """List recent Nessus scans.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan info dictionaries
        """
        if not self._nessus:
            if not self.connect():
                return []
        
        try:
            scans = self._nessus.scans.list()
            
            result = []
            for scan in scans.get("scans", [])[:limit]:
                result.append({
                    "id": scan.get("id"),
                    "name": scan.get("name"),
                    "status": scan.get("status"),
                    "progress": scan.get("progress", 0),
                })
            
            return result
        except Exception as e:
            logger.error(f"Failed to list scans: {e}")
            return []
    
    def _curl_nessus_download(self, path: str, output_path: Path) -> bool:
        """Download a binary file from the Nessus API via curl.

        Uses the same auth headers as ``_curl_nessus()`` but writes
        directly to disk with ``-o`` instead of capturing text output.

        Args:
            path: API path (e.g. ``/tokens/{token}/download``)
            output_path: Local file path to write

        Returns:
            True if the file was downloaded successfully
        """
        url = f"{self._nessus._url}/{path.lstrip('/')}"

        if self._session_token:
            auth_header = f"X-Cookie: token={self._session_token}"
        else:
            api_keys = self._nessus._session.headers.get("X-APIKeys", "")
            auth_header = f"X-APIKeys: {api_keys}"

        cmd = [
            "curl", "-sk",
            "-o", str(output_path),
            "-w", "%{http_code}",
            "-H", auth_header,
        ]
        if self._api_token:
            cmd.extend(["-H", f"X-Api-Token: {self._api_token}"])
        cmd.append(url)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except Exception as e:
            logger.error(f"Download {path} failed: {e}")
            return False

        try:
            status = int(proc.stdout.strip())
        except (ValueError, IndexError):
            status = 0

        if status != 200 or not output_path.exists():
            logger.error(f"Download {path} → HTTP {status}")
            return False

        return True

    def export_scan(
        self,
        scan_id: int,
        output_dir: Path,
        format: str = "nessus",
        scan_name: str | None = None,
    ) -> Path | None:
        """Export a Nessus scan to a file using the token-based export API.

        Flow:
        1. ``POST /scans/{id}/export`` → receive export token
        2. ``GET /tokens/{token}/status`` → poll until ready
        3. ``GET /tokens/{token}/download`` → binary download

        Args:
            scan_id: Nessus scan ID to export
            output_dir: Directory to save the exported file
            format: Export format (``"nessus"``, ``"csv"``, ``"html"``, ``"pdf"``)
            scan_name: Scan name for fallback filename (uses scan_{id} if None)

        Returns:
            Path to the downloaded file, or None on failure
        """
        import re
        import time

        if not self._nessus:
            if not self.connect():
                return None

        # Step 1: Request export
        logger.info(f"Requesting export for scan {scan_id} (format={format})")
        http_status, body = self._curl_nessus(
            "POST", f"/scans/{scan_id}/export?limit=2500",
            payload={"format": format},
        )

        if http_status != 200:
            logger.error(f"Export request failed: HTTP {http_status}: {body[:200]}")
            return None

        try:
            data = _json.loads(body)
            token = data["token"]
        except Exception as e:
            logger.error(f"Export request unexpected response: {body[:200]} ({e})")
            return None

        logger.info(f"Export token received: {token[:16]}...")

        # Step 2: Poll until ready
        max_polls = 60
        for attempt in range(max_polls):
            http_status, body = self._curl_nessus("GET", f"/tokens/{token}/status")

            if http_status != 200:
                logger.warning(
                    f"Export status poll {attempt + 1}/{max_polls}: "
                    f"HTTP {http_status}"
                )
                time.sleep(2)
                continue

            try:
                status_data = _json.loads(body)
            except Exception:
                time.sleep(2)
                continue

            if status_data.get("status") == "ready":
                logger.info("Export ready for download")
                break

            error = status_data.get("error")
            if error:
                logger.error(f"Export failed: {error}")
                return None

            time.sleep(2)
        else:
            logger.error(f"Export timed out after {max_polls * 2}s")
            return None

        # Step 3: Download file
        # Try to get filename from a HEAD request first
        if scan_name:
            safe_name = re.sub(r'[^\w\-.]', '_', scan_name)
            filename = f"{safe_name}.{format}"
        else:
            filename = f"scan_{scan_id}.{format}"

        # Use curl with -D to capture headers and extract Content-Disposition
        download_url = f"{self._nessus._url}/tokens/{token}/download"
        if self._session_token:
            auth_header = f"X-Cookie: token={self._session_token}"
        else:
            api_keys = self._nessus._session.headers.get("X-APIKeys", "")
            auth_header = f"X-APIKeys: {api_keys}"

        header_cmd = [
            "curl", "-sk", "-I",
            "-H", auth_header,
            download_url,
        ]
        if self._api_token:
            header_cmd.extend(["-H", f"X-Api-Token: {self._api_token}"])

        try:
            proc = subprocess.run(
                header_cmd, capture_output=True, text=True, timeout=15
            )
            cd_match = re.search(
                r'Content-Disposition:.*filename="?([^"\r\n]+)"?',
                proc.stdout,
                re.IGNORECASE,
            )
            if cd_match:
                filename = cd_match.group(1).strip()
        except Exception:
            pass  # Fall back to default filename

        output_path = output_dir / filename
        logger.info(f"Downloading export to {output_path}")

        if not self._curl_nessus_download(f"/tokens/{token}/download", output_path):
            return None

        size_kb = output_path.stat().st_size / 1024
        logger.info(f"Export saved: {output_path} ({size_kb:.1f} KB)")
        return output_path
