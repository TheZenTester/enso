"""Nessus policy management — credential sync between YAML and policies.

Uses curl for reading policy details (raw API response) because pyTenable
transforms the response and strips credential IDs.  pyTenable is still used
for ``policies.list()`` (name → ID lookup) and as a fallback for edits.
"""

from __future__ import annotations

import json as _json
import subprocess
from dataclasses import dataclass
from typing import Any

from .config import NessusConfig, CredentialsConfig
from .ui.prompts import Prompts
from .utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PolicyCredential:
    """Represents a credential stored in a Nessus policy."""

    credential_type: str  # "windows" or "ssh"
    username: str
    domain: str | None = None

    def matches(self, other: "PolicyCredential") -> bool:
        """Check if this credential matches another."""
        return (
            self.credential_type == other.credential_type
            and self.username == other.username
            and self.domain == other.domain
        )


class NessusPolicyManager:
    """Manage Nessus policy credentials via pyTenable API."""

    def __init__(self, config: NessusConfig):
        self.config = config
        self._nessus = None
        self._resolved_keys: tuple[str, str] | None = None

    def _ensure_credentials(self) -> tuple[str, str]:
        """Ensure API credentials are available, prompting if needed."""
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
        self._resolved_keys = (access_key, secret_key)

        try:
            self._nessus = Nessus(
                url=self.config.url,
                access_key=access_key,
                secret_key=secret_key,
            )
            # Test connection
            self._nessus.server.status()
            logger.info(f"Connected to Nessus at {self.config.url}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Nessus: {e}")
            return False

    def _ensure_connected(self) -> bool:
        """Ensure we have an active pyTenable connection."""
        if self._nessus is not None:
            return True
        return self.connect()

    def _curl_nessus(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> tuple[int, str]:
        """Make a Nessus API request via curl with API-key auth.

        Bypasses pyTenable so we get the raw, untransformed response —
        critical for reading credential IDs that pyTenable may omit.

        Returns:
            Tuple of (http_status, response_body).
        """
        if not self._resolved_keys:
            logger.error("No API keys resolved — call connect() first")
            return 0, ""

        access_key, secret_key = self._resolved_keys
        url = f"{self.config.url}/{path.lstrip('/')}"

        cmd = [
            "curl", "-sk",
            "-X", method, url,
            "-H", f"X-APIKeys: accessKey={access_key}; secretKey={secret_key}",
            "-H", "Content-Type: application/json",
            "-w", "\n%{http_code}",
        ]
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

        return status, body

    def get_policy_by_name(self, policy_name: str) -> tuple[int, dict] | None:
        """Get a policy by name.

        Uses pyTenable for the policy list (name → ID), then fetches the
        full details via curl to get the raw credential structure.

        Args:
            policy_name: Name of the policy

        Returns:
            Tuple of (policy_id, policy_details) or None if not found
        """
        if not self._ensure_connected():
            return None

        try:
            policies = self._nessus.policies.list()
            for p in policies:
                if p["name"] == policy_name:
                    policy_id = p["id"]

                    # Prefer raw curl response — pyTenable transforms
                    # the JSON and can strip credential IDs
                    http_status, body = self._curl_nessus(
                        "GET", f"/policies/{policy_id}"
                    )
                    if http_status == 200:
                        try:
                            details = _json.loads(body)
                            logger.debug(
                                f"Raw policy top-level keys: "
                                f"{list(details.keys())}"
                            )
                            return policy_id, details
                        except Exception as e:
                            logger.warning(
                                f"Failed to parse curl policy response: {e}"
                            )

                    # Fall back to pyTenable if curl failed
                    logger.debug(
                        "Falling back to pyTenable for policy details"
                    )
                    details = self._nessus.policies.details(policy_id)
                    return policy_id, details
        except Exception as e:
            logger.error(f"Failed to list policies: {e}")
            return None

        logger.warning(f"Policy not found: {policy_name}")
        return None

    def get_policy_credentials(self, policy_name: str) -> list[PolicyCredential]:
        """Get credentials configured in a policy.

        Args:
            policy_name: Name of the policy

        Returns:
            List of credentials in the policy
        """
        result = self.get_policy_by_name(policy_name)
        if not result:
            return []

        _policy_id, details = result
        return self._parse_credentials(details)

    @staticmethod
    def _get_edit_creds(details: dict) -> dict[str, dict]:
        """Extract the ``credentials.edit`` dict from raw policy details.

        The Nessus API (GET /policies/{id}) returns credentials as::

            {"credentials": {"edit": {"48": {...}, "24": {...}}}}

        where each key is the credential ID and the value contains
        ``username``, ``auth_method``, ``domain``, etc.

        Returns:
            Dict mapping credential-ID strings to credential dicts,
            or ``{}`` if the structure is not found.
        """
        creds_root = details.get("credentials", {})
        if not isinstance(creds_root, dict):
            return {}

        edit_creds = creds_root.get("edit", {})
        if isinstance(edit_creds, dict) and edit_creds:
            logger.debug(
                f"Found {len(edit_creds)} credential(s) in "
                f"credentials.edit: IDs={list(edit_creds.keys())}"
            )
            return edit_creds

        logger.debug(
            f"No credentials.edit found — "
            f"credentials keys: {list(creds_root.keys())}"
        )
        return {}

    @staticmethod
    def _parse_credentials(details: dict) -> list[PolicyCredential]:
        """Extract PolicyCredential objects from raw policy details.

        Determines credential type from ``auth_method``:
        - ``"Password"`` (capital P) → Windows
        - ``"password"`` (lowercase) → SSH
        """
        credentials = []
        edit_creds = NessusPolicyManager._get_edit_creds(details)

        for _cred_id, cred in edit_creds.items():
            if not isinstance(cred, dict):
                continue
            auth = cred.get("auth_method", "")
            username = cred.get("username", "")

            if auth == "Password":
                credentials.append(PolicyCredential(
                    credential_type="windows",
                    username=username,
                    domain=cred.get("domain"),
                ))
            elif auth == "password":
                credentials.append(PolicyCredential(
                    credential_type="ssh",
                    username=username,
                ))
            else:
                logger.debug(
                    f"Skipping credential {_cred_id}: "
                    f"unknown auth_method={auth!r}"
                )

        return credentials

    def get_policy_credential_ids(self, policy_name: str) -> list[int]:
        """Get the numeric IDs of all credentials in a policy.

        In the raw Nessus API response, credential IDs are the **keys**
        of the ``credentials.edit`` dict (e.g. ``"48"``, ``"24"``).

        Args:
            policy_name: Name of the policy

        Returns:
            List of credential IDs (ints)
        """
        result = self.get_policy_by_name(policy_name)
        if not result:
            return []

        _policy_id, details = result
        edit_creds = self._get_edit_creds(details)

        ids: list[int] = []
        for key in edit_creds:
            try:
                ids.append(int(key))
            except (ValueError, TypeError):
                logger.warning(f"Non-numeric credential ID: {key!r}")

        return ids

    def credentials_match(
        self,
        policy_name: str,
        local_credentials: CredentialsConfig,
    ) -> bool:
        """Check if policy credentials match local credentials.yaml.

        Args:
            policy_name: Name of the policy to check
            local_credentials: Local credentials from config

        Returns:
            True if credentials match
        """
        policy_creds = self.get_policy_credentials(policy_name)

        # Build list of expected credentials from local config
        expected_creds = []

        for name, win_cred in local_credentials.windows.items():
            if not win_cred.enabled:
                continue
            expected_creds.append(PolicyCredential(
                credential_type="windows",
                username=win_cred.username,
                domain=win_cred.domain,
            ))

        for name, linux_cred in local_credentials.linux.items():
            if not linux_cred.enabled:
                continue
            expected_creds.append(PolicyCredential(
                credential_type="ssh",
                username=linux_cred.username,
            ))

        # Check if all expected credentials are in policy
        if len(policy_creds) != len(expected_creds):
            return False

        for expected in expected_creds:
            if not any(expected.matches(pc) for pc in policy_creds):
                return False

        return True

    def _build_credentials_payload(self, credentials: CredentialsConfig) -> dict:
        """Build the Nessus API credentials payload.

        Produces the correct nested structure:
        {"add": {"Host": {"Windows": [...], "SSH": [...]}}}

        Args:
            credentials: Local credentials config

        Returns:
            Credentials payload dict for the Nessus API
        """
        windows_list = []
        ssh_list = []

        for name, win in credentials.windows.items():
            if not win.enabled:
                continue
            password = win.password
            if win.needs_runtime_prompt():
                password = Prompts.prompt_secret(
                    f"Windows password for {name}",
                    "WINDOWS_ADMIN_PASSWORD",
                )
            windows_list.append({
                "auth_method": "Password",
                "username": win.username,
                "domain": win.domain or "",
                "password": password,
            })

        for name, lnx in credentials.linux.items():
            if not lnx.enabled:
                continue
            password = lnx.password
            if lnx.needs_runtime_prompt():
                password = Prompts.prompt_secret(
                    f"SSH password for {name}",
                    "SSH_PASSWORD",
                )
            entry = {
                "auth_method": "password",
                "username": lnx.username,
                "password": password,
            }
            escalation = lnx.privilege_escalation
            if escalation and escalation != "none":
                entry["elevate_privileges_with"] = escalation
            else:
                entry["elevate_privileges_with"] = "Nothing"
            ssh_list.append(entry)

        host: dict[str, list] = {}
        if windows_list:
            host["Windows"] = windows_list
        if ssh_list:
            host["SSH"] = ssh_list

        return {"add": {"Host": host}}

    def update_policy_credentials(
        self,
        policy_name: str,
        credentials: CredentialsConfig,
        delete_ids: list[int] | None = None,
    ) -> bool:
        """Update credentials in a Nessus policy.

        Tries pyTenable first, then falls back to curl PUT if that fails.

        Args:
            policy_name: Name of the policy to update
            credentials: Credentials to set
            delete_ids: Optional list of existing credential IDs to remove
                        before adding new ones

        Returns:
            True if update successful
        """
        result = self.get_policy_by_name(policy_name)
        if not result:
            return False

        policy_id, _details = result

        try:
            creds_payload = self._build_credentials_payload(credentials)

            if delete_ids:
                creds_payload["delete"] = delete_ids
                logger.info(
                    f"Removing {len(delete_ids)} existing credential(s) "
                    f"from policy before adding new ones"
                )

            logger.debug(f"Credentials payload: {list(creds_payload.keys())}")

            # Try pyTenable first
            try:
                self._nessus.policies.edit(
                    policy_id,
                    credentials=creds_payload,
                )
                logger.info(f"Updated credentials in policy: {policy_name}")
                return True
            except Exception as e:
                logger.warning(
                    f"pyTenable policy edit failed ({e}), trying curl"
                )

            # Curl fallback — PUT with credentials payload
            http_status, body = self._curl_nessus(
                "PUT",
                f"/policies/{policy_id}",
                {"credentials": creds_payload},
            )
            if http_status == 200:
                logger.info(
                    f"Updated credentials in policy via curl: {policy_name}"
                )
                return True

            logger.error(
                f"PUT /policies/{policy_id} → HTTP {http_status}: "
                f"{body[:200]}"
            )
            return False

        except Exception as e:
            logger.error(f"Failed to update policy credentials: {e}")
            return False

    def get_credential_summary(self, policy_name: str) -> dict:
        """Get a summary of credentials in a policy.

        Args:
            policy_name: Name of the policy

        Returns:
            Dict with credential counts and usernames
        """
        creds = self.get_policy_credentials(policy_name)

        windows = [c for c in creds if c.credential_type == "windows"]
        ssh = [c for c in creds if c.credential_type == "ssh"]

        return {
            "windows_count": len(windows),
            "windows_users": [c.username for c in windows],
            "ssh_count": len(ssh),
            "ssh_users": [c.username for c in ssh],
        }
