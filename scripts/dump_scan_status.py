#!/usr/bin/env python3
"""Diagnostic: dump raw Nessus scan status for a given scan ID.

Usage:
    python3 scripts/dump_scan_status.py [SCAN_ID]
    python3 scripts/dump_scan_status.py          # lists recent scans
"""

import json
import subprocess
import sys
from pathlib import Path

from enso.config import load_config


def curl_nessus(base_url: str, auth_header: str, path: str) -> dict | None:
    """GET a Nessus endpoint and return parsed JSON."""
    proc = subprocess.run(
        ["curl", "-sk", "-X", "GET", f"{base_url}/{path.lstrip('/')}",
         "-H", auth_header,
         "-H", "Content-Type: application/json"],
        capture_output=True, text=True, timeout=30,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Could not parse response for {path}:\n{proc.stdout[:500]}")
        return None


def main():
    config = load_config(Path(__file__).resolve().parent.parent / "configs")
    nessus_cfg = config.nessus

    access_key = nessus_cfg.access_key or ""
    secret_key = nessus_cfg.secret_key or ""
    if not access_key or not secret_key:
        print("ERROR: No API keys found")
        sys.exit(1)

    base_url = nessus_cfg.url
    auth_header = f"X-APIKeys: accessKey={access_key}; secretKey={secret_key}"

    # Also try session auth — scan details may require it on Pro 10.x
    # First get CSRF token
    print("=== Obtaining session auth (for scan_api:false instances) ===")

    nessus_ui = getattr(config.credentials, "nessus_ui", None)
    session_token = None
    api_token = None

    # Get CSRF token from nessus6.js
    import re
    try:
        proc = subprocess.run(
            ["curl", "-sk", f"{base_url}/nessus6.js"],
            capture_output=True, text=True, timeout=30,
        )
        match = re.search(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            proc.stdout,
        )
        if match:
            api_token = match.group(0)
            print(f"CSRF token: {api_token[:8]}...")
    except Exception as e:
        print(f"Could not get CSRF token: {e}")

    # Get session token
    if nessus_ui and not nessus_ui.needs_runtime_prompt():
        cmd = [
            "curl", "-sk", "-X", "POST", f"{base_url}/session",
            "-H", "Content-Type: application/json",
        ]
        if api_token:
            cmd.extend(["-H", f"X-Api-Token: {api_token}"])
        cmd.extend(["-d", json.dumps({
            "username": nessus_ui.username,
            "password": nessus_ui.password,
        })])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            data = json.loads(proc.stdout)
            session_token = data.get("token")
            if session_token:
                print(f"Session token: {session_token[:8]}...")
            else:
                print(f"Session auth failed: {proc.stdout[:200]}")
        except Exception as e:
            print(f"Session auth error: {e}")
    else:
        print("No nessus_ui credentials configured — using API keys only")

    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else None

    if scan_id is None:
        # List recent scans
        print(f"\n=== Listing scans from {base_url} (API keys) ===")
        data = curl_nessus(base_url, auth_header, "/scans")
        if data:
            scans = data.get("scans", [])
            print(f"Found {len(scans)} scan(s):")
            for s in scans[:15]:
                print(f"  id={s.get('id')}  status={s.get('status'):<12}  name={s.get('name')}")
        print("\nRe-run with scan ID: python3 scripts/dump_scan_status.py <ID>")
        return

    # Fetch scan details with BOTH auth methods
    for auth_name, hdr, extra_headers in [
        ("API keys", auth_header, []),
        ("Session", f"X-Cookie: token={session_token}" if session_token else None,
         [f"X-Api-Token: {api_token}"] if api_token else []),
    ]:
        if hdr is None:
            print(f"\n=== GET /scans/{scan_id} ({auth_name}) — SKIPPED (no token) ===")
            continue

        print(f"\n=== GET /scans/{scan_id} ({auth_name}) ===")
        cmd = [
            "curl", "-sk", "-X", "GET", f"{base_url}/scans/{scan_id}",
            "-H", hdr,
            "-H", "Content-Type: application/json",
            "-w", "\n%{http_code}",
        ]
        for eh in extra_headers:
            cmd.extend(["-H", eh])

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        parts = proc.stdout.rsplit("\n", 1)
        body = parts[0] if len(parts) > 1 else proc.stdout
        try:
            http_status = int(parts[-1])
        except (ValueError, IndexError):
            http_status = 0

        print(f"HTTP status: {http_status}")

        if http_status != 200:
            print(f"Response: {body[:500]}")
            continue

        try:
            details = json.loads(body)
        except json.JSONDecodeError:
            print(f"JSON parse error: {body[:500]}")
            continue

        # --- info block ---
        info = details.get("info", {})
        print(f"\ninfo keys: {list(info.keys())}")
        print(f"  status: {info.get('status')}")
        print(f"  name: {info.get('name')}")
        print(f"  hostcount: {info.get('hostcount')}")

        # Print ALL percentage/progress fields
        for key in sorted(info.keys()):
            val = info[key]
            if "progress" in key.lower() or "percent" in key.lower() or "complete" in key.lower():
                print(f"  {key}: {val!r}")

        # --- hosts block ---
        hosts = details.get("hosts", [])
        print(f"\nhosts: {len(hosts)} entries")
        if hosts:
            print(f"  Host entry keys: {list(hosts[0].keys())}")
            for i, h in enumerate(hosts):
                # Redact nothing — this is scan metadata, not secrets
                safe_fields = {
                    "host_id": h.get("host_id"),
                    "hostname": h.get("hostname") or h.get("host_ip"),
                    "progress": h.get("progress"),
                    "status": h.get("status"),
                    "score": h.get("score"),
                    "severity_count": h.get("severity_count"),
                    "totalchecksconsidered": h.get("totalchecksconsidered"),
                    "numchecksconsidered": h.get("numchecksconsidered"),
                    "scanprogresscurrent": h.get("scanprogresscurrent"),
                    "scanprogresstotal": h.get("scanprogresstotal"),
                }
                # Remove None values for cleaner output
                safe_fields = {k: v for k, v in safe_fields.items() if v is not None}
                print(f"  [{i}] {safe_fields}")

        # --- top-level keys ---
        print(f"\nTop-level keys: {list(details.keys())}")

        # Check for other progress-related fields at top level
        for key in details:
            if key in ("info", "hosts", "plugins", "vulnerabilities",
                       "compliance", "history", "notes", "remediations",
                       "filters"):
                continue
            print(f"  {key}: {str(details[key])[:200]}")


if __name__ == "__main__":
    main()
