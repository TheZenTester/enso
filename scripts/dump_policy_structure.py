#!/usr/bin/env python3
"""Diagnostic: dump the raw Nessus policy credential structure.

Curls GET /policies/{id} and prints the credential JSON tree so we
can see exactly where IDs and usernames live.

Usage:
    python3 scripts/dump_policy_structure.py
"""

import json
import subprocess
import sys

from pathlib import Path
from enso.config import load_config

def main():
    config = load_config(Path(__file__).resolve().parent.parent / "configs")
    nessus_cfg = config.nessus
    policy_name = nessus_cfg.policy_mapping.default

    # Resolve API keys
    access_key = nessus_cfg.access_key or ""
    secret_key = nessus_cfg.secret_key or ""

    if not access_key or not secret_key:
        print("ERROR: No API keys found in config/keyfile. Set them first.")
        sys.exit(1)

    base_url = nessus_cfg.url
    auth_header = f"X-APIKeys: accessKey={access_key}; secretKey={secret_key}"

    # Step 1: List policies to find the ID
    print(f"=== Listing policies from {base_url} ===")
    proc = subprocess.run(
        ["curl", "-sk", "-X", "GET", f"{base_url}/policies",
         "-H", auth_header,
         "-H", "Content-Type: application/json"],
        capture_output=True, text=True, timeout=30,
    )
    try:
        policies_resp = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Could not parse policy list response:\n{proc.stdout[:500]}")
        sys.exit(1)

    policy_list = policies_resp.get("policies", [])
    print(f"Found {len(policy_list)} policies:")
    target_id = None
    for p in policy_list:
        marker = " <-- TARGET" if p.get("name") == policy_name else ""
        print(f"  id={p.get('id')}  name={p.get('name')}{marker}")
        if p.get("name") == policy_name:
            target_id = p["id"]

    if target_id is None:
        print(f"\nERROR: Policy '{policy_name}' not found")
        sys.exit(1)

    # Step 2: GET /policies/{id} — raw response
    print(f"\n=== GET /policies/{target_id} (raw) ===")
    proc = subprocess.run(
        ["curl", "-sk", "-X", "GET", f"{base_url}/policies/{target_id}",
         "-H", auth_header,
         "-H", "Content-Type: application/json"],
        capture_output=True, text=True, timeout=30,
    )
    try:
        details = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Could not parse policy details:\n{proc.stdout[:1000]}")
        sys.exit(1)

    # Step 3: Print the credential structure
    print(f"\nTop-level keys: {list(details.keys())}")

    creds = details.get("credentials")
    if creds is None:
        print("\n'credentials' key is MISSING from response!")
        print("\nFull response (first 3000 chars):")
        print(json.dumps(details, indent=2)[:3000])
        sys.exit(0)

    print(f"\ncredentials type: {type(creds).__name__}")

    if isinstance(creds, dict):
        print(f"credentials keys: {list(creds.keys())}")

        # Walk one level deeper for each key
        for key, val in creds.items():
            if isinstance(val, dict):
                print(f"\n  credentials.{key} keys: {list(val.keys())}")
                for k2, v2 in val.items():
                    if isinstance(v2, dict):
                        print(f"    credentials.{key}.{k2} keys: {list(v2.keys())}")
                        for k3, v3 in v2.items():
                            if isinstance(v3, list):
                                print(f"      credentials.{key}.{k2}.{k3}: list of {len(v3)} items")
                                for i, item in enumerate(v3[:3]):  # first 3
                                    if isinstance(item, dict):
                                        # Redact passwords
                                        safe = {k: ("***" if "pass" in k.lower() else v)
                                                for k, v in item.items()}
                                        print(f"        [{i}] {safe}")
                            elif isinstance(v3, dict):
                                print(f"      credentials.{key}.{k2}.{k3}: dict keys={list(v3.keys())}")
                    elif isinstance(v2, list):
                        print(f"    credentials.{key}.{k2}: list of {len(v2)} items")
                        for i, item in enumerate(v2[:3]):
                            if isinstance(item, dict):
                                safe = {k: ("***" if "pass" in k.lower() else v)
                                        for k, v in item.items()}
                                print(f"      [{i}] {safe}")
            elif isinstance(val, list):
                print(f"\n  credentials.{key}: list of {len(val)} items")
    else:
        print(f"credentials value (not a dict!): {str(creds)[:500]}")

    # Also dump the full credentials block (passwords redacted)
    print("\n=== Full credentials block (passwords redacted) ===")
    def redact(obj):
        if isinstance(obj, dict):
            return {k: ("***" if "pass" in k.lower() else redact(v))
                    for k, v in obj.items()}
        elif isinstance(obj, list):
            return [redact(item) for item in obj]
        return obj

    print(json.dumps(redact(creds), indent=2))


if __name__ == "__main__":
    main()
