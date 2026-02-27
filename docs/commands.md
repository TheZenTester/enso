# CLI Reference

## Global Options

These options apply to all commands when placed before the subcommand.

| Option | Short | Default | Description |
|---|---|---|---|
| `--config-dir PATH` | `-c` | `./configs` | Configuration directory |
| `--verbose` | `-v` | off | Enable DEBUG logging |
| `--version` | `-V` | | Show version and exit |
| `--help` | `-h` | | Show help |

The `ENSO_CONFIG_DIR` environment variable can replace `--config-dir`.

Config directory search order: `./configs` -- `~/.config/enso/` -- `/etc/enso/`

---

## enso configure

Configure network interface for the engagement.

### Options

| Option | Default | Description |
|---|---|---|
| `--client-dir PATH` | `/client` | Client engagement directory |

### What It Does

1. **Power gate** -- confirms laptop is plugged into AC power
2. **Interface gate** -- confirms the configured interface has link
3. **Engagement context** -- detects simple/complex, loads scope files
4. **Network selection** -- for complex engagements, presents a picker with configured network drops plus Manual Entry and DHCP options
5. **Netplan configuration** -- applies static IP (or DHCP) via Netplan
6. **Gateway ping** -- pings the gateway with retry/reconfig/manual/exit on failure
7. **Random host ping** -- pings a sample of in-scope hosts to verify reachability
8. **DNS validation** -- optionally prompts for FQDNs and tests name resolution

### Examples

```
# Basic usage
enso configure

# Custom client directory
enso configure --client-dir /mnt/usb/client
```

---

## enso scan

Launch the scanning workflow.

### Options

| Option | Default | Description |
|---|---|---|
| `--client-dir PATH` | `/client` | Client engagement directory |
| `--network NAME` | (none) | Pre-select network drop by name (skips selection prompt) |
| `--dry-run` | off | Show plan without executing |
| `--top-ports N` | (none) | Scan only top N ports (overrides `nmap.yaml`) |
| `--skip-nessus` | off | Skip the Nessus scan module |
| `--skip-preflight` | off | Skip all pre-flight checks and confirmations |

### Workflow Steps

1. Optional network configuration prompt
2. Pre-flight gates: AC power check, interface link check
3. Build engagement context (scope files, output directories)
4. Load in-scope hosts
5. Pre-flight Nessus validation (connectivity, auth, scanner status, policy)
6. Nessus credential sync (compares policy credentials vs `credentials.yaml`)
7. Optional nxc credential test (prompt, default No)
8. Pipeline summary display
9. Confirmation prompt ("Proceed with scan?")
10. **Resume detection** -- checks for previous results (see [Scan Resume](#scan-resume))
11. Scan execution with real-time Rich dashboard

### Execution Strategies

**Linear** (`execution_strategy: linear` in `global.yaml`):

```
Discovery --> Quality Gate --> Deep Scan --> Nessus
```

**Concurrent** (`execution_strategy: concurrent`):

```
Discovery -----> Quality Gate --> Deep Scan
Nessus ------->  (runs in parallel with discovery)
```

In concurrent mode, Nessus starts immediately alongside discovery. Deep scan waits for discovery to finish. The quality gate runs between discovery and deep scan -- if more than `dead_host_threshold` (default 70%) of hosts appear offline, the pipeline pauses and prompts whether to continue.

### Dashboard

During execution, a Rich Live dashboard displays three progress sections:

- **Discovery** -- per-host status with discovered open ports
- **Deep Scan** -- per-host service enumeration progress
- **Nessus** -- overall scan progress and per-host completion

### Scan Resume

If a scan is interrupted (Ctrl+C, crash, network issue), restarting `enso scan` automatically detects previous results and prompts you to resume or start fresh.

**How it works:**

- Nmap writes per-host XML files to disk as each scan runs. A completed scan contains a `<runstats>` element; an interrupted one does not. ENSO uses this to determine which hosts finished and which need re-scanning.
- If a Nessus scan is still running on the server, ENSO reconnects to it and polls for completion instead of creating a new scan.
- The dashboard pre-populates with completed hosts so progress bars show the correct starting point (e.g. "15/20" from the start).

**Resume prompt scenarios:**

| Scenario | Prompt |
|----------|--------|
| Some hosts incomplete | "Resume remaining scans" or "Start fresh" |
| All hosts complete, no active Nessus | "All scans complete. Start fresh?" (default No) |
| No previous results on disk | No prompt -- normal scan starts immediately |

**Start fresh** deletes all previous Nmap discovery and deep scan files, then runs a full scan from scratch.

**Scope changes between runs** are handled automatically -- new hosts appear as pending, removed hosts are ignored (their files stay on disk but aren't loaded).

### Examples

```
# Standard scan
enso scan

# Quick scan of top 100 ports, no Nessus
enso scan --top-ports 100 --skip-nessus

# Pre-select network for scripted use
enso scan --network "Server Room" --skip-preflight

# Preview what would run
enso scan --dry-run
```

---

## enso status

Check Nessus scan status.

### Arguments

| Argument | Default | Description |
|---|---|---|
| `[SCAN_ID]` | (latest) | Specific Nessus scan ID |

Without a scan ID, lists the 5 most recent Nessus scans with their status and progress. With a scan ID, shows detailed status for that specific scan.

### Examples

```
# List recent scans
enso status

# Check specific scan
enso status 42
```

---

## enso nessus

Nessus-related commands.

### enso nessus setup

Store Nessus API keys securely.

Prompts for `access_key` and `secret_key`, then saves them to `~/.config/enso/nessus_keys` with 600 permissions. Keys persist across reboots and terminal sessions. Warns before overwriting existing keys.

API keys are generated in Nessus under Settings -- My Account -- API Keys.

```
enso nessus setup
```

### enso nessus clear

Remove stored Nessus API keys. Prompts for confirmation before deleting.

```
enso nessus clear
```

### enso nessus check

Run Nessus pre-flight validation. Checks:

- Server connectivity (HTTPS to configured URL)
- Authentication (API key or session auth)
- Scanner status (online/offline)
- Policy mapping (checks that the named policy exists)

Exits with code 1 if any check fails.

```
enso nessus check
```

### enso nessus sync-creds

Push credentials from `credentials.yaml` to the Nessus policy.

1. Displays a table of credentials to sync (type, name, username, domain/escalation)
2. Lets you select which credentials to push
3. Shows existing policy credentials if any
4. Offers to remove existing credentials before adding new ones
5. Updates the Nessus policy via API

```
enso nessus sync-creds
```

### enso nessus export

Export one or more Nessus scans to `.nessus` files.

### Arguments / Options

| Argument/Option | Default | Description |
|---|---|---|
| `[SCAN_IDS]` | (interactive) | Scan ID(s) to export, comma-separated. Lists recent scans if omitted. |
| `--client-dir PATH` | `/client` | Client engagement directory (determines output location) |

Exports scans in Nessus native XML format and saves them to `{output_dir}/scans/nessus/`. The filename uses the scan name (e.g., `internal_20260213_112204.nessus`), or the server-provided name if available via Content-Disposition.

If no scan IDs are provided, ENSO lists recent Nessus scans and prompts you to select one or more (comma-separated).

**Output directory routing**: When exporting multiple scans, ENSO automatically routes each `.nessus` file to the correct engagement output directory by matching the scan name prefix against configured network drops. For example, a scan named `server_room_20260213_112204` is saved to `{client_dir}/server_room/scans/nessus/`. If no matching network drop is found, the file is saved to the simple engagement output directory.

### Examples

```
# Export a single scan
enso nessus export 86

# Export multiple scans
enso nessus export 42,43,86

# Interactive scan selection
enso nessus export

# Custom client directory
enso nessus export 86 --client-dir /mnt/usb/client
```

### Typical Nessus Setup Flow

```
enso nessus setup         # Store API keys
enso nessus check         # Verify connectivity
enso nessus sync-creds    # Push credentials to policy
```

---

## enso creds

Credential management and validation commands.

### enso creds show

Display configured credentials with passwords masked.

Shows tables for Linux (SSH) and Windows (SMB) credentials. The password status column indicates:

- **Configured** -- password resolved from file or environment variable
- **Env: ${VAR}** -- will read from environment variable at runtime
- **Will prompt at runtime** -- no password source configured

```
enso creds show
```

### enso creds test

Validate credentials against in-scope hosts using nxc (NetExec).

### Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--scope FILE` | `-s` | (required) | Path to in-scope hosts file (one IP per line) |
| `--output DIR` | `-o` | `.` | Output directory for failure report |
| `--linux-only` | | off | Only test SSH credentials |
| `--windows-only` | | off | Only test SMB credentials |

Requires nxc (NetExec) to be installed. Tests each enabled credential against every host in the scope file, then displays a summary table with success/failure counts and rates. Writes a failure report listing hosts that failed authentication.

For Windows credentials, domain accounts use `-d DOMAIN` and local accounts (empty domain) use `--local-auth`.

### Examples

```
# Test SSH credentials against scope
enso creds test --scope /client/engagement_docs/inscope.txt --linux-only

# Test all credentials with report output
enso creds test -s inscope.txt -o /tmp/cred_reports

# Test only Windows credentials
enso creds test -s inscope.txt --windows-only
```

---

## enso export

Package scan results into a zip file for delivery.

### Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--export-dir PATH` | `-e` | (prompted) | Directory to save the zip file |
| `--client-dir PATH` | | `/client` | Client engagement directory |
| `--network NAME` | | (prompted) | Pre-select network (complex engagements) |
| `--full` | | off | Export all files (ignore previous export history) |
| `--skip-nessus` | | off | Skip Nessus export prompt |

### What It Does

1. Builds engagement context (prompts for network on complex engagements)
2. Checks for `.nessus` files -- offers to export from Nessus if none found
3. Collects scan files (nmap discovery/detailed/logs + nessus exports)
4. Filters to only new/changed files since last export (unless `--full`)
5. Prompts for export directory with tab completion (unless `--export-dir`)
6. Creates zip archive named `enso_export_{network}_{timestamp}.zip`

### Differential Export

ENSO tracks exported files in `.enso_exports.json` (stored in the scans/ directory). When you run `enso export` again, only new or modified files are included in the zip. This is particularly useful for complex engagements where you scan and export each network segment separately -- each network's export history is tracked independently.

Use `--full` to override differential behavior and include all files.

### Zip Contents

The zip mirrors the `scans/` directory structure. The exact directories depend on which modules are configured in `global.yaml`. With the default pipeline:

```
nmap/
  discovery/         # Per-host .xml, .gnmap, .nmap files
  detailed/          # Per-host deep scan results
  logs/              # Nmap stdout logs
nessus/
  *.nessus           # Exported Nessus scan files
cred_checks/         # nxc credential check reports (if run)
```

Custom modules added to the pipeline will also appear if their output directories contain files.

### Examples

```
# Interactive export (prompts for Nessus export and directory)
enso export

# Export to specific directory, skip Nessus prompt
enso export --export-dir ~/Downloads --skip-nessus

# Pre-select network for complex engagements
enso export --network "Server Room"

# Full re-export (ignore previous export history)
enso export --full --export-dir /mnt/usb/exports
```

---

## Credential Check During Scan

In addition to `enso creds test` (standalone), the `enso scan` workflow includes an optional credential check after Nessus credential sync. When prompted with "Test credentials against in-scope hosts with nxc?", answering yes will:

1. Run nxc against all in-scope hosts for each enabled credential
2. Write per-credential report files to `{scans_dir}/cred_checks/`
3. Print a summary table showing passed/failed counts per credential
4. Return to the "Proceed with scan?" confirmation -- you can abort if results look bad

This check runs before the scan starts, so TTY is available for password prompts. It is non-blocking -- even if credentials fail, you can still proceed with the scan.
