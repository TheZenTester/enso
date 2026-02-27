# ENSO -- Engagement Network Scanning Orchestrator

A Python CLI tool that orchestrates Nmap and Nessus scans for internal network penetration tests. ENSO handles network configuration, credential management, scan pipeline execution, and real-time progress monitoring -- all from a single terminal.

## Requirements

- Python 3.12+
- nmap (installed separately; deep scans with `-O` require root)
- Nessus Professional or Tenable.io (optional but expected)
- nxc / NetExec (optional, for credential validation)
- Linux with Netplan (for `enso configure` network setup)

## Installation

```
cd enso
pip install -e .
```

## Quick Start

### 1. Edit configuration files

The `configs/` directory ships with sane defaults. At minimum, edit:

- `engagement.yaml` -- set your client directory, scope files, and network drops
- `credentials.yaml` -- add Windows/SSH credentials for authenticated scanning

### 2. Store Nessus API keys

Both API keys and Nessus web-UI credentials are needed. See the [Configuration Reference](docs/configuration.md#nessusyaml) for details on how each is used.

```
enso nessus setup
```

### 3. Run scans

```
enso scan
```

ENSO walks you through the entire workflow interactively: network configuration (if needed), pre-flight checks, credential sync to Nessus, optional credential validation, and scan execution with a real-time dashboard.

### 4. Check Nessus progress

```
enso status
```

## How It Works

ENSO executes a configurable scan pipeline that can run in [concurrent or linear mode](docs/configuration.md#execution-strategies). In concurrent mode (default in the shipped config), Nessus and Nmap discovery run in parallel:

```
                          +---> [Quality Gate] ---> [Deep Scan]
  [Scope File] ---> [Discovery]
                    [Nessus] ------>
                          |
                    [ Live Dashboard ]
```

**Before scanning**, ENSO runs pre-flight checks:

- AC power and interface link verification
- Nessus connectivity, authentication, and policy validation
- Credential sync (compares `credentials.yaml` with the Nessus policy)
- Optional nxc credential validation against in-scope hosts

**During scanning**, a Rich terminal dashboard tracks per-host progress across all modules (discovery, deep scan, Nessus).

**Quality gate**: After discovery, if more than 70% of hosts appear offline, the pipeline pauses and prompts whether to continue.

**Scan resume**: If a scan is interrupted (Ctrl+C, crash, network issue), restarting `enso scan` automatically detects previous results on disk and offers to resume where you left off. Only hosts that didn't finish are re-scanned. If a Nessus scan is still running on the server, ENSO reconnects to it instead of creating a new one. See [Scan Resume](docs/commands.md#scan-resume) for details.

## Scan Modules

The scan pipeline is built from modules defined in [`global.yaml`](docs/configuration.md#scan_pipeline). Modules can be enabled/disabled individually and declare dependencies on other modules. The shipped config includes three modules:

| Module | Description |
|---|---|
| `nmap_discovery` | Lightweight port scan across all in-scope hosts. Identifies which ports are open on each host. Runs first with no dependencies. Checks all 65,535 ports. |
| `nmap_deep` | Service detection, OS fingerprinting, and NSE scripts against only the open ports found during discovery. Depends on `nmap_discovery`. Requires root for `-O` (ENSO handles `sudo` automatically). |
| `nessus` | Authenticated vulnerability scan via Nessus. Runs independently -- in concurrent mode it starts in parallel with discovery rather than waiting for it to finish. |

The pipeline is extensible. You can add custom module names (e.g. `web_enum`, `vuln_analysis`, `report_generator`) with dependency chains -- see the commented-out examples in the shipped `global.yaml`. As ENSO grows, new modules will plug into this same pipeline.

## Directory Layout

```
/client/                          # client_dir (configurable)
  engagement_docs/                # scope_dir
    inscope.txt                   # in-scope hosts (one IP per line)
    excluded.txt                  # excluded hosts
  internal/                       # output_dir (simple engagement)
    scans/
      nmap/
        discovery/                # per-host XML + greppable output
        detailed/                 # deep scan results
      nessus/                     # Nessus exports
      cred_checks/                # nxc credential check reports
```

For complex (multi-network) engagements, each network drop gets its own output directory under `client_dir`.

## Configuration Files

All files live in `configs/` and are documented in detail in [docs/configuration.md](docs/configuration.md).

| File | Purpose |
|---|---|
| `global.yaml` | Execution strategy (linear/concurrent), log level, scan pipeline modules |
| `nmap.yaml` | Nmap flags, port specification, thread count, host timeout, quality gate |
| `nessus.yaml` | Nessus server URL, API key resolution, policy mapping |
| `credentials.yaml` | Windows/SSH credentials, Nessus UI fallback credentials |
| `engagement.yaml` | Engagement type (simple/complex), client directory, scope files, network drops |

## CLI Reference

Full documentation with flags and examples in [docs/commands.md](docs/commands.md).

| Command | Description |
|---|---|
| `enso configure` | Set up network interface (static IP or DHCP via Netplan) |
| `enso scan` | Launch scanning workflow with real-time dashboard |
| `enso export` | Package scan results into a zip for delivery (differential tracking) |
| `enso status` | Check Nessus scan progress |
| `enso nessus setup` | Store API keys securely (~/.config/enso/nessus_keys) |
| `enso nessus clear` | Remove stored API keys |
| `enso nessus check` | Pre-flight Nessus validation (connectivity, auth, policy) |
| `enso nessus sync-creds` | Push credentials from credentials.yaml to Nessus policy |
| `enso nessus export` | Export one or more Nessus scans to .nessus files (auto-routes to correct output dir) |
| `enso creds show` | Display configured credentials (passwords masked) |
| `enso creds test` | Validate credentials against target hosts with nxc |

## Environment Variables
ENSO supports environment variables as the default mechanism for injecting secrets. If a variable is not set and the corresponding value is not provided in the config files, ENSO will prompt for it interactively during the scan workflow.

>[!IMPORTANT] Storing Cleartext Passwords in `credentials.yaml`
> ENSO allows plaintext passwords in `credentials.yaml` for convenience during engagements.
> This assumes you're exercising good judgment -- the device is trusted, the file is `chmod 600`, and you're not committing secrets to version control. Use environment variables if in doubt.

Plaintext values in config files are also supported for convenience during an engagement -- but only when the file has strict permissions (`chmod 600`). See the [Configuration Reference](docs/configuration.md#password-resolution) for the full resolution order.

| Variable | Purpose |
|---|---|
| `ENSO_CONFIG_DIR` | Override configuration directory |
| `NESSUS_ACCESS_KEY` | Nessus API access key (fallback if no key file) |
| `NESSUS_SECRET_KEY` | Nessus API secret key (fallback if no key file) |
| `WINDOWS_ADMIN_PASSWORD` | Default env var for Windows credential passwords |
| `SSH_PASSWORD` | Default env var for SSH credential passwords |

## Running Tests

Runs the full test suite covering configuration loading, Nessus API contract, credential validation, scan resume, and scan orchestration.

```
python3 -m pytest tests/ -v
```
