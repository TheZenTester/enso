# Configuration Reference

ENSO loads configuration from a directory of YAML files. Each file is optional -- missing files use built-in defaults.

**Config directory search order:**

1. `--config-dir` / `ENSO_CONFIG_DIR` (if specified)
2. `./configs/` (relative to working directory)
3. `~/.config/enso/`
4. `/etc/enso/`

---

## global.yaml

Controls execution strategy, logging, network validation, and the scan pipeline.

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `execution_strategy` | `"linear"` / `"concurrent"` | `"linear"` | How scan modules execute |
| `log_level` | `"DEBUG"` / `"INFO"` / `"WARNING"` / `"ERROR"` | `"INFO"` | Logging verbosity |
| `random_host_count` | int or `"N%"` | `5` | Hosts to ping during reachability check. Accepts integer or "% of in scope hosts". |
| `reachability_threshold` | float (0.0--1.0) | `0.5` | Minimum ratio of reachable hosts required. 0.5 = 50% |
| `cred_check_dir` | string | `"cred_checks"` | Directory under scans/ for credential check reports |
| `export_exclude_dirs` | list of strings | `[]` | Directory names under scans/ to exclude from export |
| `scan_pipeline` | list of modules | see below | Ordered list of scan modules |

### scan_pipeline

Each module in the list accepts the following fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | (required) | Unique module identifier |
| `enabled` | bool | `true` | Whether this module runs |
| `description` | string | `""` | Human-readable description |
| `depends_on` | list of strings | `[]` | Modules that must complete first (concurrent mode only) |
| `output_dir` | string | (from name) | Output directory relative to scans/. Defaults to a convention-based path for built-in modules (`nmap_discovery` -> `nmap/discovery`, `nmap_deep` -> `nmap/detailed`, `nessus` -> `nessus`). Custom modules default to their module name (e.g. `web_enum` -> `web_enum/`). |

**Default pipeline** (see [Scan Modules](../README.md#scan-modules) for a description of each):

- `nmap_discovery` -- no dependencies
- `nmap_deep` -- depends on `nmap_discovery`
- `nessus` -- no dependencies (runs in parallel with discovery in concurrent mode)

### Execution Strategies

**linear**: Modules run in list order, one at a time. `depends_on` is ignored. The order in which they are specified in the `scan_pipeline` is IMPORTANT!

**concurrent**: Modules with no unmet dependencies start immediately. Multiple modules can run in parallel. Typically this means Nessus and Nmap discovery run simultaneously.

### Example

```yaml
execution_strategy: concurrent
log_level: INFO
random_host_count: "20%"
reachability_threshold: 0.5

scan_pipeline:
  - name: nmap_discovery
    enabled: true
    description: "Host discovery and port scanning"
    output_dir: "nmap/discovery"

  - name: nmap_deep
    enabled: true
    description: "Deep scan with service detection and NSE scripts"
    depends_on: [nmap_discovery]
    output_dir: "nmap/detailed"

  - name: nessus
    enabled: true
    description: "Vulnerability scanning with Nessus"
    output_dir: "nessus"
    # No depends_on = starts immediately in concurrent mode
```

The pipeline is extensible -- you can add custom module names for future integrations. Commented-out examples in the shipped `global.yaml` show multi-stage pipelines with modules like `web_enum`, `vuln_analysis`, and `report_generator` (modules not available at this time).

### Extending the Pipeline

Adding a new module only requires a `scan_pipeline` entry with an `output_dir`. The exporter auto-discovers all files under `scans/`, so no code changes are needed for new modules to appear in exports.

Example adding a hypothetical `web_enum` module:

```yaml
scan_pipeline:
  - name: nmap_discovery
    enabled: true
    output_dir: "nmap/discovery"

  - name: web_enum
    enabled: true
    description: "Web application enumeration"
    depends_on: [nmap_discovery]
    output_dir: "web_enum"
```

The `output_dir` is created automatically under `scans/` when the scan starts. Any files written there will be included in `enso export` output.

---

## nmap.yaml

Controls Nmap scan behavior for both discovery and deep phases.

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `discovery.flags` | string | `"-sT -vv -T4 --max-retries=4 -Pn"` | Nmap flags for discovery (do NOT include `-p`) |
| `discovery.default_ports` | string or int | `"all"` | Port specification (see below) |
| `deep.flags` | string | `"-sT -sV -O -sC -vv --max-retries=4"` | Nmap flags for deep scan (do NOT include `-p`) |
| `max_threads` | int (1--50) | `10` | Concurrent Nmap processes |
| `host_timeout` | string | `"35m"` | Per-host timeout (e.g. `"35m"`, `"1h"`, `""` to disable) |
| `log_dir` | string | `"nmap/logs"` | Nmap log directory relative to scans/ |
| `quality_gate.dead_host_threshold` | float (0.0--1.0) | `0.7` | Pause if this percentage of hosts appear offline |

### Port Specification

The `discovery.default_ports` field accepts three formats:

- `"all"` -- scans all 65535 ports (passes `-p-` to nmap)
- Integer (e.g. `1000`) -- uses `--top-ports 1000`
- Comma-separated string (e.g. `"22,80,443,8080"`) -- scans specific ports

The `--top-ports` CLI flag on `enso scan` overrides this value at runtime.

### Deep Scan Notes

- Do NOT include `-p` in `deep.flags` -- ports are automatically passed from discovery results (only open ports are deep-scanned).
- `-O` (OS detection) requires root. ENSO auto-detects this and runs nmap via `sudo` when needed.
- `sudo -v` is called before the dashboard starts to cache credentials while the TTY is still available.

Flags that trigger automatic sudo: `-sS`, `-sU`, `-sA`, `-sW`, `-sM`, `-sN`, `-sF`, `-sX`, `-sY`, `-sZ`, `-O`, `--traceroute`, `--send-eth`.

### Example

```yaml
discovery:
  flags: "-sT -vv -T4 --max-retries=4 -Pn"
  default_ports: all

deep:
  flags: "-sT -sV -O -sC -vv --max-retries=4"

max_threads: 5
host_timeout: "45m"

quality_gate:
  dead_host_threshold: 0.7
```

---

## nessus.yaml

Nessus server connection and policy configuration.

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | `"https://localhost:8834"` | Nessus server URL |
| `access_key` | string | `"${NESSUS_ACCESS_KEY}"` | API access key |
| `secret_key` | string | `"${NESSUS_SECRET_KEY}"` | API secret key |
| `policy_mapping.default` | string | `"Advanced Network Scan"` | Default Nessus policy name |
| `policy_mapping.web` | string | `"Web Application Tests"` | Web scan policy name |

### How to Obtain API Keys

1. Log into the Nessus web interface (e.g. `https://localhost:8834`)
2. Click your username in the upper right hand corner.
3. Click **My Account** in the left navigation bar
4. Click the **API Keys** tab
5. Click **Generate**

Nessus only displays the keys once at generation time -- copy both the Access Key and Secret Key immediately. If you lose them, you must regenerate (which invalidates the old keys). See the [Tenable documentation](https://docs.tenable.com/nessus/Content/GenerateAnAPIKey.htm) for more details.

Once you have the keys, store them with ENSO:

```
enso nessus setup
```

### API Key Resolution

Keys are resolved in this order (first match wins):

1. **Secure key file** (`~/.config/enso/nessus_keys`) -- created by `enso nessus setup`, stored with 600 permissions. This is the recommended approach.
2. **Environment variables** (`NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`) -- use `${VAR}` syntax in the YAML.
3. **Direct values in nessus.yaml** -- only honored if the file has 600 permissions. If the file is group/world-readable, direct values are rejected and ENSO prompts at runtime.

### Why Both API Keys and Web-UI Credentials Are Needed

ENSO uses two authentication methods for different Nessus operations:

| Operation | Auth Method | Configured In |
|---|---|---|
| Server connection and validation | API keys | `nessus.yaml` or `enso nessus setup` |
| Pre-flight checks (connectivity, scanner, policy) | API keys | `nessus.yaml` or `enso nessus setup` |
| Policy reads and credential sync | API keys | `nessus.yaml` or `enso nessus setup` |
| Scan creation, launch, and polling | Session auth | `nessus_ui` in `credentials.yaml` |

Nessus Professional 10.x disables the scan creation API for API keys (`features.scan_api: false`). ENSO automatically detects this and falls back to session authentication using web-UI credentials from the `nessus_ui` section in `credentials.yaml`. If those are not configured, you will be prompted at runtime.

In short: **API keys** handle everything except scan lifecycle operations, which require **session auth** on Pro 10.x.

### Example

```yaml
url: https://nessus.internal:8834
access_key: ${NESSUS_ACCESS_KEY}
secret_key: ${NESSUS_SECRET_KEY}

policy_mapping:
  default: "Internal Network Scan"
  web: "OWASP Top 10"
```

---

## credentials.yaml

Windows and SSH credentials for authenticated Nessus scanning and nxc credential validation.

**Security**: This file may contain passwords. Use `chmod 600 credentials.yaml` to allow direct plaintext values. If the file is group/world-readable, plaintext passwords are rejected and ENSO falls back to runtime prompts.

### Sections

| Section | Type | Description |
|---|---|---|
| `windows` | dict of named credentials | Windows/SMB credentials |
| `linux` | dict of named credentials | Linux/SSH credentials |
| `nessus_ui` | single credential (optional) | Nessus web-UI login for session auth fallback |

### Windows Credential Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `username` | string | (required) | Windows username |
| `domain` | string | `""` | AD domain (empty = local account) |
| `password` | string | `"${WINDOWS_ADMIN_PASSWORD}"` | Password |
| `enabled` | bool | `true` | Include in credential sync and validation |
| `description` | string | `""` | Human-readable label |

### Linux Credential Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `username` | string | (required) | SSH username |
| `password` | string | `"${SSH_PASSWORD}"` | Password |
| `privilege_escalation` | `"sudo"` / `"su"` / `"none"` | `"sudo"` | Escalation method for Nessus |
| `enabled` | bool | `true` | Include in credential sync and validation |
| `description` | string | `""` | Human-readable label |

### Nessus UI Credential Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `username` | string | `""` | Nessus web-UI username |
| `password` | string | `""` | Nessus web-UI password |

### Password Resolution

Passwords are resolved in this order:

1. **Environment variable**: `password: "${MY_SECRET}"` -- interpolates from environment. Safe to commit.
2. **Direct plaintext**: `password: "MyP@ssword!"` -- only accepted if the file has 600 permissions.
3. **Omit or leave empty** -- prompts interactively at runtime.

### Example

```yaml
windows:
  domain_admin:
    username: administrator
    domain: CORP
    password: ${WINDOWS_ADMIN_PASSWORD}
    description: "Domain admin account"

  local_admin:
    username: localadmin
    domain: ""                      # empty domain = local account
    password: "Passw0rd!"           # requires chmod 600
    enabled: false
    description: "Local admin (backup)"

linux:
  ssh_scan:
    username: scanner
    password: ${SSH_PASSWORD}
    privilege_escalation: sudo
    description: "Scan account with sudo"

nessus_ui:
  username: nessus_admin
  password: ${NESSUS_UI_PASSWORD}
```

---

## engagement.yaml

Defines the engagement structure: type, directories, scope files, and network drops/static IP assignments.

### Top-Level Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `engagement_type` | `"simple"` / `"complex"` | `"simple"` | Single or multi-network engagement |
| `client_dir` | path | `/client` | Root client directory |
| `scope_dir` | string | `"engagement_docs"` | Scope files directory (relative to `client_dir`) |
| `interface` | string or null | `null` | Default network interface (auto-detect if null) |
| `simple` | object | see below | Settings for simple engagements |
| `complex` | object | see below | Default scope files for complex engagements |
| `network_drops` | list | `[]` | Network drop configurations |

### simple

| Field | Type | Default | Description |
|---|---|---|---|
| `output_dir` | string | `"internal"` | Base output directory (relative to `client_dir`) |
| `scope_files.in_scope` | string | `null` | In-scope hosts filename |
| `scope_files.excluded` | string | `null` | Excluded hosts filename |
| `scope_files.special` | string | `null` | Special considerations filename |

### complex

| Field | Type | Default | Description |
|---|---|---|---|
| `scope_files.excluded` | string | `null` | Default excluded filename (inherited by all drops) |
| `scope_files.special` | string | `null` | Default special considerations filename |

### network_drops

Each entry in the list:

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | (required) | Human-readable name (can include spaces) |
| `network_dir` | string or null | (from `name`) | Filesystem-safe directory name |
| `interface` | string or null | (global) | Override interface for this drop |
| `static_ip` | string | (required) | Static IP to assign |
| `subnet` | string | `"24"` | CIDR prefix (`24`) or netmask (`255.255.255.0`) |
| `netmask` | string or null | `null` | Alternative to `subnet` (dotted decimal) |
| `gateway` | string | (required) | Gateway IP address |
| `dns` | list of strings | `[]` | DNS server IPs |
| `scope_files` | object or null | `null` | Per-drop scope file overrides |
| `output_dir` | string or null | (from `network_dir`) | Base output directory |

### Subnet Formats

Both are accepted:

- CIDR: `subnet: "24"` or `subnet: "/24"`
- Netmask: `netmask: "255.255.255.0"`

If both are provided, `netmask` takes precedence.

### Simple vs Complex

**Simple** (`engagement_type: simple`): Single network, single scope file. Uses 0 or 1 static IP addresses. Output goes to `{client_dir}/{simple.output_dir}/`.

**Complex** (`engagement_type: complex`): Multiple network drops. Interactive network selection during `enso configure` and `enso scan`. Each drop gets its own output directory. The `in_scope` file must be set per-drop (each network has different targets). The `excluded` and `special` files inherit from `complex.scope_files` unless overridden per-drop. Set a field to `""` to explicitly disable it for one drop.

### Output Directory Structure

For each network (or the single simple network):

```
{client_dir}/{output_dir}/
  scans/
    nmap/
      discovery/      # Per-host Nmap discovery XML + greppable
      detailed/       # Per-host deep scan XML + greppable
    nessus/           # Nessus scan exports
    cred_checks/      # nxc credential check reports
```

### Example: Simple Engagement

```yaml
engagement_type: simple
client_dir: /client
scope_dir: engagement_docs
interface: eth0

simple:
  output_dir: internal
  scope_files:
    in_scope: inscope.txt
    excluded: excluded.txt
```

### Example: Complex Multi-Drop Engagement

```yaml
engagement_type: complex
client_dir: /client
scope_dir: engagement_docs
interface: eth0

complex:
  scope_files:
    excluded: excluded.txt
    special: special_considerations.txt

network_drops:
  - name: "Server Room"
    static_ip: "10.10.10.50"
    subnet: "24"
    gateway: "10.10.10.1"
    dns: ["10.10.10.10"]
    scope_files:
      in_scope: server_room_inscope.txt

  - name: "3rd Floor"
    static_ip: "192.168.50.100"
    netmask: "255.255.255.0"
    gateway: "192.168.50.1"
    dns: ["192.168.50.10"]
    output_dir: 3rd_floor
    scope_files:
      in_scope: 3rd_floor_inscope.txt
      excluded: 3rd_floor_excluded.txt   # overrides complex default
```
