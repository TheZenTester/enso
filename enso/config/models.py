"""Pydantic models for ENSO configuration validation."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


# Global flag to track if credentials file has secure permissions
_credentials_file_secure: bool = False


def check_file_permissions(file_path: Path) -> bool:
    """Check if a file has secure permissions (600 or stricter).
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if file has 600 permissions (owner read/write only), False otherwise
    """
    if not file_path.exists():
        return False
    
    file_stat = file_path.stat()
    mode = file_stat.st_mode
    
    # Check that only owner has read/write, no group/other access
    # 0o600 = owner read+write, no group/other
    other_perms = mode & (stat.S_IRWXG | stat.S_IRWXO)
    return other_perms == 0


def set_credentials_file_security(is_secure: bool) -> None:
    """Set the global credentials file security flag.
    
    Called by loader after checking file permissions.
    """
    global _credentials_file_secure
    _credentials_file_secure = is_secure


def is_credentials_file_secure() -> bool:
    """Check if credentials file has secure permissions."""
    return _credentials_file_secure


# Track nessus.yaml file security (same pattern as credentials)
_nessus_file_secure: bool = False


def set_nessus_file_security(is_secure: bool) -> None:
    """Set the global nessus file security flag.
    
    Called by loader after checking file permissions.
    """
    global _nessus_file_secure
    _nessus_file_secure = is_secure


def is_nessus_file_secure() -> bool:
    """Check if nessus file has secure permissions."""
    return _nessus_file_secure


def resolve_secret(value: str | None, file_secure: bool) -> str:
    """Resolve a secret value using the hybrid security approach.
    
    This is a generalized version that works for any secret field.
    
    Resolution order:
    1. If value contains ${VAR}, try to interpolate from environment
    2. If it's a literal value and file is secure (600), use it directly
    3. If it's a literal value but file is NOT secure, mark for runtime prompt
    4. If None/empty, mark for runtime prompt
    
    Args:
        value: The secret value from config
        file_secure: Whether the source file has secure permissions
        
    Returns:
        Resolved secret, or placeholder pattern for runtime prompt
    """
    if not value:
        return "${PROMPT}"  # Will trigger runtime prompt
    
    # Check for env var pattern
    if "${" in value:
        resolved = _interpolate_env_vars(value)
        return resolved  # Returns original ${...} if env var not set
    
    # Direct value - only allow if file has secure permissions
    if file_secure:
        return value  # Use direct value from secure file
    else:
        # File is not secure, refuse to use direct value
        # Mark for runtime prompt instead
        return "${INSECURE_FILE}"  # Special marker for insecure file warning


def _interpolate_env_vars(value: str) -> str:
    """Replace ${ENV_VAR} patterns with actual environment variable values.
    
    Returns the original pattern if env var is not set (will prompt at runtime).
    """
    pattern = re.compile(r"\$\{([^}]+)\}")
    
    def replacer(match: re.Match) -> str:
        env_var = match.group(1)
        return os.environ.get(env_var, match.group(0))  # Keep original if not set
    
    return pattern.sub(replacer, value)


def resolve_password(value: str | None) -> str:
    """Resolve a password value using the hybrid approach.
    
    Resolution order:
    1. If value contains ${VAR}, try to interpolate from environment
    2. If it's a literal value, use it directly (with security warning if file not secure)
    3. If None/empty, mark for runtime prompt
    
    Args:
        value: The password value from config
        
    Returns:
        Resolved password, or placeholder pattern for runtime prompt
    """
    if not value:
        return "${PROMPT}"  # Will trigger runtime prompt
    
    # Check for env var pattern
    if "${" in value:
        resolved = _interpolate_env_vars(value)
        return resolved  # Returns original ${...} if env var not set
    
    # Direct password - use it directly
    # Security warning is logged elsewhere if file isn't 600
    return value


_DEFAULT_OUTPUT_DIRS: dict[str, str] = {
    "nmap_discovery": "nmap/discovery",
    "nmap_deep": "nmap/detailed",
    "nessus": "nessus",
}


class ScanModule(BaseModel):
    """Configuration for a single scan module in the pipeline.

    Modules can be any tool you want to integrate. The 'depends_on' field
    controls execution order in concurrent mode - modules wait for their
    dependencies to complete before starting.
    """

    name: str = Field(
        description="Module identifier (any unique name)"
    )
    enabled: bool = Field(
        default=True,
        description="Whether this module is enabled"
    )
    description: str = Field(
        default="",
        description="Human-readable description of what this module does"
    )
    depends_on: list[str] = Field(
        default_factory=list,
        description="Modules this depends on (only applies to 'concurrent' strategy)"
    )
    output_dir: str = Field(
        default="",
        description="Output dir relative to scans/ (derived from name if empty)"
    )

    def get_output_dir(self) -> str:
        """Get the output directory for this module.

        Returns the explicit ``output_dir`` if set, otherwise falls back to
        a built-in map for known modules.  Unknown modules default to using
        their ``name`` as the directory.
        """
        if self.output_dir:
            return self.output_dir
        return _DEFAULT_OUTPUT_DIRS.get(self.name, self.name)


def _default_scan_pipeline() -> list["ScanModule"]:
    """Return the default scan pipeline configuration."""
    return [
        ScanModule(
            name="nmap_discovery",
            enabled=True,
            description="Host discovery and port scanning",
        ),
        ScanModule(
            name="nmap_deep",
            enabled=True,
            description="Deep scan with service detection and NSE scripts",
            depends_on=["nmap_discovery"],
        ),
        ScanModule(
            name="nessus",
            enabled=True,
            description="Vulnerability scanning with Nessus",
            depends_on=["nmap_discovery"],
        ),
    ]


class GlobalConfig(BaseModel):
    """Global application configuration."""
    
    execution_strategy: Literal["linear", "concurrent"] = Field(
        default="linear",
        description="Execution mode: 'linear' (list order) or 'concurrent' (parallel with dependencies)"
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging verbosity level"
    )
    random_host_count: str | int = Field(
        default=5,
        description="Hosts to ping for validation: integer (e.g. 5) or percentage string (e.g. '20%')"
    )

    @field_validator("random_host_count")
    @classmethod
    def validate_random_host_count(cls, v: str | int) -> str | int:
        """Accept an integer 1-50 or a percentage string like '20%'."""
        if isinstance(v, int):
            if not 1 <= v <= 50:
                raise ValueError("random_host_count must be between 1 and 50")
            return v
        s = str(v).strip()
        if s.endswith("%"):
            pct = float(s[:-1])
            if not 1 <= pct <= 100:
                raise ValueError("Percentage must be between 1% and 100%")
            return s
        # Bare numeric string
        n = int(s)
        if not 1 <= n <= 50:
            raise ValueError("random_host_count must be between 1 and 50")
        return n

    def resolve_ping_count(self, total_hosts: int) -> int:
        """Compute the actual number of hosts to ping.

        Args:
            total_hosts: Number of hosts available in the scope file

        Returns:
            Actual count to ping (clamped to available hosts, minimum 1)
        """
        if total_hosts <= 0:
            return 0
        v = self.random_host_count
        if isinstance(v, str) and v.strip().endswith("%"):
            import math
            pct = float(v.strip()[:-1]) / 100.0
            count = max(1, math.ceil(total_hosts * pct))
        else:
            count = int(v)
        return min(count, total_hosts)
    reachability_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum ratio of reachable hosts required (0.0-1.0, default 0.5 = 50%)"
    )
    scan_pipeline: list[ScanModule] = Field(
        default_factory=_default_scan_pipeline,
        description="Ordered list of scan modules to execute"
    )
    export_exclude_dirs: list[str] = Field(
        default_factory=list,
        description="Directory names under scans/ to exclude from export"
    )
    cred_check_dir: str = Field(
        default="cred_checks",
        description="Credential check report dir relative to scans/"
    )

    def get_enabled_modules(self) -> list[ScanModule]:
        """Return only enabled modules from the pipeline."""
        return [m for m in self.scan_pipeline if m.enabled]

    def get_module_by_name(self, name: str) -> ScanModule | None:
        """Get a module by its name."""
        for m in self.scan_pipeline:
            if m.name == name:
                return m
        return None

    def get_module_output_dir(self, module_name: str) -> str:
        """Get the output directory for a module by name.

        Args:
            module_name: Module name to look up

        Returns:
            Output directory string relative to scans/

        Raises:
            ValueError: If module is not found in the pipeline
        """
        module = self.get_module_by_name(module_name)
        if module is None:
            raise ValueError(f"Module '{module_name}' not found in pipeline")
        return module.get_output_dir()


class NmapDiscoveryConfig(BaseModel):
    """Nmap discovery scan configuration."""
    
    flags: str = Field(
        default="-sT -vv -T4 --max-retries=4 -Pn",
        description="Nmap flags for discovery scan"
    )
    default_ports: str | int = Field(
        default="all",
        description=(
            "'all' for -p- (all ports), "
            "integer for --top-ports N, "
            "or comma-separated list like '22,80,443,8080'"
        )
    )


class NmapDeepConfig(BaseModel):
    """Nmap deep scan configuration."""
    
    flags: str = Field(
        default="-sT -sV -O -sC -vv --max-retries=4",
        description="Nmap flags for deep scan"
    )


class QualityGateConfig(BaseModel):
    """Quality gate configuration for offline host detection."""
    
    dead_host_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Pause if this percentage of hosts are unreachable"
    )


class NmapConfig(BaseModel):
    """Complete Nmap configuration."""

    discovery: NmapDiscoveryConfig = Field(default_factory=NmapDiscoveryConfig)
    deep: NmapDeepConfig = Field(default_factory=NmapDeepConfig)
    max_threads: int = Field(default=10, ge=1, le=50, description="ThreadPool workers")
    host_timeout: str = Field(
        default="35m",
        description="Per-host timeout for nmap (e.g. '35m', '1h'). Empty string to disable.",
    )
    log_dir: str = Field(
        default="nmap/logs",
        description="Nmap log dir relative to scans/"
    )
    quality_gate: QualityGateConfig = Field(default_factory=QualityGateConfig)


class NessusPolicyMapping(BaseModel):
    """Nessus policy name mappings."""
    
    default: str = Field(default="Advanced Network Scan")
    web: str = Field(default="Web Application Tests")


class NessusConfig(BaseModel):
    """Nessus API configuration.

    Keys are resolved in this priority order:
    1. Secure key file (~/.config/enso/nessus_keys) - use `enso nessus setup`
    2. Environment variables (NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY)
    3. Direct values in nessus.yaml (only if file has 600 permissions)
    """
    
    url: str = Field(
        default="https://localhost:8834",
        description="Nessus server URL"
    )
    access_key: str = Field(
        default="${NESSUS_ACCESS_KEY}",
        description="Nessus API access key"
    )
    secret_key: str = Field(
        default="${NESSUS_SECRET_KEY}",
        description="Nessus API secret key"
    )
    policy_mapping: NessusPolicyMapping = Field(default_factory=NessusPolicyMapping)
    
    @model_validator(mode="after")
    def resolve_secrets(self) -> "NessusConfig":
        """Resolve secrets with multi-source priority.

        Priority:
        1. Secure key file (~/.config/enso/nessus_keys)
        2. Environment variables
        3. nessus.yaml values (only if file is secure)
        """
        # Try loading from secure key file first
        try:
            from ..nessus_keys import load_nessus_keys
            keys = load_nessus_keys()
            if keys:
                self.access_key = keys.access_key
                self.secret_key = keys.secret_key
                return self
        except ImportError:
            pass
        
        # Fall back to resolve_secret (env vars / yaml values)
        self.access_key = resolve_secret(self.access_key, is_nessus_file_secure())
        self.secret_key = resolve_secret(self.secret_key, is_nessus_file_secure())
        return self
    
    def needs_runtime_prompt(self) -> dict[str, bool]:
        """Check which secrets need runtime prompts (still have ${} pattern)."""
        return {
            "access_key": "${" in self.access_key,
            "secret_key": "${" in self.secret_key,
        }
    
    def keys_configured(self) -> bool:
        """Check if both keys are properly configured (no ${} patterns)."""
        needs = self.needs_runtime_prompt()
        return not needs["access_key"] and not needs["secret_key"]


class WindowsCredential(BaseModel):
    """Windows domain credential."""
    
    username: str = Field(description="Windows username")
    domain: str = Field(default="", description="Windows domain (optional)")
    password: str = Field(
        default="${WINDOWS_ADMIN_PASSWORD}",
        description="Password (env var interpolation supported)"
    )
    enabled: bool = Field(default=True, description="Enable this credential for syncing")
    description: str = Field(default="", description="Human-readable description for disambiguation")

    @model_validator(mode="after")
    def resolve_creds(self) -> "WindowsCredential":
        """Resolve password using hybrid approach (env var, file, or prompt)."""
        self.password = resolve_password(self.password)
        return self

    def needs_runtime_prompt(self) -> bool:
        """Check if password needs runtime prompt."""
        return "${" in self.password


class LinuxCredential(BaseModel):
    """Linux SSH credential."""

    username: str = Field(description="SSH username")
    password: str = Field(
        default="${SSH_PASSWORD}",
        description="Password (env var interpolation supported)"
    )
    privilege_escalation: Literal["sudo", "su", "none"] = Field(
        default="sudo",
        description="Privilege escalation method for Nessus"
    )
    enabled: bool = Field(default=True, description="Enable this credential for syncing")
    description: str = Field(default="", description="Human-readable description for disambiguation")
    
    @model_validator(mode="after")
    def resolve_creds(self) -> "LinuxCredential":
        """Resolve password using hybrid approach (env var, file, or prompt)."""
        self.password = resolve_password(self.password)
        return self
    
    def needs_runtime_prompt(self) -> bool:
        """Check if password needs runtime prompt."""
        return "${" in self.password


class NessusUICredential(BaseModel):
    """Nessus web-UI credential for session auth fallback.

    When ``scan_api`` is disabled (Nessus Professional 10.x), API-key auth
    cannot create scans.  Session auth via ``POST /session`` is used instead.
    These credentials are the Nessus web-UI login, NOT the API keys.
    """

    username: str = Field(default="", description="Nessus web-UI username")
    password: str = Field(
        default="",
        description="Password (env var interpolation supported)",
    )

    @model_validator(mode="after")
    def resolve_creds(self) -> "NessusUICredential":
        """Resolve password via env-var interpolation."""
        if self.password:
            self.password = resolve_password(self.password)
        return self

    def needs_runtime_prompt(self) -> bool:
        """Check if credentials still need an interactive prompt."""
        return not self.username or not self.password or "${" in self.password


class CredentialsConfig(BaseModel):
    """Credential configuration for authenticated scans."""

    windows: dict[str, WindowsCredential] = Field(default_factory=dict)
    linux: dict[str, LinuxCredential] = Field(default_factory=dict)
    nessus_ui: NessusUICredential | None = Field(
        default=None,
        description="Nessus web-UI credentials for session auth fallback",
    )

    def filter_by_names(
        self,
        windows_names: list[str],
        linux_names: list[str],
    ) -> "CredentialsConfig":
        """Return a new CredentialsConfig containing only the named credentials.

        Args:
            windows_names: Windows credential names to keep
            linux_names: Linux credential names to keep

        Returns:
            New CredentialsConfig with only the selected credentials
        """
        return CredentialsConfig(
            windows={n: c for n, c in self.windows.items() if n in windows_names},
            linux={n: c for n, c in self.linux.items() if n in linux_names},
            nessus_ui=self.nessus_ui,
        )


# Netmask to CIDR lookup table
_NETMASK_TO_CIDR = {
    "255.255.255.255": "32",
    "255.255.255.254": "31",
    "255.255.255.252": "30",
    "255.255.255.248": "29",
    "255.255.255.240": "28",
    "255.255.255.224": "27",
    "255.255.255.192": "26",
    "255.255.255.128": "25",
    "255.255.255.0": "24",
    "255.255.254.0": "23",
    "255.255.252.0": "22",
    "255.255.248.0": "21",
    "255.255.240.0": "20",
    "255.255.224.0": "19",
    "255.255.192.0": "18",
    "255.255.128.0": "17",
    "255.255.0.0": "16",
    "255.254.0.0": "15",
    "255.252.0.0": "14",
    "255.248.0.0": "13",
    "255.240.0.0": "12",
    "255.224.0.0": "11",
    "255.192.0.0": "10",
    "255.128.0.0": "9",
    "255.0.0.0": "8",
}


def netmask_to_cidr(netmask: str) -> str:
    """Convert a netmask (e.g., '255.255.255.0') to CIDR notation (e.g., '24').
    
    Args:
        netmask: Netmask in dotted decimal format
        
    Returns:
        CIDR prefix length as a string
        
    Raises:
        ValueError: If the netmask is invalid
    """
    if netmask in _NETMASK_TO_CIDR:
        return _NETMASK_TO_CIDR[netmask]
    raise ValueError(f"Invalid netmask: {netmask}")


def normalize_subnet(value: str) -> str:
    """Normalize subnet input to CIDR notation.
    
    Accepts:
        - CIDR notation: "24", "/24"
        - Netmask: "255.255.255.0"
        
    Returns:
        CIDR prefix length as a string (without /)
    """
    # Remove leading slash if present
    value = value.lstrip("/")
    
    # If it's already CIDR (just digits)
    if value.isdigit():
        cidr = int(value)
        if 0 <= cidr <= 32:
            return value
        raise ValueError(f"Invalid CIDR prefix: {value}")
    
    # Try to convert from netmask
    if "." in value:
        return netmask_to_cidr(value)
    
    raise ValueError(f"Invalid subnet format: {value}. Use CIDR (e.g., '24') or netmask (e.g., '255.255.255.0')")


class ScopeFilesConfig(BaseModel):
    """Scope file names (relative to scope_dir)."""

    in_scope: str | None = Field(default=None, description="In-scope hosts filename")
    excluded: str | None = Field(default=None, description="Excluded hosts filename")
    special: str | None = Field(default=None, description="Special considerations filename")


class SimpleConfig(BaseModel):
    """Configuration specific to simple (single-network) engagements."""

    output_dir: str = Field(default="internal", description="Base output dir for simple engagements")
    scope_files: ScopeFilesConfig = Field(
        default_factory=lambda: ScopeFilesConfig(
            in_scope="inscope.txt", excluded="excluded.txt", special="special_considerations.txt"
        )
    )


class ComplexConfig(BaseModel):
    """Default scope files inherited by all network drops in complex engagements."""

    scope_files: ScopeFilesConfig = Field(
        default_factory=lambda: ScopeFilesConfig(excluded="excluded.txt", special="special_considerations.txt"),
        description="Default scope files inherited by drops"
    )


class NetworkDropConfig(BaseModel):
    """Configuration for a specific network drop in complex engagements."""

    name: str = Field(description="Human-readable network name (can include spaces)")
    network_dir: str | None = Field(
        default=None,
        description="Filesystem-safe directory name (auto-generated from name if not set)"
    )
    interface: str | None = Field(
        default=None,
        description="Override interface for this drop (uses global interface if not set)"
    )
    static_ip: str = Field(description="Static IP to assign for this network")
    subnet: str = Field(
        default="24",
        description="Subnet in CIDR (e.g., '24') or netmask format (e.g., '255.255.255.0')"
    )
    netmask: str | None = Field(
        default=None,
        description="Alternative to subnet - netmask in dotted decimal (e.g., '255.255.255.0')"
    )
    gateway: str = Field(description="Gateway IP address")
    dns: list[str] = Field(default_factory=list, description="DNS servers")
    scope_files: ScopeFilesConfig | None = Field(
        default=None,
        description="Per-drop scope files (fields inherit from complex.scope_files if not set)"
    )
    output_dir: str | None = Field(
        default=None,
        description="Base output dir (auto-computed from network_dir if not set)"
    )
    
    @field_validator("static_ip", "gateway")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Basic IP address format validation."""
        parts = v.split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address format: {v}")
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                raise ValueError(f"Invalid IP address octet: {part}")
        return v
    
    @model_validator(mode="after")
    def normalize_subnet_value(self) -> "NetworkDropConfig":
        """Normalize subnet to CIDR notation, handling netmask if provided."""
        # If netmask is provided, use it (takes precedence)
        if self.netmask:
            self.subnet = netmask_to_cidr(self.netmask)
        else:
            # Normalize the subnet value
            self.subnet = normalize_subnet(self.subnet)
        return self
    
    def get_cidr_subnet(self) -> str:
        """Get the subnet in CIDR notation (always normalized)."""
        return self.subnet
    
    def get_network_dir(self) -> str:
        """Get network directory (uses network_dir if set, otherwise auto-generates from name).
        
        Returns:
            Filesystem-safe directory name (lowercase, underscores instead of spaces)
        """
        if self.network_dir:
            return self.network_dir
        # Auto-generate: lowercase, replace spaces with underscores
        return self.name.lower().replace(" ", "_").replace("-", "_")
    
    def get_output_dir(self) -> str:
        """Get base output directory for this drop.

        Returns:
            Base output directory (e.g., 'internal' or 'server_room').
            /scans/nmap and /scans/nessus are appended by EngagementContext.
        """
        if self.output_dir:
            return self.output_dir
        return self.get_network_dir()


class EngagementConfig(BaseModel):
    """Engagement-specific configuration for complex networks."""

    engagement_type: Literal["simple", "complex"] = Field(
        default="simple",
        description="Engagement type: 'simple' (single network) or 'complex' (multiple networks)"
    )
    client_dir: Path = Field(
        default=Path("/client"),
        description="Root client directory"
    )
    scope_dir: str = Field(
        default="engagement_docs",
        description="Scope files directory (relative to client_dir)"
    )
    interface: str | None = Field(
        default=None,
        description="Default network interface to configure (e.g., 'eth0'). Auto-detected if not set."
    )
    simple: SimpleConfig = Field(default_factory=SimpleConfig)
    complex_config: ComplexConfig = Field(default_factory=ComplexConfig, alias="complex")
    network_drops: list[NetworkDropConfig] = Field(
        default_factory=list,
        description="Network drop configurations for complex engagements"
    )

    model_config = {"populate_by_name": True}

    def get_interface_for_drop(self, drop: NetworkDropConfig) -> str | None:
        """Get effective interface for a network drop (drop override or global)."""
        return drop.interface or self.interface

    def resolve_scope_files_for_drop(self, drop: NetworkDropConfig) -> ScopeFilesConfig:
        """Merge defaults with per-drop scope_files overrides.

        Defaults come from simple.scope_files or complex.scope_files
        depending on engagement_type. Per-field inheritance: if a field
        is present on the drop it wins, if absent the default is used,
        if explicitly "" no file.
        """
        if self.engagement_type == "simple":
            defaults = self.simple.scope_files
        else:
            defaults = self.complex_config.scope_files

        if drop.scope_files is None:
            return defaults

        overrides = drop.scope_files
        return ScopeFilesConfig(
            in_scope=overrides.in_scope if overrides.in_scope is not None else defaults.in_scope,
            excluded=overrides.excluded if overrides.excluded is not None else defaults.excluded,
            special=overrides.special if overrides.special is not None else defaults.special,
        )


class EnsoConfig(BaseModel):
    """Root configuration combining all config sections."""
    
    global_config: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    nessus: NessusConfig = Field(default_factory=NessusConfig)
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)
    engagement: EngagementConfig = Field(default_factory=EngagementConfig)
    
    model_config = {"populate_by_name": True}
