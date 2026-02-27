"""Configuration file loader with YAML support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import (
    EnsoConfig,
    CredentialsConfig,
    GlobalConfig,
    NessusConfig,
    NmapConfig,
    EngagementConfig,
)


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load a YAML file and return its contents as a dictionary."""
    if not path.exists():
        return {}
    with open(path, "r") as f:
        content = yaml.safe_load(f)
        return content if content else {}


def load_config(config_dir: Path | str) -> EnsoConfig:
    """Load configuration from a directory containing YAML config files.

    Expected files:
        - global.yaml: Global settings (execution strategy, log level)
        - nmap.yaml: Nmap scan configuration
        - nessus.yaml: Nessus API configuration
        - credentials.yaml: Credential templates
        - engagement.yaml: Engagement-specific settings (optional)

    Args:
        config_dir: Path to the configuration directory

    Returns:
        Fully validated EnsoConfig instance
    """
    config_path = Path(config_dir)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration directory not found: {config_path}")
    
    # Load individual config files
    global_data = _load_yaml_file(config_path / "global.yaml")
    nmap_data = _load_yaml_file(config_path / "nmap.yaml")
    engagement_data = _load_yaml_file(config_path / "engagement.yaml")
    
    # Check credentials file permissions BEFORE loading
    # This must happen before the credentials are parsed
    credentials_file = config_path / "credentials.yaml"
    from .models import (
        check_file_permissions, 
        set_credentials_file_security,
        set_nessus_file_security,
    )
    
    is_secure = check_file_permissions(credentials_file)
    set_credentials_file_security(is_secure)
    credentials_data = _load_yaml_file(credentials_file)
    
    # Check nessus file permissions BEFORE loading (same pattern as credentials)
    # API keys should have the same security treatment as passwords
    nessus_file = config_path / "nessus.yaml"
    nessus_is_secure = check_file_permissions(nessus_file)
    set_nessus_file_security(nessus_is_secure)
    nessus_data = _load_yaml_file(nessus_file)
    
    # Build individual config objects
    global_config = GlobalConfig(**global_data) if global_data else GlobalConfig()
    nmap_config = NmapConfig(**nmap_data) if nmap_data else NmapConfig()
    nessus_config = NessusConfig(**nessus_data) if nessus_data else NessusConfig()
    credentials_config = CredentialsConfig(**credentials_data) if credentials_data else CredentialsConfig()
    engagement_config = EngagementConfig(**engagement_data) if engagement_data else EngagementConfig()
    
    return EnsoConfig(
        global_config=global_config,
        nmap=nmap_config,
        nessus=nessus_config,
        credentials=credentials_config,
        engagement=engagement_config,
    )


_CRITICAL_CONFIGS = ["credentials.yaml", "engagement.yaml"]


def check_missing_configs(config_dir: Path | str) -> list[str]:
    """Check for critical config files that are missing entirely.

    Returns a list of filenames that don't exist and have no .example counterpart.
    Files that have a .example are handled by check_example_configs() instead.
    """
    config_path = Path(config_dir)
    missing = []
    for name in _CRITICAL_CONFIGS:
        yaml_file = config_path / name
        example_file = config_path / f"{name}.example"
        if not yaml_file.exists() and not example_file.exists():
            missing.append(name)
    return missing


def check_example_configs(config_dir: Path | str) -> list[str]:
    """Check for .example config files that haven't been copied to .yaml.

    Returns a list of basenames (without .example) that need setup.
    Only warns if the .example exists but the corresponding .yaml does not.
    """
    config_path = Path(config_dir)
    missing = []
    for example_file in sorted(config_path.glob("*.example")):
        yaml_file = example_file.with_suffix("")  # strips .example
        if not yaml_file.exists():
            missing.append(yaml_file.name)
    return missing


def get_default_config_dir() -> Path:
    """Get the default configuration directory.
    
    Checks in order:
        1. ./configs (relative to current working directory)
        2. ~/.config/enso/
        3. /etc/enso/
    
    Returns:
        Path to the first existing config directory, or ./configs as default
    """
    candidates = [
        Path.cwd() / "configs",
        Path.home() / ".config" / "enso",
        Path("/etc/enso"),
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    # Default to local configs directory
    return candidates[0]
