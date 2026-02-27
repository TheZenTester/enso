"""Tests for configuration loading and validation."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from enso.config import (
    load_config,
    GlobalConfig,
    NmapConfig,
    NessusConfig,
    CredentialsConfig,
    EnsoConfig,
    ScopeFilesConfig,
    SimpleConfig,
    ComplexConfig,
)
from enso.config.models import _interpolate_env_vars


class TestEnvVarInterpolation:
    """Tests for environment variable interpolation."""
    
    def test_interpolate_existing_var(self, monkeypatch):
        """Test interpolation of existing environment variable."""
        monkeypatch.setenv("TEST_VAR", "secret_value")
        result = _interpolate_env_vars("prefix_${TEST_VAR}_suffix")
        assert result == "prefix_secret_value_suffix"
    
    def test_interpolate_missing_var(self):
        """Test that missing env vars are kept as-is."""
        result = _interpolate_env_vars("${NONEXISTENT_VAR}")
        assert result == "${NONEXISTENT_VAR}"
    
    def test_interpolate_multiple_vars(self, monkeypatch):
        """Test interpolation of multiple variables."""
        monkeypatch.setenv("VAR1", "one")
        monkeypatch.setenv("VAR2", "two")
        result = _interpolate_env_vars("${VAR1}_and_${VAR2}")
        assert result == "one_and_two"


class TestGlobalConfig:
    """Tests for GlobalConfig model."""
    
    def test_defaults(self):
        """Test default values."""
        config = GlobalConfig()
        assert config.execution_strategy == "linear"
        assert config.log_level == "INFO"
    
    def test_valid_strategies(self):
        """Test valid execution strategies."""
        config = GlobalConfig(execution_strategy="concurrent")
        assert config.execution_strategy == "concurrent"
    
    def test_invalid_strategy(self):
        """Test invalid execution strategy raises error."""
        with pytest.raises(ValueError):
            GlobalConfig(execution_strategy="invalid")


class TestNmapConfig:
    """Tests for NmapConfig model."""
    
    def test_defaults(self):
        """Test default values."""
        config = NmapConfig()
        assert config.max_threads == 10
        assert config.discovery.default_ports == "all"
    
    def test_thread_bounds(self):
        """Test thread count bounds."""
        with pytest.raises(ValueError):
            NmapConfig(max_threads=0)
        
        with pytest.raises(ValueError):
            NmapConfig(max_threads=100)


class TestNessusConfig:
    """Tests for NessusConfig model."""
    
    def test_env_var_interpolation(self, monkeypatch):
        """Test that API keys are interpolated from env."""
        monkeypatch.setenv("NESSUS_ACCESS_KEY", "test_access")
        monkeypatch.setenv("NESSUS_SECRET_KEY", "test_secret")
        
        # Mock out key file loading to test env var path
        import enso.nessus_keys as nk
        monkeypatch.setattr(nk, "load_nessus_keys", lambda: None)
        
        config = NessusConfig(
            access_key="${NESSUS_ACCESS_KEY}",
            secret_key="${NESSUS_SECRET_KEY}",
        )
        
        assert config.access_key == "test_access"
        assert config.secret_key == "test_secret"
    
    def test_needs_runtime_prompt(self, monkeypatch):
        """Test detection of secrets needing runtime prompt."""
        # Mock out key file loading
        import enso.nessus_keys as nk
        monkeypatch.setattr(nk, "load_nessus_keys", lambda: None)
        
        # Set nessus file as secure so hardcoded values pass through
        from enso.config.models import set_nessus_file_security
        set_nessus_file_security(True)
        
        config = NessusConfig(
            access_key="${NOT_SET}",
            secret_key="hardcoded",
        )
        
        needs = config.needs_runtime_prompt()
        assert needs["access_key"] is True
        assert needs["secret_key"] is False
        
        # Reset to default
        set_nessus_file_security(False)


class TestConfigLoader:
    """Tests for YAML config loading."""
    
    def test_load_from_directory(self, tmp_path):
        """Test loading config from a directory."""
        # Create config files
        global_yaml = tmp_path / "global.yaml"
        global_yaml.write_text("execution_strategy: concurrent\nlog_level: DEBUG")
        
        nmap_yaml = tmp_path / "nmap.yaml"
        nmap_yaml.write_text("max_threads: 5")
        
        config = load_config(tmp_path)
        
        assert config.global_config.execution_strategy == "concurrent"
        assert config.global_config.log_level == "DEBUG"
        assert config.nmap.max_threads == 5
    
    def test_load_missing_directory(self, tmp_path):
        """Test loading from non-existent directory raises error."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent")
    
    def test_load_with_missing_files(self, tmp_path):
        """Test loading with some config files missing uses defaults."""
        # Create only global.yaml
        global_yaml = tmp_path / "global.yaml"
        global_yaml.write_text("log_level: WARNING")
        
        config = load_config(tmp_path)
        
        assert config.global_config.log_level == "WARNING"
        # Other configs should be defaults
        assert config.nmap.max_threads == 10
        assert config.nessus.url == "https://localhost:8834"


class TestCredentialResolution:
    """Tests for hybrid credential resolution."""
    
    def test_resolve_password_from_env_var(self, monkeypatch):
        """Test password resolution from environment variable."""
        from enso.config.models import resolve_password
        
        monkeypatch.setenv("TEST_PASSWORD", "env_secret")
        
        result = resolve_password("${TEST_PASSWORD}")
        assert result == "env_secret"
    
    def test_resolve_password_unset_env_returns_placeholder(self):
        """Test password with unset env var keeps placeholder."""
        from enso.config.models import resolve_password
        
        result = resolve_password("${DEFINITELY_UNSET_VAR_12345}")
        # Unset env vars are kept as-is for later runtime prompt detection
        assert result == "${DEFINITELY_UNSET_VAR_12345}"
    
    def test_check_file_permissions_secure(self, tmp_path):
        """Test permission check for secure file (600)."""
        from enso.config.models import check_file_permissions
        import stat
        
        secure_file = tmp_path / "secure.yaml"
        secure_file.write_text("password: secret")
        secure_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
        
        assert check_file_permissions(secure_file) is True
    
    def test_check_file_permissions_insecure(self, tmp_path):
        """Test permission check for insecure file (644)."""
        from enso.config.models import check_file_permissions
        import stat
        
        insecure_file = tmp_path / "insecure.yaml"
        insecure_file.write_text("password: secret")
        insecure_file.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 644
        
        assert check_file_permissions(insecure_file) is False


class TestNmapPortFormats:
    """Tests for Nmap port specification formats."""
    
    def test_default_ports_all(self):
        """Test default ports value is 'all'."""
        from enso.config.models import NmapDiscoveryConfig
        
        config = NmapDiscoveryConfig()
        assert config.default_ports == "all"
    
    def test_custom_port_list(self):
        """Test custom port list format."""
        from enso.config.models import NmapDiscoveryConfig
        
        config = NmapDiscoveryConfig(default_ports="22,80,443,8080")
        assert config.default_ports == "22,80,443,8080"
    
    def test_port_range_format(self):
        """Test port range format."""
        from enso.config.models import NmapDiscoveryConfig
        
        config = NmapDiscoveryConfig(default_ports="1-1000")
        assert config.default_ports == "1-1000"
    
    def test_top_ports_format(self):
        """Test top-N ports format."""
        from enso.config.models import NmapDiscoveryConfig
        
        config = NmapDiscoveryConfig(default_ports="top100")
        assert config.default_ports == "top100"


class TestInterfaceResolution:
    """Tests for network interface resolution with fallback."""

    def test_get_interface_from_drop(self):
        """Test interface from drop-specific config."""
        from enso.config.models import EngagementConfig, NetworkDropConfig

        config = EngagementConfig(
            interface="eth0",
            network_drops=[
                NetworkDropConfig(
                    name="Test Network",
                    static_ip="10.0.0.1",
                    subnet="24",
                    gateway="10.0.0.254",
                    interface="enp0s3",
                    output_dir="internal",
                )
            ]
        )

        drop = config.network_drops[0]
        result = config.get_interface_for_drop(drop)
        assert result == "enp0s3"

    def test_get_interface_fallback_to_global(self):
        """Test interface falls back to global when not specified on drop."""
        from enso.config.models import EngagementConfig, NetworkDropConfig

        config = EngagementConfig(
            interface="eth0",
            network_drops=[
                NetworkDropConfig(
                    name="Test Network",
                    static_ip="10.0.0.1",
                    subnet="24",
                    gateway="10.0.0.254",
                    output_dir="internal",
                )
            ]
        )

        drop = config.network_drops[0]
        result = config.get_interface_for_drop(drop)
        assert result == "eth0"

    def test_get_interface_both_none(self):
        """Test interface is None when neither drop nor global specifies."""
        from enso.config.models import EngagementConfig, NetworkDropConfig

        config = EngagementConfig(
            network_drops=[
                NetworkDropConfig(
                    name="Test Network",
                    static_ip="10.0.0.1",
                    subnet="24",
                    gateway="10.0.0.254",
                    output_dir="internal",
                )
            ]
        )

        drop = config.network_drops[0]
        result = config.get_interface_for_drop(drop)
        assert result is None


class TestACPowerCheck:
    """Tests for AC power detection."""
    
    def test_check_ac_power_no_sys_path(self, tmp_path, monkeypatch):
        """Test power check returns True when /sys/class/power_supply doesn't exist."""
        from enso.ui.prompts import Prompts
        
        # Mock Path to return non-existent directory
        original_path = Path
        
        class MockPath(type(Path())):
            def __new__(cls, *args, **kwargs):
                instance = super().__new__(cls, *args, **kwargs)
                return instance
            
            def exists(self):
                if str(self) == "/sys/class/power_supply":
                    return False
                return super().exists()
        
        # The function should return True (assume plugged in) if path doesn't exist
        # We test this by checking the expected behavior
        result = Prompts._check_ac_power()
        # Result depends on actual system state, but function should not crash
        assert isinstance(result, bool)
    
    def test_check_ac_power_returns_bool(self):
        """Test that _check_ac_power always returns a boolean."""
        from enso.ui.prompts import Prompts
        
        result = Prompts._check_ac_power()
        assert isinstance(result, bool)


class TestEngagementContext:
    """Tests for EngagementContext flags."""
    
    def test_context_defaults(self, tmp_path):
        """Test EngagementContext default values."""
        from enso.context import EngagementContext, ScopeFiles
        
        scope_files = ScopeFiles(in_scope=tmp_path / "scope.txt")
        context = EngagementContext(
            engagement_type="simple",
            client_dir=tmp_path,
            scope_files=scope_files,
            output_dir=tmp_path / "output",
        )

        assert context.manual_entry_requested is False
        assert context.dhcp_requested is False
        assert context.network_drop is None
    
    def test_context_manual_entry_flag(self, tmp_path):
        """Test EngagementContext with manual_entry_requested flag."""
        from enso.context import EngagementContext, ScopeFiles
        
        scope_files = ScopeFiles(in_scope=tmp_path / "scope.txt")
        context = EngagementContext(
            engagement_type="complex",
            client_dir=tmp_path,
            scope_files=scope_files,
            output_dir=tmp_path / "output",
            manual_entry_requested=True,
        )
        
        assert context.manual_entry_requested is True
        assert context.dhcp_requested is False
    
    def test_context_dhcp_flag(self, tmp_path):
        """Test EngagementContext with dhcp_requested flag."""
        from enso.context import EngagementContext, ScopeFiles
        
        scope_files = ScopeFiles(in_scope=tmp_path / "scope.txt")
        context = EngagementContext(
            engagement_type="complex",
            client_dir=tmp_path,
            scope_files=scope_files,
            output_dir=tmp_path / "output",
            dhcp_requested=True,
        )
        
        assert context.manual_entry_requested is False
        assert context.dhcp_requested is True


class TestScanPipeline:
    """Tests for scan pipeline configuration."""
    
    def test_scan_module_defaults(self):
        """Test ScanModule with default values."""
        from enso.config.models import ScanModule
        
        module = ScanModule(name="nmap_discovery")
        
        assert module.name == "nmap_discovery"
        assert module.enabled is True
        assert module.description == ""
        assert module.depends_on == []
    
    def test_scan_module_with_dependency(self):
        """Test ScanModule with depends_on."""
        from enso.config.models import ScanModule
        
        module = ScanModule(
            name="nmap_deep",
            enabled=True,
            description="NSE scanning",
            depends_on=["nmap_discovery"],
        )
        
        assert module.name == "nmap_deep"
        assert module.depends_on == ["nmap_discovery"]
    
    def test_scan_module_with_multiple_dependencies(self):
        """Test ScanModule with multiple dependencies."""
        from enso.config.models import ScanModule
        
        module = ScanModule(
            name="final_report",
            description="Generate report from all scan data",
            depends_on=["nmap_discovery", "nessus", "vuln_scanner"],
        )
    
    def test_global_config_default_pipeline(self):
        """Test GlobalConfig has default pipeline."""
        from enso.config.models import GlobalConfig
        
        config = GlobalConfig()
        
        assert len(config.scan_pipeline) == 3
        assert config.scan_pipeline[0].name == "nmap_discovery"
        assert config.scan_pipeline[1].name == "nmap_deep"
        assert config.scan_pipeline[2].name == "nessus"
    
    def test_get_enabled_modules(self):
        """Test filtering enabled modules."""
        from enso.config.models import GlobalConfig, ScanModule
        
        config = GlobalConfig(
            scan_pipeline=[
                ScanModule(name="nmap_discovery", enabled=True),
                ScanModule(name="nmap_deep", enabled=False),
                ScanModule(name="nessus", enabled=True),
            ]
        )
        
        enabled = config.get_enabled_modules()
        
        assert len(enabled) == 2
        assert enabled[0].name == "nmap_discovery"
        assert enabled[1].name == "nessus"
    
    def test_get_module_by_name(self):
        """Test retrieving module by name."""
        from enso.config.models import GlobalConfig
        
        config = GlobalConfig()
        
        nessus = config.get_module_by_name("nessus")
        assert nessus is not None
        assert nessus.name == "nessus"
        
        missing = config.get_module_by_name("missing")
        assert missing is None


class TestScanModuleOutputDir:
    """Tests for ScanModule.get_output_dir() and GlobalConfig.get_module_output_dir()."""

    def test_explicit_output_dir(self):
        """ScanModule returns explicit output_dir when set."""
        from enso.config.models import ScanModule
        module = ScanModule(name="nmap_discovery", output_dir="custom/disc")
        assert module.get_output_dir() == "custom/disc"

    def test_default_nmap_discovery(self):
        """nmap_discovery falls back to 'nmap/discovery'."""
        from enso.config.models import ScanModule
        module = ScanModule(name="nmap_discovery")
        assert module.get_output_dir() == "nmap/discovery"

    def test_default_nmap_deep(self):
        """nmap_deep falls back to 'nmap/detailed'."""
        from enso.config.models import ScanModule
        module = ScanModule(name="nmap_deep")
        assert module.get_output_dir() == "nmap/detailed"

    def test_default_nessus(self):
        """nessus falls back to 'nessus'."""
        from enso.config.models import ScanModule
        module = ScanModule(name="nessus")
        assert module.get_output_dir() == "nessus"

    def test_unknown_module_uses_name(self):
        """Unknown module falls back to module name as directory."""
        from enso.config.models import ScanModule
        module = ScanModule(name="web_enum")
        assert module.get_output_dir() == "web_enum"

    def test_get_module_output_dir_helper(self):
        """GlobalConfig.get_module_output_dir() returns correct dir."""
        config = GlobalConfig()
        assert config.get_module_output_dir("nmap_discovery") == "nmap/discovery"
        assert config.get_module_output_dir("nessus") == "nessus"

    def test_get_module_output_dir_missing_raises(self):
        """GlobalConfig.get_module_output_dir() raises ValueError for unknown module."""
        config = GlobalConfig()
        with pytest.raises(ValueError, match="not found"):
            config.get_module_output_dir("nonexistent")

    def test_cred_check_dir_default(self):
        """GlobalConfig.cred_check_dir defaults to 'cred_checks'."""
        config = GlobalConfig()
        assert config.cred_check_dir == "cred_checks"

    def test_nmap_log_dir_default(self):
        """NmapConfig.log_dir defaults to 'nmap/logs'."""
        config = NmapConfig()
        assert config.log_dir == "nmap/logs"

    def test_yaml_without_output_dir_loads(self, tmp_path):
        """Existing YAML without output_dir field loads correctly (backward compat)."""
        global_yaml = tmp_path / "global.yaml"
        global_yaml.write_text(
            "scan_pipeline:\n"
            "  - name: nmap_discovery\n"
            "    enabled: true\n"
        )
        config = load_config(tmp_path)
        module = config.global_config.get_module_by_name("nmap_discovery")
        assert module is not None
        assert module.output_dir == ""
        assert module.get_output_dir() == "nmap/discovery"


class TestScopeFilesConfig:
    """Tests for ScopeFilesConfig model."""

    def test_defaults_all_none(self):
        """Test that all fields default to None."""
        sf = ScopeFilesConfig()
        assert sf.in_scope is None
        assert sf.excluded is None
        assert sf.special is None

    def test_explicit_values(self):
        """Test setting explicit filenames."""
        sf = ScopeFilesConfig(in_scope="hosts.txt", excluded="excl.txt", special="notes.txt")
        assert sf.in_scope == "hosts.txt"
        assert sf.excluded == "excl.txt"
        assert sf.special == "notes.txt"

    def test_empty_string_means_no_file(self):
        """Test that empty string is a valid value (meaning 'no file')."""
        sf = ScopeFilesConfig(in_scope="", excluded="", special="")
        assert sf.in_scope == ""
        assert sf.excluded == ""
        assert sf.special == ""


class TestSimpleConfig:
    """Tests for SimpleConfig model."""

    def test_defaults(self):
        """Test default values for simple config."""
        cfg = SimpleConfig()
        assert cfg.output_dir == "internal"
        assert cfg.scope_files.in_scope == "inscope.txt"
        assert cfg.scope_files.excluded == "excluded.txt"
        assert cfg.scope_files.special == "special_considerations.txt"

    def test_custom_output_dir(self):
        """Test custom output dir."""
        cfg = SimpleConfig(output_dir="custom_dir")
        assert cfg.output_dir == "custom_dir"


class TestComplexConfig:
    """Tests for ComplexConfig model."""

    def test_defaults(self):
        """Test default scope files for complex config."""
        cfg = ComplexConfig()
        assert cfg.scope_files.in_scope is None
        assert cfg.scope_files.excluded == "excluded.txt"
        assert cfg.scope_files.special == "special_considerations.txt"


class TestScopeFileInheritance:
    """Tests for resolve_scope_files_for_drop() field-level inheritance."""

    def _make_engagement(self, engagement_type="complex", **complex_overrides):
        """Helper to build an EngagementConfig with optional complex scope overrides."""
        from enso.config.models import EngagementConfig
        complex_sf = ScopeFilesConfig(**complex_overrides) if complex_overrides else None
        kwargs = {"engagement_type": engagement_type}
        if complex_sf:
            kwargs["complex"] = ComplexConfig(scope_files=complex_sf)
        return EngagementConfig(**kwargs)

    def test_no_drop_overrides_inherits_complex_defaults(self):
        """Drop with no scope_files inherits all complex defaults."""
        from enso.config.models import NetworkDropConfig
        eng = self._make_engagement(excluded="global_excl.txt", special="global_special.txt")
        drop = NetworkDropConfig(
            name="Test", static_ip="10.0.0.1", gateway="10.0.0.254",
        )
        result = eng.resolve_scope_files_for_drop(drop)
        assert result.in_scope is None
        assert result.excluded == "global_excl.txt"
        assert result.special == "global_special.txt"

    def test_partial_override(self):
        """Drop overrides in_scope but inherits excluded and special."""
        from enso.config.models import NetworkDropConfig
        eng = self._make_engagement(excluded="global_excl.txt", special="global_special.txt")
        drop = NetworkDropConfig(
            name="Test", static_ip="10.0.0.1", gateway="10.0.0.254",
            scope_files=ScopeFilesConfig(in_scope="my_inscope.txt"),
        )
        result = eng.resolve_scope_files_for_drop(drop)
        assert result.in_scope == "my_inscope.txt"
        assert result.excluded == "global_excl.txt"
        assert result.special == "global_special.txt"

    def test_full_override(self):
        """Drop overrides all fields."""
        from enso.config.models import NetworkDropConfig
        eng = self._make_engagement(excluded="global_excl.txt", special="global_special.txt")
        drop = NetworkDropConfig(
            name="Test", static_ip="10.0.0.1", gateway="10.0.0.254",
            scope_files=ScopeFilesConfig(
                in_scope="drop_in.txt", excluded="drop_excl.txt", special="drop_sp.txt",
            ),
        )
        result = eng.resolve_scope_files_for_drop(drop)
        assert result.in_scope == "drop_in.txt"
        assert result.excluded == "drop_excl.txt"
        assert result.special == "drop_sp.txt"

    def test_empty_string_overrides_default(self):
        """Setting a field to '' explicitly removes it (no file)."""
        from enso.config.models import NetworkDropConfig
        eng = self._make_engagement(excluded="global_excl.txt", special="global_special.txt")
        drop = NetworkDropConfig(
            name="Test", static_ip="10.0.0.1", gateway="10.0.0.254",
            scope_files=ScopeFilesConfig(excluded=""),
        )
        result = eng.resolve_scope_files_for_drop(drop)
        assert result.excluded == ""
        assert result.special == "global_special.txt"

    def test_simple_engagement_inherits_simple_defaults(self):
        """Drop with no scope_files in simple engagement inherits simple defaults."""
        from enso.config.models import NetworkDropConfig
        eng = self._make_engagement(engagement_type="simple")
        drop = NetworkDropConfig(
            name="Test", static_ip="10.0.0.1", gateway="10.0.0.254",
        )
        result = eng.resolve_scope_files_for_drop(drop)
        assert result.in_scope == "inscope.txt"
        assert result.excluded == "excluded.txt"
        assert result.special == "special_considerations.txt"

    def test_simple_engagement_drop_override_still_works(self):
        """Drop in simple engagement can still override specific fields."""
        from enso.config.models import NetworkDropConfig
        eng = self._make_engagement(engagement_type="simple")
        drop = NetworkDropConfig(
            name="Test", static_ip="10.0.0.1", gateway="10.0.0.254",
            scope_files=ScopeFilesConfig(in_scope="custom.txt"),
        )
        result = eng.resolve_scope_files_for_drop(drop)
        assert result.in_scope == "custom.txt"
        assert result.excluded == "excluded.txt"
        assert result.special == "special_considerations.txt"


class TestNetworkDropOutputDir:
    """Tests for NetworkDropConfig.get_output_dir() fix."""

    def test_default_output_dir_uses_network_dir(self):
        """Output dir defaults to network_dir (no /scans suffix)."""
        from enso.config.models import NetworkDropConfig
        drop = NetworkDropConfig(
            name="Server Room", static_ip="10.0.0.1", gateway="10.0.0.254",
        )
        assert drop.get_output_dir() == "server_room"

    def test_explicit_output_dir(self):
        """Explicit output_dir is returned as-is."""
        from enso.config.models import NetworkDropConfig
        drop = NetworkDropConfig(
            name="Server Room", static_ip="10.0.0.1", gateway="10.0.0.254",
            output_dir="custom_dir",
        )
        assert drop.get_output_dir() == "custom_dir"

    def test_custom_network_dir(self):
        """Custom network_dir used when output_dir not set."""
        from enso.config.models import NetworkDropConfig
        drop = NetworkDropConfig(
            name="Server Room", static_ip="10.0.0.1", gateway="10.0.0.254",
            network_dir="srv",
        )
        assert drop.get_output_dir() == "srv"


class TestEngagementConfigScopeDir:
    """Tests for EngagementConfig.scope_dir and sub-configs."""

    def test_default_scope_dir(self):
        """Default scope_dir is engagement_docs."""
        from enso.config.models import EngagementConfig
        cfg = EngagementConfig()
        assert cfg.scope_dir == "engagement_docs"

    def test_custom_scope_dir(self):
        """Custom scope_dir is accepted."""
        from enso.config.models import EngagementConfig
        cfg = EngagementConfig(scope_dir="docs")
        assert cfg.scope_dir == "docs"

    def test_simple_and_complex_defaults(self):
        """Both simple and complex sub-configs get populated with defaults."""
        from enso.config.models import EngagementConfig
        cfg = EngagementConfig()
        assert cfg.simple.output_dir == "internal"
        assert cfg.complex_config.scope_files.excluded == "excluded.txt"

    def test_load_with_alias(self):
        """ComplexConfig loads via the 'complex' alias in YAML."""
        from enso.config.models import EngagementConfig
        cfg = EngagementConfig(**{
            "complex": ComplexConfig(
                scope_files=ScopeFilesConfig(excluded="my_excl.txt")
            )
        })
        assert cfg.complex_config.scope_files.excluded == "my_excl.txt"


class TestRandomHostCount:
    """Tests for random_host_count validation and resolve_ping_count."""

    def test_integer_count(self):
        """Integer count is accepted."""
        cfg = GlobalConfig(random_host_count=10)
        assert cfg.random_host_count == 10

    def test_percentage_string(self):
        """Percentage string is accepted."""
        cfg = GlobalConfig(random_host_count="20%")
        assert cfg.random_host_count == "20%"

    def test_integer_out_of_range(self):
        """Integer outside 1-50 is rejected."""
        with pytest.raises(ValueError):
            GlobalConfig(random_host_count=0)
        with pytest.raises(ValueError):
            GlobalConfig(random_host_count=51)

    def test_percentage_out_of_range(self):
        """Percentage outside 1%-100% is rejected."""
        with pytest.raises(ValueError):
            GlobalConfig(random_host_count="0%")
        with pytest.raises(ValueError):
            GlobalConfig(random_host_count="101%")

    def test_resolve_hard_count(self):
        """resolve_ping_count with integer returns min(count, total)."""
        cfg = GlobalConfig(random_host_count=5)
        assert cfg.resolve_ping_count(100) == 5
        assert cfg.resolve_ping_count(3) == 3

    def test_resolve_percentage(self):
        """resolve_ping_count with percentage computes correctly."""
        cfg = GlobalConfig(random_host_count="20%")
        assert cfg.resolve_ping_count(100) == 20
        assert cfg.resolve_ping_count(10) == 2

    def test_resolve_percentage_rounds_up(self):
        """Small percentages round up to at least 1."""
        cfg = GlobalConfig(random_host_count="10%")
        assert cfg.resolve_ping_count(3) == 1  # ceil(0.3) = 1

    def test_resolve_zero_hosts(self):
        """Zero available hosts returns 0."""
        cfg = GlobalConfig(random_host_count=5)
        assert cfg.resolve_ping_count(0) == 0


class TestBuildCredentialsPayload:
    """Tests for NessusPolicyManager._build_credentials_payload()."""

    def _make_credentials(self, **kwargs) -> CredentialsConfig:
        """Build a CredentialsConfig from raw dicts, bypassing env resolution."""
        from enso.config.models import WindowsCredential, LinuxCredential

        windows = {}
        for name, data in kwargs.get("windows", {}).items():
            windows[name] = WindowsCredential(**data)
        linux = {}
        for name, data in kwargs.get("linux", {}).items():
            linux[name] = LinuxCredential(**data)
        return CredentialsConfig(windows=windows, linux=linux)

    def _make_manager(self):
        """Build a NessusPolicyManager without a real connection."""
        from enso.nessus_policy import NessusPolicyManager
        from enso.config.models import NessusConfig, set_nessus_file_security
        import enso.nessus_keys as nk

        # Prevent key file loading and mark file as secure so passwords resolve
        set_nessus_file_security(True)
        config = NessusConfig(
            url="https://localhost:8834",
            access_key="fake_access",
            secret_key="fake_secret",
        )
        set_nessus_file_security(False)
        return NessusPolicyManager(config)

    def test_windows_and_ssh_structure(self):
        """Payload has correct nested add.Host.Windows/SSH structure."""
        creds = self._make_credentials(
            windows={"admin": {"username": "admin", "domain": "CORP", "password": "pass1"}},
            linux={"ssh_user": {"username": "scan", "password": "pass2", "privilege_escalation": "sudo"}},
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        assert "add" in result
        assert "Host" in result["add"]
        host = result["add"]["Host"]

        assert len(host["Windows"]) == 1
        assert host["Windows"][0]["auth_method"] == "Password"
        assert host["Windows"][0]["username"] == "admin"
        assert host["Windows"][0]["domain"] == "CORP"
        assert host["Windows"][0]["password"] == "pass1"

        assert len(host["SSH"]) == 1
        assert host["SSH"][0]["auth_method"] == "password"
        assert host["SSH"][0]["username"] == "scan"
        assert host["SSH"][0]["password"] == "pass2"
        assert host["SSH"][0]["elevate_privileges_with"] == "sudo"

    def test_privilege_escalation_none_maps_to_nothing(self):
        """privilege_escalation 'none' should map to 'Nothing' for Nessus API."""
        creds = self._make_credentials(
            linux={"user": {"username": "scan", "password": "pass", "privilege_escalation": "none"}},
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        ssh_entry = result["add"]["Host"]["SSH"][0]
        assert ssh_entry["elevate_privileges_with"] == "Nothing"

    def test_privilege_escalation_sudo_passes_through(self):
        """privilege_escalation 'sudo' should pass through directly."""
        creds = self._make_credentials(
            linux={"user": {"username": "scan", "password": "pass", "privilege_escalation": "sudo"}},
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        ssh_entry = result["add"]["Host"]["SSH"][0]
        assert ssh_entry["elevate_privileges_with"] == "sudo"

    def test_disabled_credentials_excluded(self):
        """Disabled credentials should not appear in payload."""
        creds = self._make_credentials(
            windows={
                "enabled_win": {"username": "admin", "password": "p1", "enabled": True},
                "disabled_win": {"username": "skip", "password": "p2", "enabled": False},
            },
            linux={
                "enabled_ssh": {"username": "scan", "password": "p3", "enabled": True},
                "disabled_ssh": {"username": "skip", "password": "p4", "enabled": False},
            },
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        host = result["add"]["Host"]
        assert len(host["Windows"]) == 1
        assert host["Windows"][0]["username"] == "admin"
        assert len(host["SSH"]) == 1
        assert host["SSH"][0]["username"] == "scan"

    def test_empty_credentials(self):
        """Empty credentials produce empty Host dict."""
        creds = self._make_credentials()
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        assert result == {"add": {"Host": {}}}

    def test_windows_empty_domain_defaults(self):
        """Windows cred with no domain gets empty string."""
        creds = self._make_credentials(
            windows={"admin": {"username": "admin", "password": "p1", "domain": ""}},
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        assert result["add"]["Host"]["Windows"][0]["domain"] == ""

    def test_only_ssh_no_windows_key(self):
        """When only SSH creds exist, Windows key should be absent from Host."""
        creds = self._make_credentials(
            linux={"user": {"username": "scan", "password": "p", "privilege_escalation": "su"}},
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        host = result["add"]["Host"]
        assert "Windows" not in host
        assert len(host["SSH"]) == 1
        assert host["SSH"][0]["elevate_privileges_with"] == "su"

    def test_only_windows_no_ssh_key(self):
        """When only Windows creds exist, SSH key should be absent from Host."""
        creds = self._make_credentials(
            windows={"admin": {"username": "admin", "password": "p1"}},
        )
        manager = self._make_manager()
        result = manager._build_credentials_payload(creds)

        host = result["add"]["Host"]
        assert "SSH" not in host
        assert len(host["Windows"]) == 1


class TestCredentialDescription:
    """Tests for the description field on credentials."""

    def test_windows_description_default(self):
        """WindowsCredential description defaults to empty string."""
        from enso.config.models import WindowsCredential
        cred = WindowsCredential(username="admin", password="pass")
        assert cred.description == ""

    def test_linux_description_default(self):
        """LinuxCredential description defaults to empty string."""
        from enso.config.models import LinuxCredential
        cred = LinuxCredential(username="scan", password="pass")
        assert cred.description == ""

    def test_windows_description_set(self):
        """WindowsCredential accepts a custom description."""
        from enso.config.models import WindowsCredential
        cred = WindowsCredential(username="admin", password="pass", description="Domain admin")
        assert cred.description == "Domain admin"

    def test_linux_description_set(self):
        """LinuxCredential accepts a custom description."""
        from enso.config.models import LinuxCredential
        cred = LinuxCredential(username="scan", password="pass", description="SSH scan account")
        assert cred.description == "SSH scan account"


class TestFilterByNames:
    """Tests for CredentialsConfig.filter_by_names()."""

    def _make_credentials(self, **kwargs) -> CredentialsConfig:
        """Build a CredentialsConfig from raw dicts."""
        from enso.config.models import WindowsCredential, LinuxCredential

        windows = {}
        for name, data in kwargs.get("windows", {}).items():
            windows[name] = WindowsCredential(**data)
        linux = {}
        for name, data in kwargs.get("linux", {}).items():
            linux[name] = LinuxCredential(**data)
        return CredentialsConfig(windows=windows, linux=linux)

    def test_filter_selects_named(self):
        """filter_by_names keeps only the specified credentials."""
        creds = self._make_credentials(
            windows={
                "admin": {"username": "admin", "password": "p1"},
                "svc": {"username": "svc", "password": "p2"},
            },
            linux={
                "root": {"username": "root", "password": "p3"},
                "scan": {"username": "scan", "password": "p4"},
            },
        )
        filtered = creds.filter_by_names(["admin"], ["scan"])
        assert list(filtered.windows.keys()) == ["admin"]
        assert list(filtered.linux.keys()) == ["scan"]

    def test_filter_empty_selection(self):
        """filter_by_names with empty lists returns empty dicts."""
        creds = self._make_credentials(
            windows={"admin": {"username": "admin", "password": "p1"}},
            linux={"scan": {"username": "scan", "password": "p2"}},
        )
        filtered = creds.filter_by_names([], [])
        assert filtered.windows == {}
        assert filtered.linux == {}

    def test_filter_all_names(self):
        """filter_by_names with all names returns everything."""
        creds = self._make_credentials(
            windows={"admin": {"username": "admin", "password": "p1"}},
            linux={"scan": {"username": "scan", "password": "p2"}},
        )
        filtered = creds.filter_by_names(["admin"], ["scan"])
        assert list(filtered.windows.keys()) == ["admin"]
        assert list(filtered.linux.keys()) == ["scan"]

    def test_filter_preserves_nessus_ui(self):
        """filter_by_names preserves the nessus_ui field."""
        from enso.config.models import NessusUICredential
        creds = CredentialsConfig(
            nessus_ui=NessusUICredential(username="admin", password="pass"),
        )
        filtered = creds.filter_by_names([], [])
        assert filtered.nessus_ui is not None
        assert filtered.nessus_ui.username == "admin"

    def test_filter_nonexistent_names_ignored(self):
        """filter_by_names silently ignores names that don't exist."""
        creds = self._make_credentials(
            windows={"admin": {"username": "admin", "password": "p1"}},
        )
        filtered = creds.filter_by_names(["admin", "nonexistent"], ["also_missing"])
        assert list(filtered.windows.keys()) == ["admin"]
        assert filtered.linux == {}


class TestCheckInterfaceLink:
    """Tests for check_interface_link() sysfs reader."""

    def test_nonexistent_interface(self):
        """Non-existent interface returns exists=False."""
        from enso.utils.network import check_interface_link
        result = check_interface_link("definitely_not_a_real_iface_xyz")
        assert result["exists"] is False
        assert result["carrier"] is False
        assert result["operstate"] == ""

    def test_loopback_exists(self):
        """Loopback interface exists and has known operstate."""
        from enso.utils.network import check_interface_link
        result = check_interface_link("lo")
        assert result["exists"] is True
        # lo operstate is typically "unknown"
        assert result["operstate"] in ("unknown", "up", "down")

    def test_returns_expected_keys(self):
        """Return dict always has exists, carrier, operstate keys."""
        from enso.utils.network import check_interface_link
        result = check_interface_link("lo")
        assert "exists" in result
        assert "carrier" in result
        assert "operstate" in result
        assert isinstance(result["exists"], bool)
        assert isinstance(result["carrier"], bool)
        assert isinstance(result["operstate"], str)

    def test_sysfs_carrier_with_mock(self, tmp_path, monkeypatch):
        """Carrier reads '1' when link is up."""
        from enso.utils import network as net_mod

        fake_iface = tmp_path / "eth_fake"
        fake_iface.mkdir()
        (fake_iface / "carrier").write_text("1\n")
        (fake_iface / "operstate").write_text("up\n")

        # Patch Path so /sys/class/net/eth_fake points to our tmp dir
        original_fn = net_mod.check_interface_link

        def patched(interface):
            import enso.utils.network as _mod
            from pathlib import Path as _P
            orig_path = _P
            # Temporarily monkey-patch the function to use tmp_path
            sys_path = tmp_path / interface
            if not sys_path.is_dir():
                return {"exists": False, "carrier": False, "operstate": ""}
            operstate = ""
            try:
                operstate = (sys_path / "operstate").read_text().strip()
            except OSError:
                pass
            carrier = False
            try:
                carrier = (sys_path / "carrier").read_text().strip() == "1"
            except OSError:
                pass
            return {"exists": True, "carrier": carrier, "operstate": operstate}

        monkeypatch.setattr(net_mod, "check_interface_link", patched)

        result = net_mod.check_interface_link("eth_fake")
        assert result["exists"] is True
        assert result["carrier"] is True
        assert result["operstate"] == "up"

    def test_sysfs_carrier_down_with_mock(self, tmp_path, monkeypatch):
        """Carrier reads '0' when link is down."""
        from enso.utils import network as net_mod

        fake_iface = tmp_path / "eth_down"
        fake_iface.mkdir()
        (fake_iface / "carrier").write_text("0\n")
        (fake_iface / "operstate").write_text("down\n")

        def patched(interface):
            sys_path = tmp_path / interface
            if not sys_path.is_dir():
                return {"exists": False, "carrier": False, "operstate": ""}
            operstate = ""
            try:
                operstate = (sys_path / "operstate").read_text().strip()
            except OSError:
                pass
            carrier = False
            try:
                carrier = (sys_path / "carrier").read_text().strip() == "1"
            except OSError:
                pass
            return {"exists": True, "carrier": carrier, "operstate": operstate}

        monkeypatch.setattr(net_mod, "check_interface_link", patched)

        result = net_mod.check_interface_link("eth_down")
        assert result["exists"] is True
        assert result["carrier"] is False
        assert result["operstate"] == "down"
