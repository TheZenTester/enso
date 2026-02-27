"""Tests for the scan result exporter (collection, manifest, zip, differential)."""

import json
import os
import time
import zipfile
from pathlib import Path

import pytest

from enso.exporter import (
    MANIFEST_FILENAME,
    ExportManifest,
    ExportResult,
    FileEntry,
    ScanExporter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scans_dir(tmp_path: Path) -> Path:
    """Create a realistic scans/ directory structure."""
    scans = tmp_path / "scans"
    (scans / "nmap" / "discovery").mkdir(parents=True)
    (scans / "nmap" / "detailed").mkdir(parents=True)
    (scans / "nmap" / "logs").mkdir(parents=True)
    (scans / "nessus").mkdir(parents=True)
    return scans


def _write(path: Path, content: str = "test") -> Path:
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# ExportManifest
# ---------------------------------------------------------------------------

class TestExportManifest:
    """Tests for manifest persistence and differential tracking."""

    def test_load_missing_returns_empty(self, tmp_path):
        manifest = ExportManifest.load(tmp_path)
        assert manifest.exports == []

    def test_load_corrupt_json_returns_empty(self, tmp_path):
        (tmp_path / MANIFEST_FILENAME).write_text("{bad json!!")
        manifest = ExportManifest.load(tmp_path)
        assert manifest.exports == []

    def test_save_and_load_roundtrip(self, tmp_path):
        m = ExportManifest()
        m.record_export("test.zip", [
            FileEntry("nmap/discovery/10.0.0.1.xml", 1000.0, 4096),
        ])
        m.save(tmp_path)

        loaded = ExportManifest.load(tmp_path)
        assert len(loaded.exports) == 1
        assert loaded.exports[0]["zip_name"] == "test.zip"
        assert len(loaded.exports[0]["files"]) == 1

    def test_get_previously_exported_empty(self):
        m = ExportManifest()
        assert m.get_previously_exported() == {}

    def test_get_previously_exported_merges_latest_mtime(self):
        m = ExportManifest(exports=[
            {
                "timestamp": "2026-01-01T00:00:00",
                "zip_name": "a.zip",
                "files": [
                    {"relative_path": "x.xml", "mtime": 100.0, "size": 10},
                ],
            },
            {
                "timestamp": "2026-02-01T00:00:00",
                "zip_name": "b.zip",
                "files": [
                    {"relative_path": "x.xml", "mtime": 200.0, "size": 10},
                    {"relative_path": "y.xml", "mtime": 300.0, "size": 20},
                ],
            },
        ])
        exported = m.get_previously_exported()
        assert exported["x.xml"] == 200.0  # latest
        assert exported["y.xml"] == 300.0

    def test_record_export_appends(self):
        m = ExportManifest()
        m.record_export("a.zip", [FileEntry("f1", 1.0, 10)])
        m.record_export("b.zip", [FileEntry("f2", 2.0, 20)])
        assert len(m.exports) == 2
        assert m.exports[0]["zip_name"] == "a.zip"
        assert m.exports[1]["zip_name"] == "b.zip"


# ---------------------------------------------------------------------------
# ScanExporter -- file collection
# ---------------------------------------------------------------------------

class TestScanExporterCollect:
    """Tests for ScanExporter.collect_files()."""

    def test_collect_empty_dir(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")
        assert exporter.collect_files() == []

    def test_collect_nmap_discovery(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "10.0.0.1.xml")
        _write(scans / "nmap" / "discovery" / "10.0.0.1.gnmap")
        _write(scans / "nmap" / "discovery" / "10.0.0.1.nmap")

        files = ScanExporter(scans, "internal").collect_files()
        paths = [f.relative_path for f in files]
        assert "nmap/discovery/10.0.0.1.xml" in paths
        assert "nmap/discovery/10.0.0.1.gnmap" in paths
        assert "nmap/discovery/10.0.0.1.nmap" in paths

    def test_collect_nmap_detailed(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "detailed" / "10.0.0.1.xml")

        files = ScanExporter(scans, "internal").collect_files()
        assert any(f.relative_path == "nmap/detailed/10.0.0.1.xml" for f in files)

    def test_collect_nmap_logs(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "logs" / "nmap_discovery_10.0.0.1.log")

        files = ScanExporter(scans, "internal").collect_files()
        assert any("logs" in f.relative_path for f in files)

    def test_collect_nessus(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nessus" / "internal_20260226.nessus")

        files = ScanExporter(scans, "internal").collect_files()
        assert any(f.relative_path == "nessus/internal_20260226.nessus" for f in files)

    def test_collect_ignores_dotfiles(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nessus" / ".enso_exports.json")
        _write(scans / "nessus" / "scan.nessus")

        files = ScanExporter(scans, "internal").collect_files()
        paths = [f.relative_path for f in files]
        assert "nessus/scan.nessus" in paths
        assert not any(".enso_exports" in p for p in paths)

    def test_collect_includes_any_extension(self, tmp_path):
        """Auto-discovery includes all file types, not just known extensions."""
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "10.0.0.1.tmp")
        _write(scans / "nmap" / "discovery" / "10.0.0.1.bak")
        _write(scans / "nmap" / "discovery" / "10.0.0.1.xml")

        files = ScanExporter(scans, "internal").collect_files()
        assert len(files) == 3

    def test_collect_all_subdirs(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "a.xml")
        _write(scans / "nmap" / "detailed" / "b.xml")
        _write(scans / "nmap" / "logs" / "c.log")
        _write(scans / "nessus" / "d.nessus")

        files = ScanExporter(scans, "internal").collect_files()
        assert len(files) == 4

    def test_collect_missing_subdirs(self, tmp_path):
        """Missing subdirectories don't cause errors."""
        scans = tmp_path / "scans"
        scans.mkdir()
        files = ScanExporter(scans, "internal").collect_files()
        assert files == []

    def test_collect_autodiscovers_unknown_subdirs(self, tmp_path):
        """New module directories are automatically discovered."""
        scans = _make_scans_dir(tmp_path)
        (scans / "web_enum").mkdir()
        _write(scans / "web_enum" / "results.json")
        _write(scans / "web_enum" / "report.html")
        _write(scans / "nmap" / "discovery" / "a.xml")

        files = ScanExporter(scans, "internal").collect_files()
        paths = [f.relative_path for f in files]
        assert "web_enum/results.json" in paths
        assert "web_enum/report.html" in paths
        assert len(files) == 3

    def test_collect_exclude_dirs(self, tmp_path):
        """Directories in exclude_dirs are skipped."""
        scans = _make_scans_dir(tmp_path)
        (scans / "temp_work").mkdir()
        _write(scans / "temp_work" / "scratch.txt")
        _write(scans / "nmap" / "discovery" / "a.xml")

        files = ScanExporter(scans, "internal", exclude_dirs=["temp_work"]).collect_files()
        paths = [f.relative_path for f in files]
        assert "nmap/discovery/a.xml" in paths
        assert not any("temp_work" in p for p in paths)

    def test_collect_exclude_dirs_multiple(self, tmp_path):
        """Multiple directories can be excluded."""
        scans = _make_scans_dir(tmp_path)
        (scans / "scratch").mkdir()
        (scans / "debug").mkdir()
        _write(scans / "scratch" / "a.txt")
        _write(scans / "debug" / "b.txt")
        _write(scans / "nessus" / "scan.nessus")

        files = ScanExporter(scans, "internal", exclude_dirs=["scratch", "debug"]).collect_files()
        assert len(files) == 1
        assert files[0].relative_path == "nessus/scan.nessus"

    def test_collect_ignores_dot_directories(self, tmp_path):
        """Files inside dot-directories (e.g. .git/) are skipped."""
        scans = _make_scans_dir(tmp_path)
        (scans / ".hidden_dir").mkdir()
        _write(scans / ".hidden_dir" / "secret.txt")
        _write(scans / "nmap" / "discovery" / "a.xml")

        files = ScanExporter(scans, "internal").collect_files()
        paths = [f.relative_path for f in files]
        assert len(files) == 1
        assert not any(".hidden_dir" in p for p in paths)


# ---------------------------------------------------------------------------
# ScanExporter -- differential filtering
# ---------------------------------------------------------------------------

class TestScanExporterFilter:
    """Tests for ScanExporter.filter_new_or_changed()."""

    def test_filter_all_new(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")
        manifest = ExportManifest()

        files = [
            FileEntry("nmap/discovery/10.0.0.1.xml", 1000.0, 100),
            FileEntry("nessus/scan.nessus", 2000.0, 200),
        ]
        result = exporter.filter_new_or_changed(files, manifest)
        assert len(result) == 2

    def test_filter_none_changed(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")

        files = [FileEntry("x.xml", 1000.0, 100)]
        manifest = ExportManifest()
        manifest.record_export("prev.zip", files)

        result = exporter.filter_new_or_changed(files, manifest)
        assert result == []

    def test_filter_some_modified(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")

        old_files = [FileEntry("x.xml", 1000.0, 100)]
        manifest = ExportManifest()
        manifest.record_export("prev.zip", old_files)

        current = [
            FileEntry("x.xml", 1000.0, 100),  # unchanged
            FileEntry("y.xml", 2000.0, 200),  # new
            FileEntry("x.xml", 1001.0, 100),  # but wait, duplicate path
        ]
        # Actually test with distinct files
        current = [
            FileEntry("x.xml", 1000.0, 100),  # unchanged
            FileEntry("y.xml", 2000.0, 200),  # new
        ]
        result = exporter.filter_new_or_changed(current, manifest)
        assert len(result) == 1
        assert result[0].relative_path == "y.xml"

    def test_filter_modified_mtime(self, tmp_path):
        """A file with a newer mtime is included."""
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")

        manifest = ExportManifest()
        manifest.record_export("prev.zip", [FileEntry("x.xml", 1000.0, 100)])

        current = [FileEntry("x.xml", 1500.0, 150)]  # newer mtime
        result = exporter.filter_new_or_changed(current, manifest)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# ScanExporter -- zip creation
# ---------------------------------------------------------------------------

class TestScanExporterZip:
    """Tests for ScanExporter.create_zip()."""

    def test_create_zip_basic(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "10.0.0.1.xml", "<nmap/>")

        exporter = ScanExporter(scans, "internal")
        files = exporter.collect_files()
        export_dir = tmp_path / "exports"

        result = exporter.create_zip(files, export_dir)

        assert result.zip_path.exists()
        assert result.file_count == 1
        assert result.zip_size > 0
        assert "enso_export_internal_" in result.zip_path.name
        assert result.zip_path.suffix == ".zip"

    def test_create_zip_structure(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "10.0.0.1.xml", "<disc/>")
        _write(scans / "nmap" / "detailed" / "10.0.0.1.xml", "<deep/>")
        _write(scans / "nessus" / "scan.nessus", "<nessus/>")

        exporter = ScanExporter(scans, "internal")
        files = exporter.collect_files()
        result = exporter.create_zip(files, tmp_path / "out")

        with zipfile.ZipFile(result.zip_path) as zf:
            names = zf.namelist()
            assert "nmap/discovery/10.0.0.1.xml" in names
            assert "nmap/detailed/10.0.0.1.xml" in names
            assert "nessus/scan.nessus" in names

    def test_create_zip_empty_raises(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")

        with pytest.raises(ValueError, match="No files"):
            exporter.create_zip([], tmp_path / "out")

    def test_create_zip_creates_export_dir(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "a.xml")

        exporter = ScanExporter(scans, "internal")
        files = exporter.collect_files()
        export_dir = tmp_path / "new" / "nested" / "dir"

        result = exporter.create_zip(files, export_dir)
        assert export_dir.is_dir()
        assert result.zip_path.exists()

    def test_create_zip_is_differential_flag(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nmap" / "discovery" / "a.xml")

        exporter = ScanExporter(scans, "internal")
        files = exporter.collect_files()

        result_full = exporter.create_zip(files, tmp_path / "out1", full_export=True)
        assert result_full.is_differential is False

        result_diff = exporter.create_zip(files, tmp_path / "out2", full_export=False)
        assert result_diff.is_differential is True


# ---------------------------------------------------------------------------
# ScanExporter -- nessus files
# ---------------------------------------------------------------------------

class TestScanExporterNessus:
    """Tests for ScanExporter.get_nessus_files()."""

    def test_get_nessus_files_empty(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        assert ScanExporter(scans, "internal").get_nessus_files() == []

    def test_get_nessus_files_no_dir(self, tmp_path):
        scans = tmp_path / "scans"
        scans.mkdir()
        assert ScanExporter(scans, "internal").get_nessus_files() == []

    def test_get_nessus_files_found(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        _write(scans / "nessus" / "b_scan.nessus")
        _write(scans / "nessus" / "a_scan.nessus")

        result = ScanExporter(scans, "internal").get_nessus_files()
        assert len(result) == 2
        assert result[0].name == "a_scan.nessus"  # sorted

    def test_get_nessus_files_custom_dir(self, tmp_path):
        """get_nessus_files() with a non-default nessus_dir parameter."""
        scans = _make_scans_dir(tmp_path)
        custom = scans / "vuln_scans"
        custom.mkdir()
        _write(custom / "scan.nessus")

        result = ScanExporter(scans, "internal").get_nessus_files("vuln_scans")
        assert len(result) == 1
        assert result[0].name == "scan.nessus"

    def test_get_nessus_files_custom_dir_missing(self, tmp_path):
        """get_nessus_files() with non-existent custom dir returns empty."""
        scans = _make_scans_dir(tmp_path)
        result = ScanExporter(scans, "internal").get_nessus_files("nonexistent")
        assert result == []


# ---------------------------------------------------------------------------
# Integration: full export then differential
# ---------------------------------------------------------------------------

class TestExportIntegration:
    """End-to-end: collect -> filter -> zip -> manifest update."""

    def test_full_export_then_differential(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        export_dir = tmp_path / "exports"
        exporter = ScanExporter(scans, "internal")

        # Initial files
        _write(scans / "nmap" / "discovery" / "10.0.0.1.xml", "<a/>")
        _write(scans / "nmap" / "discovery" / "10.0.0.2.xml", "<b/>")

        # First export: everything
        all_files = exporter.collect_files()
        manifest = ExportManifest.load(scans)
        new_files = exporter.filter_new_or_changed(all_files, manifest)
        assert len(new_files) == 2

        result1 = exporter.create_zip(new_files, export_dir)
        manifest.record_export(result1.zip_path.name, new_files)
        manifest.save(scans)

        # Add one new file
        _write(scans / "nmap" / "discovery" / "10.0.0.3.xml", "<c/>")

        # Second export: differential
        all_files = exporter.collect_files()
        manifest = ExportManifest.load(scans)
        new_files = exporter.filter_new_or_changed(all_files, manifest)
        assert len(new_files) == 1
        assert new_files[0].relative_path == "nmap/discovery/10.0.0.3.xml"

    def test_full_flag_ignores_manifest(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        export_dir = tmp_path / "exports"
        exporter = ScanExporter(scans, "internal")

        _write(scans / "nmap" / "discovery" / "a.xml")

        # Record a previous export
        manifest = ExportManifest()
        all_files = exporter.collect_files()
        manifest.record_export("prev.zip", all_files)
        manifest.save(scans)

        # With --full, filter returns nothing (but we skip filtering)
        manifest = ExportManifest.load(scans)
        filtered = exporter.filter_new_or_changed(all_files, manifest)
        assert len(filtered) == 0

        # Full export uses all_files directly, not filtered
        result = exporter.create_zip(all_files, export_dir, full_export=True)
        assert result.file_count == 1
        assert result.is_differential is False

    def test_manifest_persists_across_exports(self, tmp_path):
        scans = _make_scans_dir(tmp_path)
        exporter = ScanExporter(scans, "internal")

        _write(scans / "nmap" / "discovery" / "a.xml")

        # First export
        manifest = ExportManifest.load(scans)
        manifest.record_export("first.zip", exporter.collect_files())
        manifest.save(scans)

        # Second export
        _write(scans / "nmap" / "discovery" / "b.xml")
        manifest = ExportManifest.load(scans)
        manifest.record_export("second.zip", exporter.collect_files())
        manifest.save(scans)

        # Verify both exports recorded
        final = ExportManifest.load(scans)
        assert len(final.exports) == 2
        assert final.exports[0]["zip_name"] == "first.zip"
        assert final.exports[1]["zip_name"] == "second.zip"
