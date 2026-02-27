"""Scan result exporter with differential tracking."""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .utils.logging import get_logger

logger = get_logger(__name__)

MANIFEST_FILENAME = ".enso_exports.json"


@dataclass
class FileEntry:
    """A single file tracked in the export manifest."""

    relative_path: str  # relative to scans_dir
    mtime: float
    size: int


@dataclass
class ExportResult:
    """Result of an export operation."""

    zip_path: Path
    file_count: int
    total_size: int  # uncompressed bytes
    zip_size: int  # compressed bytes
    is_differential: bool


@dataclass
class ExportManifest:
    """Tracks previously exported files for differential export.

    Stored as ``.enso_exports.json`` in the scans/ directory.
    """

    exports: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, scans_dir: Path) -> ExportManifest:
        """Load manifest from disk, or return empty if not found."""
        manifest_path = scans_dir / MANIFEST_FILENAME
        if not manifest_path.exists():
            return cls()
        try:
            data = json.loads(manifest_path.read_text())
            return cls(exports=data.get("exports", []))
        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning(f"Corrupt manifest, starting fresh: {e}")
            return cls()

    def save(self, scans_dir: Path) -> None:
        """Write manifest to disk."""
        manifest_path = scans_dir / MANIFEST_FILENAME
        manifest_path.write_text(json.dumps({"exports": self.exports}, indent=2))
        logger.debug(f"Manifest saved: {manifest_path}")

    def get_previously_exported(self) -> dict[str, float]:
        """Return ``{relative_path: latest_mtime}`` across all exports."""
        exported: dict[str, float] = {}
        for export_entry in self.exports:
            for f in export_entry.get("files", []):
                path = f["relative_path"]
                mtime = f["mtime"]
                if path not in exported or mtime > exported[path]:
                    exported[path] = mtime
        return exported

    def record_export(self, zip_name: str, files: list[FileEntry]) -> None:
        """Record a completed export in the manifest."""
        self.exports.append(
            {
                "timestamp": datetime.now().isoformat(),
                "zip_name": zip_name,
                "files": [
                    {
                        "relative_path": f.relative_path,
                        "mtime": f.mtime,
                        "size": f.size,
                    }
                    for f in files
                ],
            }
        )


class ScanExporter:
    """Collects scan files and packages them into a zip archive.

    Uses auto-discovery: every file under ``scans_dir`` is included unless
    it is a dotfile or lives inside a directory listed in *exclude_dirs*.
    """

    def __init__(
        self,
        scans_dir: Path,
        network_id: str,
        exclude_dirs: list[str] | None = None,
    ) -> None:
        self.scans_dir = scans_dir
        self.network_id = network_id
        self.exclude_dirs: set[str] = set(exclude_dirs or [])

    def collect_files(self) -> list[FileEntry]:
        """Recursively discover all exportable files under scans_dir.

        Skips dotfiles/dotdirs and any top-level directory whose name
        appears in *exclude_dirs*.
        """
        entries: list[FileEntry] = []

        for file_path in self.scans_dir.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip dotfiles and files inside dot-directories
            rel = file_path.relative_to(self.scans_dir)
            if any(part.startswith(".") for part in rel.parts):
                continue
            # Skip excluded top-level directories
            if rel.parts[0] in self.exclude_dirs:
                continue

            st = file_path.stat()
            entries.append(
                FileEntry(
                    relative_path=str(rel),
                    mtime=st.st_mtime,
                    size=st.st_size,
                )
            )

        entries.sort(key=lambda e: e.relative_path)
        return entries

    def filter_new_or_changed(
        self, files: list[FileEntry], manifest: ExportManifest
    ) -> list[FileEntry]:
        """Filter to only files that are new or changed since last export."""
        previously_exported = manifest.get_previously_exported()

        new_files = []
        for f in files:
            prev_mtime = previously_exported.get(f.relative_path)
            if prev_mtime is None or f.mtime > prev_mtime:
                new_files.append(f)

        return new_files

    def create_zip(
        self,
        files: list[FileEntry],
        export_dir: Path,
        full_export: bool = False,
    ) -> ExportResult:
        """Create a zip archive containing the specified files.

        Args:
            files: Files to include in the zip.
            export_dir: Directory to write the zip file to.
            full_export: Whether this is a full (non-differential) export.

        Returns:
            ExportResult with zip path and statistics.

        Raises:
            ValueError: If no files to export.
        """
        if not files:
            raise ValueError("No files to export")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"enso_export_{self.network_id}_{timestamp}.zip"
        zip_path = export_dir / zip_name

        export_dir.mkdir(parents=True, exist_ok=True)

        total_size = 0
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry in files:
                abs_path = self.scans_dir / entry.relative_path
                if abs_path.exists():
                    zf.write(abs_path, arcname=entry.relative_path)
                    total_size += entry.size

        zip_size = zip_path.stat().st_size

        logger.info(
            f"Created {zip_name}: {len(files)} files, "
            f"{total_size / 1024:.1f} KB -> {zip_size / 1024:.1f} KB compressed"
        )

        return ExportResult(
            zip_path=zip_path,
            file_count=len(files),
            total_size=total_size,
            zip_size=zip_size,
            is_differential=not full_export,
        )

    def get_nessus_files(self, nessus_dir: str = "nessus") -> list[Path]:
        """Return list of existing .nessus files in the nessus directory.

        Args:
            nessus_dir: Nessus output directory name relative to scans_dir.
        """
        full_path = self.scans_dir / nessus_dir
        if not full_path.is_dir():
            return []
        return sorted(full_path.glob("*.nessus"))
