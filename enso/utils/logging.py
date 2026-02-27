"""Structured logging setup for ENSO."""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Literal

from rich.console import Console
from rich.logging import RichHandler


_LOG_FORMAT = "%(message)s"
_FILE_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def setup_logging(
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO",
    log_dir: Path | None = None,
) -> None:
    """Configure logging with Rich console handler and optional file handler.
    
    Args:
        level: Logging level string
        log_dir: Optional directory for log files. If provided, creates timestamped log file.
    """
    log_level = getattr(logging, level.upper())
    
    # Clear existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(log_level)
    
    # Rich console handler for pretty output
    console = Console(stderr=True)
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
    )
    rich_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    rich_handler.setLevel(log_level)
    root_logger.addHandler(rich_handler)
    
    # File handler for persistent logs
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"enso_{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(_FILE_LOG_FORMAT))
        file_handler.setLevel(logging.DEBUG)  # Always capture DEBUG in file
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given module name.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


class ScanLogger:
    """Dedicated logger for streaming scan output to files.
    
    This replaces the old `screen` attachment workflow by capturing
    raw Nmap/Nessus output directly to log files for troubleshooting.
    """
    
    def __init__(self, log_dir: Path, scan_type: str, target: str):
        """Initialize a scan logger.
        
        Args:
            log_dir: Directory for scan logs
            scan_type: Type of scan (e.g., 'nmap_discovery', 'nmap_deep', 'nessus')
            target: Target identifier (IP or network name)
        """
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        sanitized_target = target.replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"{scan_type}_{sanitized_target}_{timestamp}.log"
        
        self._file_handle = open(self.log_file, "w")
    
    def write(self, data: str) -> None:
        """Write data to the scan log."""
        self._file_handle.write(data)
        self._file_handle.flush()
    
    def close(self) -> None:
        """Close the log file."""
        self._file_handle.close()
    
    def __enter__(self) -> "ScanLogger":
        return self
    
    def __exit__(self, *args) -> None:
        self.close()
