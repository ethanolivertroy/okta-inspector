"""Output manager — handles directory creation, file writing, and archiving."""

from __future__ import annotations

import json
import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default compliance sub-directories
_COMPLIANCE_SUBDIRS = (
    "fedramp",
    "disa_stig",
    "general_security",
    "irap",
    "ismap",
    "soc2",
    "pci_dss",
    "cmmc",
)


class OutputManager:
    """Creates the output directory tree and writes reports."""

    def __init__(self, base_dir: Path | None = None) -> None:
        if base_dir is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_dir = Path(f"okta_audit_results_{ts}")
        self.base_dir = base_dir
        self._ensure_dirs()

    # ------------------------------------------------------------------
    # Directory helpers
    # ------------------------------------------------------------------

    def _ensure_dirs(self) -> None:
        self.base_dir.mkdir(exist_ok=True)
        (self.base_dir / "core_data").mkdir(exist_ok=True)
        (self.base_dir / "analysis").mkdir(exist_ok=True)
        compliance = self.base_dir / "compliance"
        compliance.mkdir(exist_ok=True)
        for sub in _COMPLIANCE_SUBDIRS:
            (compliance / sub).mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # File writers
    # ------------------------------------------------------------------

    def save_json(self, data: Any, filename: str, subdir: str = "core_data") -> Path:
        """Serialize *data* to a JSON file inside *subdir*."""
        path = self.base_dir / subdir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def save_text(self, content: str, *parts: str) -> Path:
        """Write *content* to a file at ``base_dir / parts``."""
        path = self.base_dir / Path(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def save_markdown(self, content: str, *parts: str) -> Path:
        """Convenience alias for ``save_text`` for Markdown files."""
        return self.save_text(content, *parts)

    def save_script(self, content: str, *parts: str) -> Path:
        """Write a shell script and mark it executable."""
        path = self.save_text(content, *parts)
        os.chmod(path, 0o755)
        return path

    # ------------------------------------------------------------------
    # Archiving
    # ------------------------------------------------------------------

    def create_archive(self) -> Path:
        """Create a ZIP archive of the entire output tree.  Returns the archive path."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_path = self.base_dir.parent / f"okta_audit_{ts}.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(self.base_dir):
                for file in files:
                    full = Path(root) / file
                    zf.write(full, full.relative_to(self.base_dir.parent))
        return archive_path
