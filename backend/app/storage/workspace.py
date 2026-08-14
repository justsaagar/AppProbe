from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config import Settings
from app.utils.paths import safe_join


class WorkspaceManager:
    """Isolated on-disk layout for a single scan."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = settings.workspace_dir
        self._ensure_roots()

    def _ensure_roots(self) -> None:
        for path in (
            self.settings.uploads_dir,
            self.settings.scans_dir,
            self.settings.artifacts_dir,
            self.settings.screenshots_dir,
            self.settings.logs_dir,
            self.settings.reports_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def scan_dir(self, scan_id: str, *, create: bool = True) -> Path:
        path = safe_join(self.settings.scans_dir, scan_id)
        if create:
            path.mkdir(parents=True, exist_ok=True)
        return path

    def upload_path(self, scan_id: str, stored_name: str) -> Path:
        directory = safe_join(self.settings.uploads_dir, scan_id)
        directory.mkdir(parents=True, exist_ok=True)
        return safe_join(directory, stored_name)

    def report_dir(self, scan_id: str) -> Path:
        path = safe_join(self.settings.reports_dir, scan_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def artifacts_dir(self, scan_id: str) -> Path:
        path = safe_join(self.settings.artifacts_dir, scan_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def job_file(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id, create=False) / "job.json"

    def write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def read_json(self, path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))
