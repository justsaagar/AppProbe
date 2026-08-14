"""Isolated per-scan workspace layout."""

from __future__ import annotations

from pathlib import Path

from app.utils.paths import safe_join


class ScanWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.upload = root / "upload"
        self.extract = root / "extract"
        self.artifacts = root / "artifacts"
        self.screenshots = root / "screenshots"
        self.logs = root / "logs"
        self.report = root / "report"
        self.tools = root / "tools"
        self.findings_dir = root / "findings"
        self.evidence = root / "evidence"

    def ensure(self) -> None:
        for path in (
            self.root,
            self.upload,
            self.extract,
            self.artifacts,
            self.screenshots,
            self.logs,
            self.report,
            self.tools,
            self.findings_dir,
            self.evidence,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def path(self, *parts: str) -> Path:
        return safe_join(self.root, *parts)

    def tool_dir(self, name: str) -> Path:
        """Isolated output directory for one external tool within this scan."""
        path = safe_join(self.tools, name)
        path.mkdir(parents=True, exist_ok=True)
        return path


class WorkspaceManager:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.uploads = base / "uploads"
        self.scans = base / "scans"
        self.artifacts = base / "artifacts"
        self.screenshots = base / "screenshots"
        self.logs = base / "logs"
        self.reports = base / "reports"

    def ensure_base(self) -> None:
        for path in (
            self.base,
            self.uploads,
            self.scans,
            self.artifacts,
            self.screenshots,
            self.logs,
            self.reports,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def for_scan(self, scan_id: str) -> ScanWorkspace:
        workspace = ScanWorkspace(self.scans / scan_id)
        workspace.ensure()
        (self.reports / scan_id).mkdir(parents=True, exist_ok=True)
        (self.uploads / scan_id).mkdir(parents=True, exist_ok=True)
        (self.artifacts / scan_id).mkdir(parents=True, exist_ok=True)
        return workspace

    def report_path(self, scan_id: str) -> Path:
        return self.reports / scan_id / "security-report.md"
