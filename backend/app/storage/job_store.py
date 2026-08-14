from __future__ import annotations

import asyncio
from pathlib import Path

from app.models.scan_job import ScanJob
from app.storage.workspace import WorkspaceManager


class JobStore:
    """Persists scan jobs as JSON under the scan workspace."""

    def __init__(self, workspace: WorkspaceManager) -> None:
        self.workspace = workspace
        self._lock = asyncio.Lock()
        self._jobs: dict[str, ScanJob] = {}

    def _job_path(self, scan_id: str) -> Path:
        return self.workspace.job_file(scan_id)

    async def save(self, job: ScanJob) -> ScanJob:
        async with self._lock:
            self._jobs[job.id] = job
            self.workspace.write_json(self._job_path(job.id), job.model_dump(mode="json"))
            return job

    async def get(self, scan_id: str) -> ScanJob | None:
        async with self._lock:
            if scan_id in self._jobs:
                return self._jobs[scan_id]
            path = self._job_path(scan_id)
            if not path.exists():
                return None
            job = ScanJob.model_validate(self.workspace.read_json(path))
            self._jobs[scan_id] = job
            return job

    async def list_jobs(self) -> list[ScanJob]:
        async with self._lock:
            self._hydrate_from_disk()
            return sorted(self._jobs.values(), key=lambda job: job.created_at, reverse=True)

    def _hydrate_from_disk(self) -> None:
        scans_root = self.workspace.settings.scans_dir
        if not scans_root.exists():
            return
        for child in scans_root.iterdir():
            job_file = child / "job.json"
            if child.name in self._jobs or not job_file.exists():
                continue
            self._jobs[child.name] = ScanJob.model_validate(self.workspace.read_json(job_file))
