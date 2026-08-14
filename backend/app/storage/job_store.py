"""JSON-backed scan job store with in-memory cache."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.models.scan_job import ScanJob


class JobStore:
    async def create(self, job: ScanJob) -> ScanJob: ...
    async def get(self, scan_id: str) -> ScanJob | None: ...
    async def list(self) -> list[ScanJob]: ...
    async def save(self, job: ScanJob) -> ScanJob: ...


class JsonJobStore(JobStore):
    def __init__(self, path: Path) -> None:
        self.path = path
        self._jobs: dict[str, ScanJob] = {}
        self._lock = asyncio.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for item in raw.get("jobs", []):
            job = ScanJob.model_validate(item)
            self._jobs[job.id] = job

    def _dump_unlocked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"jobs": [job.model_dump(mode="json") for job in self._jobs.values()]}
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        tmp.replace(self.path)

    async def create(self, job: ScanJob) -> ScanJob:
        async with self._lock:
            self._jobs[job.id] = job
            self._dump_unlocked()
        return job

    async def get(self, scan_id: str) -> ScanJob | None:
        async with self._lock:
            job = self._jobs.get(scan_id)
            return job.model_copy(deep=True) if job else None

    async def list(self) -> list[ScanJob]:
        async with self._lock:
            jobs = [job.model_copy(deep=True) for job in self._jobs.values()]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs

    async def save(self, job: ScanJob) -> ScanJob:
        async with self._lock:
            self._jobs[job.id] = job
            self._dump_unlocked()
        return job
