from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

from fastapi import UploadFile

from app.analyzers.artifact import ArtifactValidationError, validate_filename, validate_size
from app.config import Settings
from app.models.enums import ScanStatus
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.services.pipeline import ScanPipeline
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager
from app.utils.paths import sanitize_filename

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(
        self,
        settings: Settings,
        workspace: WorkspaceManager,
        store: JobStore,
        pipeline: ScanPipeline,
    ) -> None:
        self.settings = settings
        self.workspace = workspace
        self.store = store
        self.pipeline = pipeline
        self._tasks: dict[str, asyncio.Task[ScanJob]] = {}

    async def create_from_upload(self, upload: UploadFile) -> ScanJob:
        original = sanitize_filename(upload.filename or "upload.bin")
        try:
            validate_filename(original, self.settings)
        except ArtifactValidationError:
            raise
        scan_id = str(uuid.uuid4())
        suffix = Path(original).suffix.lower()
        stored_name = f"upload{suffix}"
        dest = self.workspace.upload_path(scan_id, stored_name)
        size = 0
        with dest.open("wb") as handle:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > self.settings.max_upload_bytes:
                    handle.close()
                    dest.unlink(missing_ok=True)
                    raise ArtifactValidationError(
                        f"Upload exceeds size limit of {self.settings.max_upload_bytes} bytes"
                    )
                handle.write(chunk)
        try:
            validate_size(size, self.settings)
        except ArtifactValidationError:
            dest.unlink(missing_ok=True)
            raise
        job = ScanJob(
            id=scan_id,
            filename=original,
            status=ScanStatus.QUEUED,
            artifact_path=str(dest),
            current_stage="queued",
            metadata={"content_type": upload.content_type, "size_bytes": size},
        )
        await self.store.save(job)
        self._tasks[scan_id] = asyncio.create_task(self.pipeline.run(job), name=f"scan-{scan_id}")
        return job

    async def create_from_path(self, file_path: Path) -> ScanJob:
        original = sanitize_filename(file_path.name)
        validate_filename(original, self.settings)
        if not file_path.is_file():
            raise ArtifactValidationError(f"File not found: {file_path}")
        scan_id = str(uuid.uuid4())
        suffix = Path(original).suffix.lower()
        dest = self.workspace.upload_path(scan_id, f"upload{suffix}")
        dest.write_bytes(file_path.read_bytes())
        validate_size(dest.stat().st_size, self.settings)
        job = ScanJob(
            id=scan_id,
            filename=original,
            status=ScanStatus.QUEUED,
            artifact_path=str(dest),
            current_stage="queued",
            metadata={"content_type": None, "size_bytes": dest.stat().st_size},
        )
        await self.store.save(job)
        return job

    async def run_inline(self, job: ScanJob, progress=None) -> ScanJob:
        return await self.pipeline.run(job, progress=progress)

    async def get(self, scan_id: str) -> ScanJob | None:
        return await self.store.get(scan_id)

    async def list_jobs(self) -> list[ScanJob]:
        return await self.store.list_jobs()

    async def cancel(self, scan_id: str) -> ScanJob | None:
        job = await self.store.get(scan_id)
        if job is None:
            return None
        job.cancel_requested = True
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
        if job.status not in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.PARTIAL}:
            job.status = ScanStatus.FAILED
            job.error = "Scan cancelled by user"
            job.current_stage = "cancelled"
        await self.store.save(job)
        return job

    def load_findings(self, scan_id: str) -> list[Finding]:
        path = self.workspace.scan_dir(scan_id, create=False) / "findings.json"
        if not path.exists():
            return []
        raw = self.workspace.read_json(path)
        return [Finding.model_validate(item) for item in raw]

    def report_path(self, scan_id: str) -> Path:
        return self.workspace.report_dir(scan_id) / "security-report.md"

    def list_artifacts(self, job: ScanJob) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        candidates = []
        if job.artifact_path:
            candidates.append(Path(job.artifact_path))
        scan_dir = self.workspace.scan_dir(job.id, create=False)
        if scan_dir.exists():
            candidates.extend(path for path in scan_dir.iterdir() if path.is_file())
        report = Path(job.report_path) if job.report_path else None
        if report:
            candidates.append(report)
        seen: set[str] = set()
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen or not path.exists() or not path.is_file():
                continue
            seen.add(resolved)
            items.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                    "kind": path.suffix.lstrip(".") or "file",
                }
            )
        return items
