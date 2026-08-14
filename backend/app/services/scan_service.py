"""Application service for creating and querying scans."""

from __future__ import annotations

import uuid
from pathlib import Path

import aiofiles

from app.analyzers.validator import (
    ArtifactValidationError,
    validate_content_type,
    validate_size,
    validate_upload_name,
)
from app.config import Settings
from app.models.scan_job import ScanJob
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager
from app.utils.paths import safe_join


class ScanService:
    def __init__(self, store: JobStore, workspace: WorkspaceManager, settings: Settings) -> None:
        self.store = store
        self.workspace = workspace
        self.settings = settings

    async def create_from_upload(
        self,
        *,
        filename: str,
        content_type: str | None,
        data: bytes,
    ) -> ScanJob:
        cleaned = validate_upload_name(filename)
        validate_content_type(content_type)
        validate_size(len(data), self.settings.max_upload_bytes)
        scan_id = uuid.uuid4().hex
        self.workspace.ensure_base()
        scan_ws = self.workspace.for_scan(scan_id)
        artifact_path = scan_ws.upload / cleaned
        artifact_path.write_bytes(data)
        # Also keep a copy under workspace/uploads/<id>/ for the documented layout.
        upload_copy = safe_join(self.workspace.uploads / scan_id, cleaned)
        upload_copy.write_bytes(data)
        job = ScanJob(
            id=scan_id,
            filename=cleaned,
            artifact_path=str(artifact_path),
        )
        await self.store.create(job)
        return job

    async def create_from_path(self, source: Path) -> ScanJob:
        if not source.is_file():
            raise ArtifactValidationError(f"file not found: {source}")
        data = source.read_bytes()
        return await self.create_from_upload(
            filename=source.name,
            content_type="application/octet-stream",
            data=data,
        )

    async def get(self, scan_id: str) -> ScanJob | None:
        return await self.store.get(scan_id)

    async def list(self) -> list[ScanJob]:
        return await self.store.list()

    async def cancel(self, scan_id: str) -> ScanJob | None:
        job = await self.store.get(scan_id)
        if job is None:
            return None
        job.cancel_requested = True
        await self.store.save(job)
        return job

    async def save_upload_stream(self, dest: Path, stream) -> int:
        dest.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        async with aiofiles.open(dest, "wb") as handle:
            while True:
                chunk = await stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > self.settings.max_upload_bytes:
                    raise ArtifactValidationError(
                        f"file exceeds size limit of {self.settings.max_upload_bytes} bytes"
                    )
                await handle.write(chunk)
        return size
