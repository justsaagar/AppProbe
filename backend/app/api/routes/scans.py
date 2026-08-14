"""HTTP API for scan jobs."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse

from app.analyzers.validator import ArtifactValidationError
from app.models.enums import ScanStatus
from app.models.scan_job import ScanJob
from app.schemas.scan import (
    ArtifactEntry,
    ArtifactList,
    FindingList,
    ReportResponse,
    ScanDetail,
    ScanSummary,
)
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_service import ScanService
from app.storage.workspace import WorkspaceManager
from app.utils.paths import UnsafePathError, safe_join

router = APIRouter(prefix="/api")


def _service(request: Request) -> ScanService:
    return request.app.state.scan_service


def _orchestrator(request: Request) -> ScanOrchestrator:
    return request.app.state.orchestrator


def _workspace(request: Request) -> WorkspaceManager:
    return request.app.state.workspace


def to_summary(job: ScanJob) -> ScanSummary:
    return ScanSummary(
        id=job.id,
        filename=job.filename,
        platform=job.platform,
        artifact_kind=job.artifact_kind,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        progress=job.progress,
        current_stage=job.current_stage,
        report_path=job.report_path,
        error=job.error,
        overall_risk=job.overall_risk,
        severity_counts=job.severity_counts,
    )


def to_detail(job: ScanJob) -> ScanDetail:
    base = to_summary(job)
    return ScanDetail(
        **base.model_dump(),
        artifact_path=job.artifact_path,
        metadata=job.metadata,
        coverage=job.coverage,
        stages_completed=job.stages_completed,
        finding_count=len(job.findings),
    )


@router.post("/scans", response_model=ScanSummary, status_code=202)
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile,
) -> ScanSummary:
    try:
        data = await file.read()
        job = await _service(request).create_from_upload(
            filename=file.filename or "upload.bin",
            content_type=file.content_type,
            data=data,
        )
    except ArtifactValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    background_tasks.add_task(_orchestrator(request).run, job.id)
    return to_summary(job)


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(request: Request) -> list[ScanSummary]:
    jobs = await _service(request).list()
    return [to_summary(job) for job in jobs]


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, request: Request) -> ScanDetail:
    job = await _service(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return to_detail(job)


@router.get("/scans/{scan_id}/findings", response_model=FindingList)
async def get_findings(scan_id: str, request: Request) -> FindingList:
    job = await _service(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return FindingList(scan_id=job.id, findings=job.findings)


@router.get("/scans/{scan_id}/report")
async def get_report(scan_id: str, request: Request, download: bool = False):
    job = await _service(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not job.report_path or not Path(job.report_path).is_file():
        if job.status in {ScanStatus.FAILED}:
            raise HTTPException(status_code=409, detail=job.error or "scan failed before report generation")
        raise HTTPException(status_code=409, detail="report is not ready")
    markdown = Path(job.report_path).read_text(encoding="utf-8")
    if download:
        return PlainTextResponse(
            markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="security-report-{scan_id}.md"'},
        )
    return ReportResponse(scan_id=job.id, path=job.report_path, markdown=markdown)


@router.get("/scans/{scan_id}/artifacts", response_model=ArtifactList)
async def get_artifacts(scan_id: str, request: Request) -> ArtifactList:
    job = await _service(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    root = _workspace(request).for_scan(scan_id).root
    artifacts: list[ArtifactEntry] = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            artifacts.append(
                ArtifactEntry(
                    name=path.name,
                    path=rel,
                    size=path.stat().st_size,
                    kind=path.suffix.lstrip(".") or "file",
                )
            )
    return ArtifactList(scan_id=scan_id, artifacts=artifacts)


@router.post("/scans/{scan_id}/cancel", response_model=ScanSummary)
async def cancel_scan(scan_id: str, request: Request) -> ScanSummary:
    job = await _service(request).cancel(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return to_summary(job)


@router.get("/scans/{scan_id}/artifacts/{artifact_path:path}")
async def get_artifact_file(scan_id: str, artifact_path: str, request: Request):
    job = await _service(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    root = _workspace(request).for_scan(scan_id).root
    try:
        target = safe_join(root, artifact_path)
    except UnsafePathError as exc:
        raise HTTPException(status_code=400, detail="invalid artifact path") from exc
    if not target.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return PlainTextResponse(target.read_bytes(), media_type="application/octet-stream")
