from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse

from app.analyzers.artifact import ArtifactValidationError
from app.api.deps import get_scan_service
from app.models.enums import ScanStatus
from app.schemas.finding import FindingOut
from app.schemas.scan import (
    ArtifactInfo,
    ScanCreateResponse,
    ScanDetail,
    ScanListResponse,
    ScanSummary,
)
from app.services.scan_service import ScanService
from app.utils.paths import PathTraversalError

router = APIRouter(prefix="/scans", tags=["scans"])


def _summary(job) -> ScanSummary:
    return ScanSummary.model_validate(job.model_dump())


def _detail(job, service: ScanService) -> ScanDetail:
    payload = job.model_dump()
    payload["finding_counts"] = job.metadata.get("finding_counts") or {}
    payload["overall_risk"] = job.metadata.get("overall_risk")
    return ScanDetail.model_validate(payload)


async def _job_or_404(scan_id: str, service: ScanService):
    try:
        job = await service.get(scan_id)
    except PathTraversalError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job


@router.post("", status_code=202, response_model=ScanCreateResponse)
async def create_scan(
    file: UploadFile = File(...),
    service: ScanService = Depends(get_scan_service),
) -> ScanCreateResponse:
    try:
        job = await service.create_from_upload(file)
    except ArtifactValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanCreateResponse(
        id=job.id,
        status=job.status,
        filename=job.filename,
        created_at=job.created_at,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(service: ScanService = Depends(get_scan_service)) -> ScanListResponse:
    jobs = await service.list_jobs()
    return ScanListResponse(scans=[_summary(job) for job in jobs], total=len(jobs))


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, service: ScanService = Depends(get_scan_service)) -> ScanDetail:
    job = await _job_or_404(scan_id, service)
    return _detail(job, service)


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def get_findings(scan_id: str, service: ScanService = Depends(get_scan_service)) -> list[FindingOut]:
    await _job_or_404(scan_id, service)
    findings = service.load_findings(scan_id)
    return [FindingOut.model_validate(item.model_dump()) for item in findings]


@router.get("/{scan_id}/report")
async def get_report(scan_id: str, service: ScanService = Depends(get_scan_service)):
    job = await _job_or_404(scan_id, service)
    if job.status not in {ScanStatus.COMPLETED, ScanStatus.PARTIAL} or not job.report_path:
        raise HTTPException(status_code=409, detail="Report is not available yet")
    path = service.report_path(scan_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")


@router.get("/{scan_id}/artifacts", response_model=list[ArtifactInfo])
async def get_artifacts(scan_id: str, service: ScanService = Depends(get_scan_service)) -> list[ArtifactInfo]:
    job = await _job_or_404(scan_id, service)
    return [ArtifactInfo.model_validate(item) for item in service.list_artifacts(job)]


@router.post("/{scan_id}/cancel", response_model=ScanDetail)
async def cancel_scan(scan_id: str, service: ScanService = Depends(get_scan_service)) -> ScanDetail:
    try:
        job = await service.cancel(scan_id)
    except PathTraversalError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _detail(job, service)
