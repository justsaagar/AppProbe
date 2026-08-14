"""API request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import ArtifactKind, Platform, ScanStatus
from app.models.finding import Finding
from app.models.scan_job import ApplicationMetadata, CoverageNote


class ScanSummary(BaseModel):
    id: str
    filename: str
    platform: Platform
    artifact_kind: ArtifactKind
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    progress: int
    current_stage: str
    report_path: str | None
    error: str | None
    overall_risk: str | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ScanDetail(ScanSummary):
    artifact_path: str
    metadata: ApplicationMetadata | None = None
    coverage: list[CoverageNote] = Field(default_factory=list)
    stages_completed: list[str] = Field(default_factory=list)
    finding_count: int = 0


class FindingList(BaseModel):
    scan_id: str
    findings: list[Finding]


class ArtifactEntry(BaseModel):
    name: str
    path: str
    size: int
    kind: str


class ArtifactList(BaseModel):
    scan_id: str
    artifacts: list[ArtifactEntry]


class ReportResponse(BaseModel):
    scan_id: str
    path: str | None
    markdown: str
