from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import ArtifactKind, Platform, ScanStatus


class ScanCreateResponse(BaseModel):
    id: str
    status: ScanStatus
    filename: str
    created_at: datetime


class ScanSummary(BaseModel):
    id: str
    filename: str
    platform: Platform
    artifact_kind: ArtifactKind
    status: ScanStatus
    progress: int
    current_stage: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    package_name: str | None = None


class ScanDetail(ScanSummary):
    artifact_path: str | None = None
    report_path: str | None = None
    skipped_stages: list[str] = Field(default_factory=list)
    stage_notes: dict[str, str] = Field(default_factory=dict)
    finding_counts: dict[str, int] = Field(default_factory=dict)
    overall_risk: str | None = None


class ScanListResponse(BaseModel):
    scans: list[ScanSummary]
    total: int


class ArtifactInfo(BaseModel):
    name: str
    path: str
    size_bytes: int
    kind: str
