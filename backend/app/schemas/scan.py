"""API request/response schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.advisory import VulnerabilityAssessment
from app.models.enums import ArtifactKind, Platform, ScanStatus
from app.models.finding import Finding
from app.models.mobsf import MobSFAnalysis
from app.models.scan_job import (
    ApplicationMetadata,
    CorrelatedGroup,
    CorrelationSummary,
    CoverageNote,
)
from app.models.technology import DependencyScanCoverage, TechnologyRecord


class ScannerStatusItem(BaseModel):
    id: str
    name: str
    status: str
    version: str | None = None
    reason: str = ""


class PipelineStage(BaseModel):
    id: str
    label: str
    status: str


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
    error: str | None
    overall_risk: str | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    package_name: str | None = None
    version_name: str | None = None
    report_ready: bool = False
    finding_count: int = 0


class ScanDetail(ScanSummary):
    metadata: ApplicationMetadata | None = None
    coverage: list[CoverageNote] = Field(default_factory=list)
    stages_completed: list[str] = Field(default_factory=list)
    scanners: list[ScannerStatusItem] = Field(default_factory=list)
    pipeline: list[PipelineStage] = Field(default_factory=list)
    correlation_summary: CorrelationSummary | None = None
    correlated_groups: list[CorrelatedGroup] = Field(default_factory=list)
    mobsf: MobSFAnalysis | None = None
    vulnerability_assessment: VulnerabilityAssessment | None = None
    technology_count: int = 0
    dependency_scan_coverage: DependencyScanCoverage | None = None


class FindingList(BaseModel):
    scan_id: str
    findings: list[Finding]
    groups: list[CorrelatedGroup] = Field(default_factory=list)


class TechnologyList(BaseModel):
    scan_id: str
    technologies: list[TechnologyRecord]
    coverage: DependencyScanCoverage | None = None


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
    markdown: str


class PublicConfig(BaseModel):
    app_name: str
    max_upload_bytes: int
    allowed_extensions: list[str]
    mobsf_enabled: bool
    mobsf_configured: bool
    jadx_configured: bool
    apktool_configured: bool
    advisory_network_enabled: bool
    extra: dict[str, Any] = Field(default_factory=dict)
