"""Scan job persistence model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.models.advisory import VulnerabilityAssessment
from app.models.enums import (
    ArtifactKind,
    Platform,
    RelationshipType,
    ScanStatus,
    Severity,
    ToolExecutionStatus,
    ToolStatus,
)
from app.models.finding import Finding
from app.models.mobsf import MobSFAnalysis
from app.models.technology import DependencyScanCoverage, TechnologyRecord


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CoverageNote(BaseModel):
    area: str
    executed: bool
    reason: str


class SkippedScanFile(BaseModel):
    path: str
    reason: str


class SecretScanCoverage(BaseModel):
    """Local secret-scanner coverage. Values are measured, never fabricated."""

    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    sources: list[str] = Field(default_factory=list)
    skipped_files: list[SkippedScanFile] = Field(default_factory=list)


class ToolRunRecord(BaseModel):
    name: str
    status: ToolStatus = ToolStatus.NOT_EXECUTED
    version: str | None = None
    reason: str = ""
    output_dir: str | None = None
    execution_status: ToolExecutionStatus | None = None
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class CorrelatedGroup(BaseModel):
    fingerprint: str
    title: str
    finding_ids: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    canonical_id: str | None = None
    note: str = ""
    group_id: str = ""
    relationship: RelationshipType = RelationshipType.DUPLICATE
    primary_finding_id: str | None = None
    related_finding_ids: list[str] = Field(default_factory=list)
    severity: Severity | None = None
    confidence: float | None = None


class CorrelationSummary(BaseModel):
    """Measured correlation coverage. Values are never fabricated."""

    raw_findings: int = 0
    correlated_findings: int = 0
    exact_duplicates_merged: int = 0
    related_groups: int = 0
    independent_findings: int = 0
    duplicate_groups: int = 0


class ApplicationMetadata(BaseModel):
    platform: Platform = Platform.UNKNOWN
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN
    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = Field(default_factory=list)
    activities: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    receivers: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    application_label: str | None = None
    main_activity: str | None = None
    native_libraries: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanJob(BaseModel):
    id: str
    filename: str
    platform: Platform = Platform.UNKNOWN
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN
    status: ScanStatus = ScanStatus.QUEUED
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    progress: int = 0
    current_stage: str = "queued"
    artifact_path: str
    report_path: str | None = None
    error: str | None = None
    cancel_requested: bool = False
    metadata: ApplicationMetadata | None = None
    findings: list[Finding] = Field(default_factory=list)
    coverage: list[CoverageNote] = Field(default_factory=list)
    stages_completed: list[str] = Field(default_factory=list)
    overall_risk: str | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    tool_runs: list[ToolRunRecord] = Field(default_factory=list)
    correlated_groups: list[CorrelatedGroup] = Field(default_factory=list)
    raw_findings: list[Finding] = Field(default_factory=list)
    correlation_summary: CorrelationSummary | None = None
    secret_scan_coverage: SecretScanCoverage | None = None
    technology_inventory: list[TechnologyRecord] = Field(default_factory=list)
    dependency_scan_coverage: DependencyScanCoverage | None = None
    vulnerability_assessment: VulnerabilityAssessment | None = None
    mobsf_analysis: MobSFAnalysis | None = None

    def mark(
        self,
        *,
        status: ScanStatus | None = None,
        stage: str | None = None,
        progress: int | None = None,
    ) -> None:
        if status is not None:
            self.status = status
        if stage is not None:
            self.current_stage = stage
        if progress is not None:
            self.progress = max(0, min(100, progress))
