from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import (
    ALLOWED_TRANSITIONS,
    STATUS_PROGRESS,
    ArtifactKind,
    Platform,
    ScanStatus,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


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
    artifact_path: str | None = None
    report_path: str | None = None
    error: str | None = None
    package_name: str | None = None
    version_name: str | None = None
    skipped_stages: list[str] = Field(default_factory=list)
    stage_notes: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    cancel_requested: bool = False

    def transition(self, new_status: ScanStatus, stage: str | None = None) -> None:
        allowed = ALLOWED_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise ValueError(f"Illegal scan transition: {self.status} -> {new_status}")
        self.status = new_status
        self.progress = STATUS_PROGRESS[new_status]
        if stage:
            self.current_stage = stage
        if new_status == ScanStatus.VALIDATING and self.started_at is None:
            self.started_at = utcnow()
        if new_status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.PARTIAL}:
            self.completed_at = utcnow()
            self.current_stage = new_status.value.lower()

    def mark_skipped(self, stage: str, reason: str) -> None:
        if stage not in self.skipped_stages:
            self.skipped_stages.append(stage)
        self.stage_notes[stage] = reason
