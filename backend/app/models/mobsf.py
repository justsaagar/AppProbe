"""Normalized MobSF analysis records.

These store useful summary fields only. The complete MobSF JSON report is not
kept on the scan job or written into the Markdown report.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.models.finding import Finding


class MobSFAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    NOT_ENABLED = "NOT_ENABLED"


class MobSFHealth(BaseModel):
    availability: MobSFAvailability
    version: str | None = None
    reason: str = ""


class MobSFUpload(BaseModel):
    scan_id: str
    scan_type: str = "apk"
    file_name: str = ""


class MobSFScanProgress(BaseModel):
    completed: bool = False
    failed: bool = False
    status: str = ""


class MobSFResult(BaseModel):
    """Internal normalized MobSF scan result."""

    status: str
    availability: MobSFAvailability = MobSFAvailability.NOT_ENABLED
    scan_id: str | None = None
    package_name: str | None = None
    version: str | None = None
    mobsf_version: str | None = None
    score: float | None = None
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_summary: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float | None = None
    cleanup_succeeded: bool | None = None
    reason: str = ""


class MobSFAnalysis(BaseModel):
    """Scan-job coverage record for the Markdown MobSF section."""

    status: str
    availability: str
    version: str | None = None
    scan_id: str | None = None
    package_name: str | None = None
    app_version: str | None = None
    score: float | None = None
    findings_imported: int = 0
    duration_seconds: float | None = None
    cleanup_succeeded: bool | None = None
    reason: str = ""
    limitations: list[str] = Field(default_factory=list)


def analysis_from_result(result: MobSFResult) -> MobSFAnalysis:
    version = result.mobsf_version
    if not version and result.status == "EXECUTED":
        version = "Unknown"
    return MobSFAnalysis(
        status=result.status,
        availability=result.availability.value,
        version=version,
        scan_id=result.scan_id,
        package_name=result.package_name,
        app_version=result.version,
        score=result.score,
        findings_imported=len(result.findings),
        duration_seconds=result.duration_seconds,
        cleanup_succeeded=result.cleanup_succeeded,
        reason=result.reason,
        limitations=[
            "MobSF is an optional static-analysis provider.",
            "AppProbe does not depend on MobSF being available.",
            "MobSF findings are normalized into AppProbe's Finding model.",
            "MobSF does not replace AppProbe's deterministic scanners.",
            "Dynamic analysis is NOT part of Milestone 2.8.",
        ],
    )
