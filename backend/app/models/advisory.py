"""Normalized advisory and vulnerability-assessment models.

These records store useful advisory fields only. Raw provider JSON is not
kept on the scan job or written into the Markdown report.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

MatchStatus = Literal["affected", "not_affected", "unknown"]
AssessmentStatus = Literal["COMPLETE", "INCOMPLETE", "NOT_AVAILABLE", "NOT_EXECUTED"]


class AdvisorySeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class AffectedRange(BaseModel):
    """One affected version range from an advisory.

    Bounds follow OSV event semantics: ``introduced`` is inclusive, ``fixed``
    and ``limit`` are exclusive, ``last_affected`` is inclusive.
    """

    type: str
    introduced: str = "0"
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    def display(self) -> str:
        parts: list[str] = []
        if self.introduced and self.introduced not in {"0", "0.0.0"}:
            parts.append(f">= {self.introduced}")
        if self.fixed:
            parts.append(f"< {self.fixed}")
        if self.last_affected:
            parts.append(f"<= {self.last_affected}")
        if self.limit:
            parts.append(f"< {self.limit}")
        return ", ".join(parts) if parts else "unspecified"


class AdvisoryReference(BaseModel):
    type: str = ""
    url: str


class Advisory(BaseModel):
    """Provider-normalized advisory. Scanner-facing, not OSV-specific."""

    id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: AdvisorySeverity = AdvisorySeverity.UNKNOWN
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_package: str = ""
    affected_ecosystem: str = ""
    affected_ranges: list[AffectedRange] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    references: list[AdvisoryReference] = Field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    source: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def cve_ids(self) -> list[str]:
        return [item for item in self.aliases if item.upper().startswith("CVE-")]

    @property
    def ghsa_ids(self) -> list[str]:
        return [item for item in self.aliases if item.upper().startswith("GHSA-")]

    def range_display(self) -> str:
        if self.affected_ranges:
            return "; ".join(item.display() for item in self.affected_ranges)
        if self.affected_versions:
            return "listed versions: " + ", ".join(self.affected_versions[:12])
        return "unspecified"

    def preferred_fixed_version(self) -> str | None:
        for item in self.affected_ranges:
            if item.fixed:
                return item.fixed
        return None


class PackageSkip(BaseModel):
    technology: str
    reason: str
    version: str | None = None


class VulnerabilityAssessment(BaseModel):
    """Scan-level advisory matching coverage. Never implies exploitability."""

    status: AssessmentStatus = "NOT_EXECUTED"
    advisory_source: str = "OSV"
    reason: str = ""
    packages_evaluated: int = 0
    vulnerable_packages: int = 0
    packages_no_advisories: int = 0
    packages_not_evaluated: int = 0
    vulnerability_findings: int = 0
    skipped: list[PackageSkip] = Field(default_factory=list)
    provider_error: str | None = None
