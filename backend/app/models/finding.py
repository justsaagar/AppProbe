"""Normalized finding schema produced by every scanner."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import FindingCategory, Severity, Verification


class Evidence(BaseModel):
    """A single piece of supporting evidence. Never fabricate these."""

    kind: str
    summary: str
    location: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    title: str
    category: FindingCategory | str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    sources: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    description: str
    impact: str = ""
    recommendation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    cwe: str | None = None
    owasp: str | None = None
    masvs: str | None = None
    reproducibility: str = ""
    affected_component: str | None = None
    potential: bool = False
    verification: Verification = Verification.CONFIRMED
    fingerprint: str | None = None

    def model_post_init(self, _context: Any) -> None:
        if not self.sources:
            self.sources = [self.source]
        elif self.source not in self.sources:
            self.sources = [self.source, *self.sources]
        if self.potential and self.verification is Verification.CONFIRMED:
            self.verification = Verification.POTENTIAL
        if self.verification is Verification.POTENTIAL:
            self.potential = True

    def display_title(self) -> str:
        if self.potential or self.verification is Verification.POTENTIAL:
            return f"Potential Finding: {self.title}"
        return self.title
