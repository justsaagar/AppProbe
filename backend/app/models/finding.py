"""Normalized finding schema produced by every scanner."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import FindingCategory, Severity


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

    def display_title(self) -> str:
        if self.potential:
            return f"Potential Finding: {self.title}"
        return self.title
