from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.enums import FindingCategory, Severity


class Evidence(BaseModel):
    """A single piece of supporting evidence. Never fabricate these."""

    kind: str
    summary: str
    location: str | None = None
    snippet: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    description: str
    impact: str
    recommendation: str
    evidence: list[Evidence] = Field(default_factory=list)
    cwe: str | None = None
    owasp: str | None = None
    masvs: str | None = None
    reproducibility: str = ""
    affected_component: str | None = None
    rule_id: str | None = None
    potential: bool = False

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: object) -> object:
        if isinstance(value, str):
            return value.upper()
        return value

    @field_validator("cwe", "owasp", "masvs")
    @classmethod
    def _empty_mapping_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None
