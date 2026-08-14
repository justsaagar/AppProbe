from pydantic import BaseModel, Field

from app.models.enums import FindingCategory, Severity


class EvidenceOut(BaseModel):
    kind: str
    summary: str
    location: str | None = None
    snippet: str | None = None


class FindingOut(BaseModel):
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float
    source: str
    description: str
    impact: str
    recommendation: str
    evidence: list[EvidenceOut] = Field(default_factory=list)
    cwe: str | None = None
    owasp: str | None = None
    masvs: str | None = None
    reproducibility: str = ""
    affected_component: str | None = None
    rule_id: str | None = None
    potential: bool = False
