"""Normalize scanner output onto the common Finding schema."""

from __future__ import annotations

from app.models.enums import FindingCategory, Severity
from app.models.finding import Evidence, Finding

ALLOWED_SEVERITIES = {item.value for item in Severity}


def normalize_finding(payload: dict[str, object], *, index: int, source: str) -> Finding:
    severity_raw = str(payload.get("severity", Severity.INFO.value)).upper()
    if severity_raw not in ALLOWED_SEVERITIES:
        severity_raw = Severity.INFO.value
    evidence_in = payload.get("evidence") or []
    evidence: list[Evidence] = []
    if isinstance(evidence_in, list):
        for item in evidence_in:
            if isinstance(item, Evidence):
                evidence.append(item)
            elif isinstance(item, dict):
                evidence.append(Evidence.model_validate(item))
    finding_id = str(payload.get("id") or f"{source}-{index:04d}")
    category_raw = payload.get("category", FindingCategory.INFORMATIONAL)
    try:
        category = (
            category_raw
            if isinstance(category_raw, FindingCategory)
            else FindingCategory(str(category_raw))
        )
    except ValueError:
        category = FindingCategory.INFORMATIONAL
    confidence = payload.get("confidence", 0.5)
    try:
        confidence_f = float(confidence)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        confidence_f = 0.5
    confidence_f = max(0.0, min(confidence_f, 1.0))
    return Finding(
        id=finding_id,
        title=str(payload.get("title") or "Untitled finding"),
        category=category,
        severity=Severity(severity_raw),
        confidence=confidence_f,
        source=str(payload.get("source") or source),
        description=str(payload.get("description") or ""),
        impact=str(payload.get("impact") or ""),
        recommendation=str(payload.get("recommendation") or ""),
        evidence=evidence,
        cwe=_optional_str(payload.get("cwe")),
        owasp=_optional_str(payload.get("owasp")),
        masvs=_optional_str(payload.get("masvs")),
        reproducibility=str(payload.get("reproducibility") or ""),
        affected_component=_optional_str(payload.get("affected_component")),
        rule_id=_optional_str(payload.get("rule_id")),
        potential=bool(payload.get("potential", False)),
    )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
