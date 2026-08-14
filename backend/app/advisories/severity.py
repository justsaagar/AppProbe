"""Normalize advisory severity onto AppProbe's scale.

Unknown severity is preserved internally and mapped conservatively to INFO
on findings. CVEs are not automatically HIGH.
"""

from __future__ import annotations

import re
from typing import Any

from app.models.advisory import AdvisorySeverity
from app.models.enums import Severity

_CVSS_NUMERIC = re.compile(r"^(\d+(?:\.\d+)?)$")
_VECTOR_SCORE_HINT = re.compile(r"CVSS:\d+\.\d+/")

_QUALITATIVE = {
    "CRITICAL": AdvisorySeverity.CRITICAL,
    "HIGH": AdvisorySeverity.HIGH,
    "MEDIUM": AdvisorySeverity.MEDIUM,
    "MODERATE": AdvisorySeverity.MEDIUM,
    "LOW": AdvisorySeverity.LOW,
    "INFO": AdvisorySeverity.INFO,
    "INFORMATIONAL": AdvisorySeverity.INFO,
    "NONE": AdvisorySeverity.INFO,
    "UNKNOWN": AdvisorySeverity.UNKNOWN,
}


def cvss_to_advisory_severity(score: float) -> AdvisorySeverity:
    if score >= 9.0:
        return AdvisorySeverity.CRITICAL
    if score >= 7.0:
        return AdvisorySeverity.HIGH
    if score >= 4.0:
        return AdvisorySeverity.MEDIUM
    if score > 0.0:
        return AdvisorySeverity.LOW
    return AdvisorySeverity.INFO


def qualitative_severity(value: str | None) -> AdvisorySeverity:
    if not value:
        return AdvisorySeverity.UNKNOWN
    return _QUALITATIVE.get(value.strip().upper(), AdvisorySeverity.UNKNOWN)


def parse_cvss_score(raw: Any) -> tuple[float | None, str | None]:
    if raw is None:
        return None, None
    if isinstance(raw, (int, float)):
        score = float(raw)
        if 0.0 <= score <= 10.0:
            return score, None
        return None, None
    if not isinstance(raw, str):
        return None, None
    text = raw.strip()
    if len(text) > 256:
        return None, None
    numeric = _CVSS_NUMERIC.match(text)
    if numeric:
        score = float(numeric.group(1))
        if 0.0 <= score <= 10.0:
            return score, None
        return None, None
    if _VECTOR_SCORE_HINT.match(text):
        return None, text
    return None, None


def normalize_osv_severity(payload: dict[str, Any]) -> tuple[AdvisorySeverity, float | None, str | None]:
    """Extract severity from an OSV vulnerability object. Conservative."""

    best_score: float | None = None
    vector: str | None = None
    qualitative = AdvisorySeverity.UNKNOWN

    severity_list = payload.get("severity")
    if isinstance(severity_list, list):
        for item in severity_list:
            if not isinstance(item, dict):
                continue
            score, maybe_vector = parse_cvss_score(item.get("score"))
            if maybe_vector and vector is None:
                vector = maybe_vector
            if score is not None and (best_score is None or score > best_score):
                best_score = score

    database = payload.get("database_specific")
    if isinstance(database, dict):
        qualitative = qualitative_severity(
            database.get("severity") if isinstance(database.get("severity"), str) else None
        )
        cvss = database.get("cvss")
        if isinstance(cvss, dict):
            score, maybe_vector = parse_cvss_score(cvss.get("score") or cvss.get("baseScore"))
            if maybe_vector and vector is None:
                vector = maybe_vector
            if score is not None and (best_score is None or score > best_score):
                best_score = score

    if best_score is not None:
        return cvss_to_advisory_severity(best_score), best_score, vector
    return qualitative, None, vector


def to_finding_severity(advisory_severity: AdvisorySeverity) -> Severity:
    if advisory_severity is AdvisorySeverity.UNKNOWN:
        return Severity.INFO
    return Severity[advisory_severity.value]
