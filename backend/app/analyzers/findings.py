"""Finding helpers: ids, OWASP/CWE mapping, normalization."""

from __future__ import annotations

import hashlib
import re

from app.models.enums import FindingCategory, Severity, Verification
from app.models.finding import Evidence, Finding

# Only mappings we can assert from scanner rule ids. Empty if unknown.
OWASP_MOBILE = {
    "debuggable": "M8: Security Misconfiguration",
    "cleartext_traffic": "M5: Insecure Communication",
    "allow_backup": "M9: Insecure Data Storage",
    "exported_activity": "M8: Security Misconfiguration",
    "exported_service": "M8: Security Misconfiguration",
    "exported_receiver": "M8: Security Misconfiguration",
    "exported_provider": "M8: Security Misconfiguration",
    "old_target_sdk": "M8: Security Misconfiguration",
}

MASVS = {
    "debuggable": "MASVS-RESILIENCE",
    "cleartext_traffic": "MASVS-NETWORK",
    "allow_backup": "MASVS-STORAGE",
    "exported_activity": "MASVS-PLATFORM",
    "exported_service": "MASVS-PLATFORM",
    "exported_receiver": "MASVS-PLATFORM",
    "exported_provider": "MASVS-PLATFORM",
}

CWE = {
    "debuggable": "CWE-489",
    "cleartext_traffic": "CWE-319",
    "allow_backup": "CWE-921",
    "exported_activity": "CWE-926",
    "exported_service": "CWE-926",
    "exported_receiver": "CWE-926",
    "exported_provider": "CWE-926",
    "hardcoded_secret": "CWE-798",
    "private_key": "CWE-321",
    "jwt": "CWE-798",
    "cloud_credential": "CWE-798",
    "http_endpoint": "CWE-319",
    "weak_crypto": "CWE-327",
}


def finding_id(source: str, rule_id: str, component: str | None) -> str:
    material = f"{source}|{rule_id}|{component or ''}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9]+", "-", rule_id.lower()).strip("-")
    return f"{slug}-{digest}"


def normalize_finding(
    *,
    source: str,
    rule_id: str,
    title: str,
    category: FindingCategory,
    severity: Severity,
    confidence: float,
    description: str,
    impact: str = "",
    recommendation: str = "",
    evidence: list[Evidence] | None = None,
    affected_component: str | None = None,
    reproducibility: str = "",
    potential: bool = False,
    verification: Verification | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    masvs: str | None = None,
) -> Finding:
    if verification is None:
        if potential:
            verification = Verification.POTENTIAL
        elif severity is Severity.INFO:
            verification = Verification.INFO
        else:
            verification = Verification.CONFIRMED
    return Finding(
        id=finding_id(source, rule_id, affected_component),
        title=title,
        category=category,
        severity=severity,
        confidence=max(0.0, min(1.0, confidence)),
        source=source,
        sources=[source],
        rule_id=rule_id,
        description=description,
        impact=impact,
        recommendation=recommendation,
        evidence=evidence or [],
        cwe=cwe or CWE.get(rule_id),
        owasp=owasp or OWASP_MOBILE.get(rule_id),
        masvs=masvs or MASVS.get(rule_id),
        reproducibility=reproducibility,
        affected_component=affected_component,
        potential=potential or verification is Verification.POTENTIAL,
        verification=verification,
    )
