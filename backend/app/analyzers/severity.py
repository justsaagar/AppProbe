"""Deterministic severity assignment. AI may only adjust later (Milestone 6)."""

from __future__ import annotations

from app.analyzers.manifest_parser import AndroidMetadata, lookup_protection_level
from app.models.enums import Severity
from app.models.finding import Finding

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

RULE_SEVERITY: dict[str, Severity] = {
    "ANDROID_DEBUGGABLE": Severity.HIGH,
    "ANDROID_CLEARTEXT_TRAFFIC": Severity.MEDIUM,
    "ANDROID_ALLOW_BACKUP": Severity.LOW,
    "ANDROID_EXPORTED_ACTIVITY": Severity.HIGH,
    "ANDROID_EXPORTED_SERVICE": Severity.HIGH,
    "ANDROID_EXPORTED_RECEIVER": Severity.MEDIUM,
    "ANDROID_EXPORTED_PROVIDER": Severity.HIGH,
    "ANDROID_DANGEROUS_PERMISSION": Severity.INFO,
    "ANDROID_NATIVE_LIBRARIES": Severity.INFO,
    "ANDROID_FIREBASE_CONFIG_PRESENT": Severity.INFO,
    "ANDROID_AAB_NOT_CONVERTED": Severity.INFO,
    "IOS_DYNAMIC_UNAVAILABLE": Severity.INFO,
}


def rank(severity: Severity) -> int:
    return SEVERITY_RANK[severity]


def overall_risk(findings: list[Finding]) -> Severity | None:
    actionable = [finding for finding in findings if finding.severity != Severity.INFO]
    if not actionable:
        return Severity.INFO if findings else None
    return max(actionable, key=lambda item: rank(item.severity)).severity


def apply_severity(finding: Finding, metadata: AndroidMetadata | None = None) -> Finding:
    """Apply deterministic rules. Never escalate to CRITICAL in Milestone 1."""
    if finding.rule_id and finding.rule_id in RULE_SEVERITY:
        finding.severity = RULE_SEVERITY[finding.rule_id]

    if finding.rule_id and finding.rule_id.startswith("ANDROID_EXPORTED_") and metadata:
        permission = None
        for group in (
            metadata.activities,
            metadata.services,
            metadata.receivers,
            metadata.providers,
        ):
            for component in group:
                if component.name == finding.affected_component:
                    permission = component.permission
                    break
        level = lookup_protection_level(metadata, permission)
        if permission and level in {"signature", "signatureOrSystem", "2", "3", "system"}:
            finding.severity = Severity.LOW
            finding.description += (
                " The component declares a permission that appears signature-level or system-protected,"
                " which reduces remote exploitability."
            )
        elif permission:
            finding.severity = Severity.MEDIUM
            finding.description += (
                " The component is permission-protected; severity is reduced pending confirmation of the"
                " protection level."
            )
    if finding.severity == Severity.CRITICAL:
        finding.severity = Severity.HIGH
        finding.description += (
            " Severity was capped at HIGH because Milestone 1 uses deterministic static rules only"
            " and does not confirm runtime exploitability."
        )
    finding.confidence = max(0.0, min(finding.confidence, 1.0))
    return finding
