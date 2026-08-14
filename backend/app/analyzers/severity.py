"""Deterministic severity assignment. AI must not override this in Milestone 1."""

from __future__ import annotations

from app.models.enums import Severity
from app.models.finding import Finding

# Lower number = more severe.
_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Scanner-provided rule ids -> default severity. Contextual scanners may still
# set severity directly; this table is the fallback and the cap for later AI
# adjustment (Milestone 6 must not invent CRITICAL without a matching rule).
RULE_SEVERITY: dict[str, Severity] = {
    "debuggable": Severity.HIGH,
    "cleartext_traffic": Severity.MEDIUM,
    "allow_backup": Severity.LOW,
    "exported_activity": Severity.MEDIUM,
    "exported_service": Severity.MEDIUM,
    "exported_receiver": Severity.MEDIUM,
    "exported_provider": Severity.HIGH,
    "dangerous_permission": Severity.INFO,
    "network_security_config_missing": Severity.INFO,
    "old_target_sdk": Severity.LOW,
    "ios_dynamic_unavailable": Severity.INFO,
    "aab_not_converted": Severity.INFO,
    "runtime_not_executed": Severity.INFO,
    "hardcoded_secret": Severity.HIGH,
    "private_key": Severity.CRITICAL,
    "jwt": Severity.HIGH,
    "cloud_credential": Severity.CRITICAL,
    "http_endpoint": Severity.INFO,
    "sdk_detected": Severity.INFO,
    "weak_crypto": Severity.MEDIUM,
}


def rank(severity: Severity) -> int:
    return _RANK[severity]


def overall_risk(findings: list[Finding]) -> Severity:
    if not findings:
        return Severity.INFO
    confirmed = [item for item in findings if not item.potential]
    pool = confirmed or findings
    return min((item.severity for item in pool), key=rank)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {item.value: 0 for item in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def apply_rule_severity(rule_id: str, *, potential: bool = False) -> Severity:
    severity = RULE_SEVERITY.get(rule_id, Severity.INFO)
    if potential and rank(severity) < rank(Severity.LOW):
        # Unverified claims cannot be CRITICAL/HIGH.
        return Severity.LOW
    return severity
