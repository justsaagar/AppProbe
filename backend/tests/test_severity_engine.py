from app.analyzers.manifest_parser import AndroidMetadata, ComponentInfo
from app.analyzers.normalize import normalize_finding
from app.analyzers.severity import apply_severity, overall_risk
from app.models.enums import FindingCategory, Severity


def _finding(rule_id: str, severity: str = "INFO", component: str | None = None):
    return normalize_finding(
        {
            "title": rule_id,
            "severity": severity,
            "confidence": 0.7,
            "rule_id": rule_id,
            "category": FindingCategory.CONFIGURATION,
            "affected_component": component,
        },
        index=1,
        source="test",
    )


def test_rule_severity_table() -> None:
    finding = apply_severity(_finding("ANDROID_DEBUGGABLE", "INFO"))
    assert finding.severity == Severity.HIGH


def test_exported_signature_permission_reduces_severity() -> None:
    metadata = AndroidMetadata(
        custom_permissions=[{"name": "com.example.SIG", "protectionLevel": "signature"}],
        activities=[
            ComponentInfo(kind="activity", name=".Secure", exported=True, permission="com.example.SIG")
        ],
    )
    finding = apply_severity(
        _finding("ANDROID_EXPORTED_ACTIVITY", "HIGH", component=".Secure"),
        metadata,
    )
    assert finding.severity == Severity.LOW


def test_never_keeps_critical_in_milestone_1() -> None:
    finding = normalize_finding(
        {
            "title": "x",
            "severity": "CRITICAL",
            "confidence": 1,
            "rule_id": "UNKNOWN_RULE",
            "category": FindingCategory.CODE,
        },
        index=1,
        source="test",
    )
    finding = apply_severity(finding)
    assert finding.severity == Severity.HIGH


def test_overall_risk_ignores_info_only() -> None:
    info = apply_severity(_finding("ANDROID_DANGEROUS_PERMISSION"))
    high = apply_severity(_finding("ANDROID_DEBUGGABLE"))
    assert overall_risk([info]) == Severity.INFO
    assert overall_risk([info, high]) == Severity.HIGH
