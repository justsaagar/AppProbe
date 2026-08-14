from app.analyzers.findings import normalize_finding
from app.analyzers.severity import apply_rule_severity, overall_risk, severity_counts
from app.models.enums import FindingCategory, Severity
from app.models.finding import Evidence
from app.scanners.manifest import analyze_manifest
from tests.helpers import vulnerable_manifest


def test_manifest_scanner_emits_expected_findings() -> None:
    findings = analyze_manifest(vulnerable_manifest())
    titles = [item.title for item in findings]
    assert any("debuggable" in title.lower() for title in titles)
    assert any("cleartext" in title.lower() for title in titles)
    assert any("backup" in title.lower() for title in titles)
    assert any("CAMERA" in title for title in titles)
    assert any("Exported activity" in title for title in titles)
    assert any("Exported service" in title for title in titles)
    assert any("Exported receiver" in title for title in titles)
    assert any("Exported provider" in title for title in titles)
    for finding in findings:
        assert finding.evidence, f"{finding.title} is missing evidence"
        assert finding.source
        assert 0 <= finding.confidence <= 1


def test_dangerous_permission_is_informational() -> None:
    findings = analyze_manifest(vulnerable_manifest())
    camera = next(item for item in findings if "CAMERA" in item.title)
    assert camera.severity is Severity.INFO
    assert camera.category is FindingCategory.PERMISSIONS


def test_exported_provider_is_high() -> None:
    findings = analyze_manifest(vulnerable_manifest())
    provider = next(item for item in findings if "Exported provider" in item.title)
    assert provider.severity is Severity.HIGH
    assert provider.cwe == "CWE-926"


def test_normalize_finding_ids_are_stable() -> None:
    first = normalize_finding(
        source="manifest-scanner",
        rule_id="debuggable",
        title="Application is debuggable",
        category=FindingCategory.MANIFEST,
        severity=Severity.HIGH,
        confidence=0.99,
        description="test",
        evidence=[Evidence(kind="manifest_entry", summary="debuggable=true")],
        affected_component="application",
    )
    second = normalize_finding(
        source="manifest-scanner",
        rule_id="debuggable",
        title="Application is debuggable",
        category=FindingCategory.MANIFEST,
        severity=Severity.HIGH,
        confidence=0.99,
        description="test",
        evidence=[Evidence(kind="manifest_entry", summary="debuggable=true")],
        affected_component="application",
    )
    assert first.id == second.id
    assert first.owasp and first.owasp.startswith("M8")


def test_overall_risk_ignores_potential_critical() -> None:
    confirmed = normalize_finding(
        source="t",
        rule_id="allow_backup",
        title="backup",
        category=FindingCategory.STORAGE,
        severity=Severity.LOW,
        confidence=0.9,
        description="d",
    )
    potential = normalize_finding(
        source="t",
        rule_id="debuggable",
        title="maybe",
        category=FindingCategory.MANIFEST,
        severity=Severity.HIGH,
        confidence=0.2,
        description="d",
        potential=True,
    )
    assert overall_risk([potential, confirmed]) is Severity.LOW
    counts = severity_counts([potential, confirmed])
    assert counts["HIGH"] == 1
    assert counts["LOW"] == 1


def test_potential_rule_cannot_stay_critical() -> None:
    assert apply_rule_severity("debuggable", potential=True) is Severity.LOW
    assert apply_rule_severity("debuggable") is Severity.HIGH
