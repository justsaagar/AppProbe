from app.analyzers.normalize import normalize_finding
from app.models.enums import FindingCategory, Severity
from app.models.finding import Finding


def test_normalize_defaults_and_clamps() -> None:
    finding = normalize_finding(
        {
            "title": "Test",
            "severity": "weird",
            "confidence": 9.5,
            "category": "not-a-category",
            "evidence": [{"kind": "manifest_entry", "summary": "x"}],
        },
        index=3,
        source="unit",
    )
    assert isinstance(finding, Finding)
    assert finding.severity == Severity.INFO
    assert finding.confidence == 1.0
    assert finding.category == FindingCategory.INFORMATIONAL
    assert finding.source == "unit"
    assert finding.id.endswith("0003") or finding.id == "unit-0003"
    assert finding.evidence[0].kind == "manifest_entry"


def test_normalize_preserves_known_severity() -> None:
    finding = normalize_finding(
        {"title": "Debuggable", "severity": "high", "confidence": 0.4, "source": "manifest-scanner"},
        index=1,
        source="ignored",
    )
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.4
    assert finding.source == "manifest-scanner"
