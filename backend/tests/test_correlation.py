from app.analyzers.correlation import correlate_findings, fingerprint_for
from app.analyzers.findings import normalize_finding
from app.models.enums import FindingCategory, Severity
from app.models.finding import Evidence


def _finding(source: str, rule_id: str, title: str, component: str, severity: Severity = Severity.MEDIUM):
    return normalize_finding(
        source=source,
        rule_id=rule_id,
        title=title,
        category=FindingCategory.NETWORK if rule_id in {"cleartext_traffic", "http_endpoint"} else FindingCategory.MANIFEST,
        severity=severity,
        confidence=0.8,
        description=title,
        evidence=[Evidence(kind="test", summary=title, location=component)],
        affected_component=component,
    )


def test_exact_duplicates_merge_and_preserve_sources() -> None:
    a = _finding("manifest-scanner", "cleartext_traffic", "Cleartext traffic enabled", "application")
    b = _finding("mobsf", "cleartext_traffic", "MobSF: cleartext traffic permitted", "application")
    merged, groups = correlate_findings([a, b])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"manifest-scanner", "mobsf"}
    assert len(merged[0].evidence) >= 2
    assert groups
    assert groups[0].canonical_id == merged[0].id


def test_related_http_url_groups_with_cleartext() -> None:
    flag = _finding("manifest-scanner", "cleartext_traffic", "Cleartext traffic enabled", "application")
    url = _finding(
        "secret-scanner",
        "http_endpoint",
        "HTTP (cleartext) URL referenced",
        "assets/config.json",
        Severity.INFO,
    )
    merged, groups = correlate_findings([flag, url])
    assert len(merged) == 1
    assert "secret-scanner" in merged[0].sources
    assert groups


def test_distinct_exported_components_do_not_merge() -> None:
    act = normalize_finding(
        source="manifest-scanner",
        rule_id="exported_activity",
        title="Exported activity without permission: .A",
        category=FindingCategory.COMPONENTS,
        severity=Severity.MEDIUM,
        confidence=0.9,
        description="a",
        affected_component=".A",
        evidence=[Evidence(kind="manifest_entry", summary=".A")],
    )
    svc = normalize_finding(
        source="manifest-scanner",
        rule_id="exported_service",
        title="Exported service without permission: .B",
        category=FindingCategory.COMPONENTS,
        severity=Severity.MEDIUM,
        confidence=0.9,
        description="b",
        affected_component=".B",
        evidence=[Evidence(kind="manifest_entry", summary=".B")],
    )
    merged, groups = correlate_findings([act, svc])
    assert len(merged) == 2
    assert not groups
    assert fingerprint_for(act) != fingerprint_for(svc)
