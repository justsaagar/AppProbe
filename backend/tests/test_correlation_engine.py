from app.analyzers.correlation import correlate_findings
from app.analyzers.normalize import normalize_finding
from app.models.enums import FindingCategory


def _finding(rule_id: str, component: str, finding_id: str):
    return normalize_finding(
        {
            "id": finding_id,
            "title": f"{rule_id}:{component}",
            "rule_id": rule_id,
            "affected_component": component,
            "category": FindingCategory.COMPONENTS,
            "severity": "HIGH",
            "confidence": 0.8,
            "evidence": [{"kind": "manifest_entry", "summary": finding_id}],
        },
        index=0,
        source="test",
    )


def test_merges_duplicate_rule_and_component() -> None:
    first = _finding("ANDROID_EXPORTED_ACTIVITY", ".Main", "a")
    second = _finding("ANDROID_EXPORTED_ACTIVITY", ".Main", "b")
    second.title = first.title
    merged, _groups = correlate_findings([first, second])
    match = [item for item in merged if item.rule_id == "ANDROID_EXPORTED_ACTIVITY"]
    assert len(match) == 1
    assert len(match[0].evidence) == 2


def test_groups_related_exported_components() -> None:
    findings = [
        _finding("ANDROID_EXPORTED_ACTIVITY", ".Main", "a"),
        _finding("ANDROID_EXPORTED_SERVICE", ".Sync", "b"),
    ]
    _merged, groups = correlate_findings(findings)
    assert any(group.id == "group-exported-components" for group in groups)
    exported_group = next(group for group in groups if group.id == "group-exported-components")
    assert set(exported_group.finding_ids) == {"a", "b"}
