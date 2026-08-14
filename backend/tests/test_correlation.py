from app.analyzers.correlation import (
    correlate,
    correlate_findings,
    fingerprint_for,
    normalize_path,
    reconcile_confidence,
    reconcile_severity,
    select_primary,
)
from app.analyzers.findings import normalize_finding
from app.models.enums import FindingCategory, RelationshipType, Severity, Verification
from app.models.finding import Evidence
from app.models.scan_job import ScanJob
from app.reporters.markdown import MarkdownReporter


def _finding(
    source: str,
    rule_id: str,
    title: str,
    component: str,
    severity: Severity = Severity.MEDIUM,
    *,
    category: FindingCategory | None = None,
    confidence: float = 0.8,
    location: str | None = None,
    secret_type: str | None = None,
    extra_data: dict | None = None,
    verification: Verification | None = None,
):
    if category is None:
        if rule_id in {"cleartext_traffic", "http_endpoint"}:
            category = FindingCategory.NETWORK
        elif rule_id in {"hardcoded_secret", "private_key", "jwt", "cloud_credential"}:
            category = FindingCategory.SECRETS
        elif rule_id == "sdk_detected":
            category = FindingCategory.DEPENDENCY
        elif rule_id and rule_id.startswith("advisory_match"):
            category = FindingCategory.DEPENDENCY
        else:
            category = FindingCategory.MANIFEST
    data = dict(extra_data or {})
    if secret_type:
        data["secret_type"] = secret_type
        data["category"] = secret_type
    loc = location or component
    return normalize_finding(
        source=source,
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        description=title,
        evidence=[Evidence(kind="test", summary=title, location=loc, data=data)],
        affected_component=component,
        verification=verification,
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
    assert groups[0].relationship is RelationshipType.DUPLICATE
    assert groups[0].group_id == "CORR-001"


def test_related_http_url_groups_with_cleartext() -> None:
    flag = _finding("manifest-scanner", "cleartext_traffic", "Cleartext traffic enabled", "application")
    url = _finding(
        "secret-scanner",
        "http_endpoint",
        "HTTP (cleartext) URL referenced",
        "assets/config.json",
        Severity.INFO,
        location="assets/config.json:12",
    )
    merged, groups = correlate_findings([flag, url])
    assert len(merged) == 2
    related = [item for item in groups if item.relationship is RelationshipType.RELATED]
    assert len(related) == 1
    assert {flag.id, url.id} <= set(related[0].finding_ids)
    assert related[0].primary_finding_id == flag.id


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


def test_same_secret_from_two_scanners_merges() -> None:
    loc = "tools/jadx/output/com/example/ApiClient.java:42"
    secret = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Embedded Stripe Secret Key",
        loc,
        Severity.HIGH,
        confidence=0.92,
        location=loc,
        secret_type="stripe_key",
        verification=Verification.CONFIRMED,
    )
    mobsf = _finding(
        "mobsf",
        "hardcoded_secret",
        "Hardcoded API key",
        "./tools/jadx/output/com/example/ApiClient.java:42",
        Severity.HIGH,
        confidence=0.95,
        location="./tools/jadx/output/com/example/ApiClient.java:42",
        secret_type="stripe_key",
        verification=Verification.CONFIRMED,
    )
    result = correlate([secret, mobsf])
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].confidence > 0.95
    assert result.findings[0].confidence <= 1.0
    assert result.groups[0].relationship is RelationshipType.DUPLICATE
    assert len(result.raw_findings) == 2


def test_different_secrets_and_files_stay_independent() -> None:
    a = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Embedded Stripe Secret Key",
        "tools/jadx/output/a/File1.java:10",
        Severity.HIGH,
        location="tools/jadx/output/a/File1.java:10",
        secret_type="stripe_key",
    )
    b = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Embedded Stripe Secret Key",
        "tools/jadx/output/b/File2.java:10",
        Severity.HIGH,
        location="tools/jadx/output/b/File2.java:10",
        secret_type="stripe_key",
    )
    jwt = _finding(
        "secret-scanner",
        "jwt",
        "JWT detected",
        "tools/jadx/output/a/File1.java:10",
        Severity.HIGH,
        location="tools/jadx/output/a/File1.java:10",
        secret_type="jwt",
    )
    merged, groups = correlate_findings([a, b, jwt])
    assert len(merged) == 3
    assert not groups


def test_dependency_and_vulnerability_are_related() -> None:
    sdk = _finding(
        "dependency-scanner",
        "sdk_detected",
        "OkHttp detected",
        "OkHttp",
        Severity.INFO,
        confidence=0.95,
        verification=Verification.INFO,
    )
    vuln = _finding(
        "vulnerability-scanner",
        "advisory_match:GHSA-aaaa-bbbb-cccc",
        "Vulnerable OkHttp version",
        "com.squareup.okhttp3:okhttp",
        Severity.HIGH,
        confidence=0.99,
        extra_data={"package": "com.squareup.okhttp3:okhttp", "osv_id": "GHSA-aaaa-bbbb-cccc", "cve": ["CVE-2024-12345"]},
        verification=Verification.CONFIRMED,
    )
    result = correlate([sdk, vuln])
    assert len(result.findings) == 2
    support = [item for item in result.groups if item.relationship is RelationshipType.SUPPORTING_EVIDENCE]
    assert len(support) == 1
    assert support[0].primary_finding_id == vuln.id
    assert sdk.id in support[0].finding_ids
    assert select_primary([sdk, vuln]).id == vuln.id


def test_different_vulnerabilities_stay_separate() -> None:
    okhttp = _finding(
        "vulnerability-scanner",
        "advisory_match:GHSA-aaaa-bbbb-cccc",
        "Vulnerable OkHttp version",
        "com.squareup.okhttp3:okhttp",
        Severity.HIGH,
        extra_data={"package": "com.squareup.okhttp3:okhttp", "osv_id": "GHSA-aaaa-bbbb-cccc"},
    )
    retrofit = _finding(
        "vulnerability-scanner",
        "advisory_match:GHSA-dddd-eeee-ffff",
        "Vulnerable Retrofit version",
        "com.squareup.retrofit2:retrofit",
        Severity.HIGH,
        extra_data={"package": "com.squareup.retrofit2:retrofit", "osv_id": "GHSA-dddd-eeee-ffff"},
    )
    merged, groups = correlate_findings([okhttp, retrofit])
    assert len(merged) == 2
    assert not groups


def test_path_normalization_and_no_absolute_leak() -> None:
    relative = normalize_path("tools/jadx/output/a/b/File.java")
    dotted = normalize_path("./tools/jadx/output/a/b/File.java")
    absolute = normalize_path("/home/ubuntu/workspace/scans/abc/tools/jadx/output/a/b/File.java")
    assert relative == dotted == "tools/jadx/output/a/b/file.java"
    assert absolute == "tools/jadx/output/a/b/file.java"
    assert "home" not in absolute
    assert "/ubuntu" not in absolute
    a = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "key",
        "x",
        location="tools/jadx/output/a/b/File.java:42",
        secret_type="generic_api_key",
    )
    b = _finding(
        "mobsf",
        "hardcoded_secret",
        "key",
        "x",
        location="/tmp/machine/tools/jadx/output/a/b/File.java:42",
        secret_type="generic_api_key",
    )
    merged, groups = correlate_findings([a, b])
    assert len(merged) == 1
    assert groups[0].relationship is RelationshipType.DUPLICATE
    assert "/tmp/machine" not in (merged[0].fingerprint or "")


def test_fingerprint_never_contains_secret_material() -> None:
    token = "sk_live_" + "FAKEAPPPROBETESTONLY99"
    finding = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Embedded Stripe Secret Key",
        "tools/jadx/output/ApiClient.java:42",
        location="tools/jadx/output/ApiClient.java:42",
        secret_type="stripe_key",
        extra_data={"token": token, "redacted_value": "sk_live_********ONLY"},
    )
    finding.evidence[0].summary = f"key={token}"
    fp = fingerprint_for(finding)
    assert token not in fp
    assert "sk_live_" not in fp
    assert "FAKEAPPPROBETESTONLY99" not in fp
    result = correlate([finding])
    blob = result.groups[0].fingerprint if result.groups else fp
    assert token not in blob


def test_severity_reconciliation_uses_justified_maximum() -> None:
    medium = _finding("manifest-scanner", "cleartext_traffic", "a", "application", Severity.MEDIUM)
    high = _finding("mobsf", "cleartext_traffic", "b", "application", Severity.HIGH)
    assert reconcile_severity([medium, high]) is Severity.HIGH
    low = _finding("a", "allow_backup", "backup", "application", Severity.LOW)
    med = _finding("b", "allow_backup", "backup", "application", Severity.MEDIUM)
    assert reconcile_severity([low, med]) is Severity.MEDIUM
    confirmed_med = _finding(
        "manifest-scanner",
        "cleartext_traffic",
        "a",
        "application",
        Severity.MEDIUM,
        verification=Verification.CONFIRMED,
    )
    potential_high = _finding(
        "mobsf",
        "cleartext_traffic",
        "b",
        "application",
        Severity.HIGH,
        verification=Verification.POTENTIAL,
    )
    potential_high.potential = True
    assert reconcile_severity([confirmed_med, potential_high]) is Severity.MEDIUM


def test_confidence_corroboration_and_cap() -> None:
    a = _finding("secret-scanner", "hardcoded_secret", "s", "f:1", confidence=0.92, secret_type="stripe_key", location="f:1")
    b = _finding("mobsf", "hardcoded_secret", "s", "f:1", confidence=0.95, secret_type="stripe_key", location="f:1")
    combined = reconcile_confidence([a, b])
    assert combined > max(a.confidence, b.confidence)
    assert combined <= 1.0
    single = _finding("secret-scanner", "hardcoded_secret", "s", "g:1", confidence=0.84, secret_type="stripe_key", location="g:1")
    assert reconcile_confidence([single]) == 0.84


def test_same_vulnerability_from_two_scanners_merges() -> None:
    a = _finding(
        "vulnerability-scanner",
        "advisory_match:GHSA-aaaa-bbbb-cccc",
        "Vulnerable OkHttp version",
        "com.squareup.okhttp3:okhttp",
        Severity.HIGH,
        extra_data={"package": "com.squareup.okhttp3:okhttp", "osv_id": "GHSA-aaaa-bbbb-cccc"},
    )
    b = _finding(
        "mobsf",
        "advisory_match:GHSA-aaaa-bbbb-cccc",
        "OkHttp CVE",
        "com.squareup.okhttp3:okhttp",
        Severity.MEDIUM,
        extra_data={"package": "com.squareup.okhttp3:okhttp", "osv_id": "GHSA-aaaa-bbbb-cccc"},
    )
    merged, groups = correlate_findings([a, b])
    assert len(merged) == 1
    assert merged[0].severity is Severity.HIGH
    assert "GHSA-aaaa-bbbb-cccc" in (merged[0].rule_id or "")
    assert groups[0].relationship is RelationshipType.DUPLICATE


def test_over_correlation_similar_titles_stay_separate() -> None:
    one = _finding("manifest-scanner", "debuggable", "Debuggable application", "application")
    two = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Debuggable-looking comment",
        "tools/jadx/output/x.java:3",
        Severity.HIGH,
        location="tools/jadx/output/x.java:3",
        secret_type="generic_api_key",
    )
    merged, groups = correlate_findings([one, two])
    assert len(merged) == 2
    assert not groups


def test_group_ids_are_deterministic_and_stable() -> None:
    a = _finding("manifest-scanner", "cleartext_traffic", "Cleartext traffic enabled", "application")
    b = _finding("mobsf", "cleartext_traffic", "MobSF: cleartext traffic permitted", "application")
    first = correlate([a, b]).groups[0].group_id
    second = correlate([b, a]).groups[0].group_id
    assert first == second == "CORR-001"


def test_report_includes_correlation_summary_and_groups() -> None:
    secret = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Embedded Stripe Secret Key",
        "tools/jadx/output/ApiClient.java:42",
        Severity.HIGH,
        location="tools/jadx/output/ApiClient.java:42",
        secret_type="stripe_key",
    )
    mobsf = _finding(
        "mobsf",
        "hardcoded_secret",
        "Hardcoded API key",
        "tools/jadx/output/ApiClient.java:42",
        Severity.HIGH,
        location="tools/jadx/output/ApiClient.java:42",
        secret_type="stripe_key",
    )
    result = correlate([secret, mobsf])
    job = ScanJob(
        id="c1",
        filename="app.apk",
        artifact_path="app.apk",
        findings=result.findings,
        raw_findings=result.raw_findings,
        correlated_groups=result.groups,
        correlation_summary=result.summary,
    )
    markdown = MarkdownReporter().render(job)
    assert "## Correlation Summary" in markdown
    assert "Raw findings: 2" in markdown
    assert "Exact duplicates merged: 1" in markdown
    assert "CORR-001" in markdown
    assert "Relationship: DUPLICATE" in markdown
    assert "Primary Finding" in markdown
    assert "Correlation is deterministic and does not use AI." in markdown
    assert "| Correlation | EXECUTED |" in markdown


def test_manual_synthetic_set_end_to_end() -> None:
    stripe_loc = "tools/jadx/output/com/example/ApiClient.java:42"
    secret = _finding(
        "secret-scanner",
        "hardcoded_secret",
        "Embedded Stripe Secret Key",
        stripe_loc,
        Severity.HIGH,
        confidence=0.92,
        location=stripe_loc,
        secret_type="stripe_key",
        verification=Verification.CONFIRMED,
    )
    mobsf_secret = _finding(
        "mobsf",
        "hardcoded_secret",
        "Hardcoded API key",
        stripe_loc,
        Severity.HIGH,
        confidence=0.95,
        location=stripe_loc,
        secret_type="stripe_key",
        verification=Verification.CONFIRMED,
    )
    sdk = _finding(
        "dependency-scanner",
        "sdk_detected",
        "OkHttp detected",
        "OkHttp",
        Severity.INFO,
        verification=Verification.INFO,
    )
    vuln = _finding(
        "vulnerability-scanner",
        "advisory_match:GHSA-aaaa-bbbb-cccc",
        "Vulnerable OkHttp version",
        "com.squareup.okhttp3:okhttp",
        Severity.HIGH,
        extra_data={"package": "com.squareup.okhttp3:okhttp", "osv_id": "GHSA-aaaa-bbbb-cccc", "cve": ["CVE-2024-12345"]},
        verification=Verification.CONFIRMED,
    )
    cleartext = _finding("manifest-scanner", "cleartext_traffic", "Cleartext traffic enabled", "application")
    http = _finding(
        "secret-scanner",
        "http_endpoint",
        "HTTP (cleartext) URL referenced",
        "assets/config.json",
        Severity.INFO,
        location="assets/config.json:4",
    )
    result = correlate([secret, mobsf_secret, sdk, vuln, cleartext, http])
    assert len(result.raw_findings) == 6
    assert len(result.findings) == 5  # stripe pair merged
    dupes = [item for item in result.groups if item.relationship is RelationshipType.DUPLICATE]
    related = [item for item in result.groups if item.relationship is RelationshipType.RELATED]
    supporting = [item for item in result.groups if item.relationship is RelationshipType.SUPPORTING_EVIDENCE]
    assert len(dupes) == 1
    assert len(related) == 1
    assert len(supporting) == 1
    assert result.summary.exact_duplicates_merged == 1
    assert result.summary.related_groups == 2
    assert supporting[0].primary_finding_id == vuln.id
    job = ScanJob(
        id="manual",
        filename="app.apk",
        artifact_path="app.apk",
        findings=result.findings,
        raw_findings=result.raw_findings,
        correlated_groups=result.groups,
        correlation_summary=result.summary,
    )
    markdown = MarkdownReporter().render(job)
    assert "CORR-001" in markdown
    assert "Vulnerable OkHttp" in markdown or "OkHttp" in markdown
    assert "sk_live_" not in markdown
    assert len(job.raw_findings) == 6
    assert result.summary.raw_findings == 6
