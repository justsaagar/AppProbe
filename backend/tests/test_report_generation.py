import pytest

from app.analyzers.axml import parse_manifest_bytes
from app.analyzers.correlation import correlate_findings
from app.analyzers.manifest_parser import parse_android_metadata
from app.analyzers.severity import overall_risk
from app.models.enums import ArtifactKind, Platform, ScanStatus
from app.models.scan_job import ScanJob
from app.reporters.markdown import generate_markdown_report
from app.scanners.base import ScanContext
from app.scanners.manifest import ManifestScanner
from tests.helpers.apk_builder import build_text_manifest


@pytest.mark.asyncio
async def test_report_contains_required_sections_and_honest_coverage() -> None:
    xml = build_text_manifest(
        package="com.report.app",
        debuggable=True,
        cleartext=True,
        permissions=["android.permission.CAMERA"],
        activities=[{"name": ".MainActivity", "exported": True, "launcher": True}],
    )
    metadata = parse_android_metadata(parse_manifest_bytes(xml.encode("utf-8")))
    job = ScanJob(id="scan-report", filename="app.apk", status=ScanStatus.QUEUED)
    job.transition(ScanStatus.VALIDATING)
    job.transition(ScanStatus.STATIC_ANALYSIS)
    job.transition(ScanStatus.PREPARING_RUNTIME)
    job.transition(ScanStatus.DYNAMIC_ANALYSIS)
    job.transition(ScanStatus.AI_ANALYSIS)
    job.transition(ScanStatus.GENERATING_REPORT)
    context = ScanContext(
        job=job,
        artifact_path="app.apk",
        kind=ArtifactKind.APK,
        platform=Platform.ANDROID,
        metadata={"manifest_member": "AndroidManifest.xml"},
        android=metadata,
    )
    findings = await ManifestScanner().scan("app.apk", context)
    findings, groups = correlate_findings(findings)
    markdown = generate_markdown_report(
        job=job,
        findings=findings,
        groups=groups,
        metadata=metadata.to_dict(),
        coverage={
            "dynamic_percent": 0,
            "runtime_reason": "Android Emulator unavailable",
            "unverified": ["iOS runtime", "Android emulator"],
            "limitations": ["Milestone 1 static analysis only"],
        },
    )
    for section in [
        "Executive Summary",
        "Application Information",
        "Scan Environment",
        "Testing Coverage",
        "Overall Risk",
        "Severity Summary",
        "Critical Findings",
        "High Findings",
        "Medium Findings",
        "Low Findings",
        "Informational Findings",
        "Functional Test Results",
        "Crash Analysis",
        "Network Analysis",
        "Permissions",
        "Dependencies",
        "Technology Detection",
        "Screenshots/Evidence",
        "Remediation Recommendations",
        "Limitations",
        "Scan Metadata",
    ]:
        assert section in markdown
    assert "Dynamic Testing Coverage: **0%**" in markdown
    assert "Runtime Testing: **NOT EXECUTED**" in markdown
    assert "Android Emulator unavailable" in markdown
    assert "MobSF" in markdown
    assert "Not integrated" in markdown
    assert "LLM reasoning layer was **not** used" in markdown
    assert "com.report.app" in markdown
    assert overall_risk(findings) is not None
    assert "100%" not in markdown.split("Dynamic Testing Coverage")[1][:80]
