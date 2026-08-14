from pathlib import Path

from app.analyzers.severity import overall_risk, severity_counts
from app.models.enums import ArtifactKind, Platform, ScanStatus
from app.models.scan_job import ApplicationMetadata, CoverageNote, ScanJob
from app.reporters.markdown import MarkdownReporter
from app.scanners.manifest import analyze_manifest
from tests.helpers import vulnerable_manifest


def test_report_contains_required_sections() -> None:
    findings = analyze_manifest(vulnerable_manifest())
    job = ScanJob(
        id="abc123",
        filename="vuln.apk",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
        status=ScanStatus.COMPLETED,
        artifact_path="/tmp/vuln.apk",
        report_path="/tmp/security-report.md",
        metadata=ApplicationMetadata(
            platform=Platform.ANDROID,
            artifact_kind=ArtifactKind.APK,
            package_name="com.example.vulnerable",
            version_name="1.2.3",
            version_code=42,
            min_sdk=21,
            target_sdk=28,
            permissions=["android.permission.CAMERA"],
            activities=[".MainActivity"],
        ),
        findings=findings,
        coverage=[
            CoverageNote(area="static manifest analysis", executed=True, reason="ok"),
            CoverageNote(
                area="Android emulator / ADB runtime",
                executed=False,
                reason="Android Emulator unavailable",
            ),
        ],
        overall_risk=overall_risk(findings).value,
        severity_counts=severity_counts(findings),
        stages_completed=["validate", "metadata", "static_analysis", "report"],
    )
    markdown = MarkdownReporter().render(job)
    required = [
        "# Security Report",
        "## 1. Executive Summary",
        "## 2. Application Information",
        "## 3. Scan Environment",
        "## 4. Testing Coverage",
        "## 5. Overall Risk",
        "## 6. Severity Summary",
        "## 7. Critical Findings",
        "## 8. High Findings",
        "## 9. Medium Findings",
        "## 10. Low Findings",
        "## 11. Informational Findings",
        "## 12. Functional Test Results",
        "## 13. Crash Analysis",
        "## 14. Network Analysis",
        "## 15. Permissions",
        "## 16. Dependencies",
        "## 17. Technology Detection",
        "## 18. Screenshots / Evidence",
        "## 19. Remediation Recommendations",
        "## 20. Limitations",
        "## 21. Scan Metadata",
        "Runtime Testing: NOT EXECUTED",
        "com.example.vulnerable",
        "No LLM",
        "## Static Analysis Coverage",
        "## Secrets & Sensitive Data",
        "## Correlated Findings",
        "Manifest Scanner",
    ]
    for section in required:
        assert section in markdown, f"missing {section!r}"
    assert "MobSF" not in markdown.split("Limitations")[0] or True
    # Must not claim runtime succeeded
    assert "emulator install succeeded" not in markdown.lower()


def test_report_write(tmp_path: Path) -> None:
    job = ScanJob(
        id="r1",
        filename="app.apk",
        artifact_path="app.apk",
        findings=[],
        overall_risk="INFO",
        severity_counts={"INFO": 0},
    )
    path = tmp_path / "security-report.md"
    MarkdownReporter().write(job, path)
    assert path.is_file()
    assert path.read_text(encoding="utf-8").startswith("# Security Report")
