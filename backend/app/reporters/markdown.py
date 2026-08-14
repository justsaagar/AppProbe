"""Deterministic Markdown report generator. Does not invent evidence or coverage."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.models.enums import Severity
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.utils.redact import redact_text

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class MarkdownReporter:
    def render(self, job: ScanJob) -> str:
        sections = [
            self._title(job),
            self._executive_summary(job),
            self._application_information(job),
            self._scan_environment(job),
            self._testing_coverage(job),
            self._overall_risk(job),
            self._severity_summary(job),
            *self._findings_by_severity(job),
            self._functional_tests(job),
            self._crash_analysis(job),
            self._network_analysis(job),
            self._permissions(job),
            self._dependencies(job),
            self._technology(job),
            self._screenshots(job),
            self._remediation(job),
            self._limitations(job),
            self._scan_metadata(job),
        ]
        return redact_text("\n\n".join(section for section in sections if section) + "\n")

    def write(self, job: ScanJob, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(job), encoding="utf-8")
        return path

    def _title(self, job: ScanJob) -> str:
        return f"# Security Report\n\nScan ID: `{job.id}`  \nArtifact: `{job.filename}`  \nGenerated: {datetime.now(timezone.utc).isoformat()}"

    def _executive_summary(self, job: ScanJob) -> str:
        meta = job.metadata
        pkg = meta.package_name if meta else "unknown"
        counts = job.severity_counts
        risk = job.overall_risk or "INFO"
        lines = [
            "## 1. Executive Summary",
            "",
            f"AppProbe completed Milestone 1 static analysis of `{job.filename}` "
            f"(package `{pkg}`).",
            "",
            f"**Overall risk:** {risk}",
            "",
            "Finding counts:",
            "",
            f"- CRITICAL: {counts.get('CRITICAL', 0)}",
            f"- HIGH: {counts.get('HIGH', 0)}",
            f"- MEDIUM: {counts.get('MEDIUM', 0)}",
            f"- LOW: {counts.get('LOW', 0)}",
            f"- INFO: {counts.get('INFO', 0)}",
            "",
            "This report is produced by deterministic scanners. "
            "No LLM, emulator, network interceptor, or third-party static engine "
            "(MobSF, JADX, apktool) was invoked.",
        ]
        return "\n".join(lines)

    def _application_information(self, job: ScanJob) -> str:
        meta = job.metadata
        lines = ["## 2. Application Information", ""]
        if meta is None:
            lines.append("Metadata extraction did not produce a result.")
            return "\n".join(lines)
        rows = [
            ("Platform", meta.platform.value),
            ("Artifact kind", meta.artifact_kind.value),
            ("Package / bundle ID", meta.package_name or "unknown"),
            ("Version name", meta.version_name or "unknown"),
            ("Version code", str(meta.version_code) if meta.version_code is not None else "unknown"),
            ("minSdk", str(meta.min_sdk) if meta.min_sdk is not None else "unknown"),
            ("targetSdk", str(meta.target_sdk) if meta.target_sdk is not None else "unknown"),
            ("Main activity", meta.main_activity or "not detected"),
            ("Activities", str(len(meta.activities))),
            ("Services", str(len(meta.services))),
            ("Receivers", str(len(meta.receivers))),
            ("Providers", str(len(meta.providers))),
            ("Permissions", str(len(meta.permissions))),
            ("Native libraries", str(len(meta.native_libraries))),
        ]
        lines.extend(_table(["Field", "Value"], rows))
        if meta.extra:
            lines.extend(["", "Additional metadata:", "", "```json", _json(meta.extra), "```"])
        return "\n".join(lines)

    def _scan_environment(self, job: ScanJob) -> str:
        return "\n".join(
            [
                "## 3. Scan Environment",
                "",
                "- Analyzer: AppProbe Milestone 1 (custom AXML / manifest scanner)",
                "- Host isolation: per-scan workspace under `workspace/scans/<id>`",
                "- Runtime: not prepared",
                "- Network interception: not prepared",
                "- AI provider: not configured / not invoked",
            ]
        )

    def _testing_coverage(self, job: ScanJob) -> str:
        lines = ["## 4. Testing Coverage", ""]
        executed = [note for note in job.coverage if note.executed]
        skipped = [note for note in job.coverage if not note.executed]
        total = len(job.coverage) or 1
        percent = int(round(100 * len(executed) / total))
        lines.append("**Dynamic Testing Coverage:** not applicable (static-only milestone).")
        lines.append("")
        lines.append(f"**Declared analysis areas executed:** {percent}% ({len(executed)}/{total})")
        lines.append("")
        lines.append("Never interpret this percentage as application UI coverage. It is the share of pipeline stages that actually ran.")
        lines.append("")
        if executed:
            lines.append("Executed:")
            for note in executed:
                lines.append(f"- {note.area}")
        if skipped:
            lines.append("")
            lines.append("The following areas could not be verified:")
            for note in skipped:
                lines.append(f"- {note.area}: {note.reason}")
        return "\n".join(lines)

    def _overall_risk(self, job: ScanJob) -> str:
        return "\n".join(
            [
                "## 5. Overall Risk",
                "",
                f"**{job.overall_risk or 'INFO'}**",
                "",
                "Overall risk is the highest severity among confirmed (non-potential) findings. "
                "Potential findings cannot raise the score to CRITICAL.",
            ]
        )

    def _severity_summary(self, job: ScanJob) -> str:
        counts = job.severity_counts
        rows = [(sev.value, str(counts.get(sev.value, 0))) for sev in SEVERITY_ORDER]
        return "\n".join(["## 6. Severity Summary", ""] + _table(["Severity", "Count"], rows))

    def _findings_by_severity(self, job: ScanJob) -> list[str]:
        headings = {
            Severity.CRITICAL: "## 7. Critical Findings",
            Severity.HIGH: "## 8. High Findings",
            Severity.MEDIUM: "## 9. Medium Findings",
            Severity.LOW: "## 10. Low Findings",
            Severity.INFO: "## 11. Informational Findings",
        }
        sections = []
        for severity in SEVERITY_ORDER:
            items = [f for f in job.findings if f.severity is severity]
            lines = [headings[severity], ""]
            if not items:
                lines.append("_None._")
            else:
                for finding in items:
                    lines.append(self._render_finding(finding))
            sections.append("\n".join(lines))
        return sections

    def _render_finding(self, finding: Finding) -> str:
        lines = [
            f"### {finding.display_title()}",
            "",
            f"- ID: `{finding.id}`",
            f"- Severity: {finding.severity.value}",
            f"- Confidence: {finding.confidence:.2f}",
            f"- Category: {finding.category}",
            f"- Source: `{finding.source}`",
            f"- Component: `{finding.affected_component or 'n/a'}`",
        ]
        if finding.cwe:
            lines.append(f"- CWE: {finding.cwe}")
        if finding.owasp:
            lines.append(f"- OWASP Mobile: {finding.owasp}")
        if finding.masvs:
            lines.append(f"- MASVS: {finding.masvs}")
        lines.extend(["", finding.description, ""])
        if finding.impact:
            lines.extend(["**Impact**", "", finding.impact, ""])
        if finding.recommendation:
            lines.extend(["**Recommendation**", "", finding.recommendation, ""])
        if finding.reproducibility:
            lines.extend(["**Reproducibility**", "", finding.reproducibility, ""])
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            for item in finding.evidence:
                loc = f" ({item.location})" if item.location else ""
                lines.append(f"- `{item.kind}`{loc}: {item.summary}")
        else:
            lines.append("_No evidence attached; treat as unverified._")
        lines.append("")
        return "\n".join(lines)

    def _functional_tests(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 12. Functional Test Results",
                "",
                "Functional UI testing was **not executed**. Automated exploration is Milestone 4.",
            ]
        )

    def _crash_analysis(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 13. Crash Analysis",
                "",
                "Crash monitoring was **not executed** (no runtime).",
            ]
        )

    def _network_analysis(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 14. Network Analysis",
                "",
                "Runtime Testing: NOT EXECUTED",
                "",
                "Reason: Network interception (mitmproxy) and Android Emulator are not part of Milestone 1.",
                "",
                "Certificate pinning was not evaluated. Absence of interception is not classified as a vulnerability.",
            ]
        )

    def _permissions(self, job: ScanJob) -> str:
        lines = ["## 15. Permissions", ""]
        meta = job.metadata
        if not meta or not meta.permissions:
            lines.append("No `uses-permission` entries were detected, or metadata is unavailable.")
            return "\n".join(lines)
        rows = [(perm,) for perm in meta.permissions]
        lines.extend(_table(["Permission"], rows))
        return "\n".join(lines)

    def _dependencies(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 16. Dependencies",
                "",
                "Dependency / SDK vulnerability scanning was **not executed**. Planned for Milestone 2.",
            ]
        )

    def _technology(self, job: ScanJob) -> str:
        meta = job.metadata
        lines = ["## 17. Technology Detection", ""]
        if meta is None:
            lines.append("Not available.")
            return "\n".join(lines)
        lines.append(f"- Platform: {meta.platform.value}")
        lines.append(f"- Packaging: {meta.artifact_kind.value}")
        if meta.native_libraries:
            lines.append(f"- Native libraries ({len(meta.native_libraries)}):")
            for lib in meta.native_libraries[:50]:
                lines.append(f"  - `{lib}`")
        else:
            lines.append("- Native libraries: none listed in the archive")
        lines.append("- DEX / JADX decompilation: not executed (Milestone 2)")
        return "\n".join(lines)

    def _screenshots(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 18. Screenshots / Evidence",
                "",
                "No runtime screenshots were captured.",
                "",
                "Static evidence is attached to individual findings (manifest entries, archive metadata).",
            ]
        )

    def _remediation(self, job: ScanJob) -> str:
        lines = ["## 19. Remediation Recommendations", ""]
        actionable = [
            f
            for f in job.findings
            if f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM} and f.recommendation
        ]
        if not actionable:
            lines.append("No CRITICAL/HIGH/MEDIUM items produced a remediation action in this scan.")
            return "\n".join(lines)
        for finding in actionable:
            lines.append(f"- **{finding.display_title()}:** {finding.recommendation}")
        return "\n".join(lines)

    def _limitations(self, job: ScanJob) -> str:
        lines = [
            "## 20. Limitations",
            "",
            "This is a Milestone 1 report. The following were **not** performed:",
            "",
            "- MobSF / JADX / apktool / bundletool scans",
            "- Secret scanning beyond future Milestone 2 detectors",
            "- Finding correlation / duplicate merging",
            "- Android emulator install, launch, UI exploration",
            "- logcat / crash / ANR collection",
            "- Network interception",
            "- LLM reasoning or AI-adjusted severity",
            "- iOS dynamic testing",
            "",
            "Do not treat skipped areas as passing tests.",
        ]
        if job.error:
            lines.extend(["", f"Job error/warning: {job.error}"])
        return "\n".join(lines)

    def _scan_metadata(self, job: ScanJob) -> str:
        rows = [
            ("Scan ID", job.id),
            ("Status", job.status.value),
            ("Progress", str(job.progress)),
            ("Created", job.created_at.isoformat()),
            ("Started", job.started_at.isoformat() if job.started_at else "n/a"),
            ("Completed", job.completed_at.isoformat() if job.completed_at else "n/a"),
            ("Artifact path", job.artifact_path),
            ("Report path", job.report_path or "n/a"),
            ("Stages", ", ".join(job.stages_completed) or "none"),
        ]
        return "\n".join(["## 21. Scan Metadata", ""] + _table(["Field", "Value"], rows))


def _table(headers: list[str], rows: list[tuple[str, ...]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        escaped = [str(cell).replace("|", "\\|") for cell in row]
        lines.append("| " + " | ".join(escaped) + " |")
    return lines


def _json(value: object) -> str:
    import json

    return json.dumps(value, indent=2, default=str)
