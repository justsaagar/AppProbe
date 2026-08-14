"""Deterministic Markdown security report generator."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.analyzers.correlation import FindingGroup
from app.analyzers.severity import overall_risk, rank
from app.models.enums import Severity
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.utils.redaction import redact_text

REPORT_SECTIONS = [
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
]


def generate_markdown_report(
    *,
    job: ScanJob,
    findings: list[Finding],
    groups: list[FindingGroup],
    metadata: dict[str, Any],
    coverage: dict[str, Any],
) -> str:
    risk = overall_risk(findings)
    counts = Counter(item.severity.value for item in findings)
    lines: list[str] = []
    lines.append(f"# Security Report — {job.filename}")
    lines.append("")
    lines.append(f"Scan ID: `{job.id}`")
    lines.append("")
    lines.append("This report is produced by deterministic static analysis. ")
    lines.append("The LLM reasoning layer was **not** used in Milestone 1.")
    lines.append("")

    _h(lines, "1. Executive Summary")
    lines.append(_executive_summary(job, findings, risk, coverage))
    lines.append("")

    _h(lines, "2. Application Information")
    lines.extend(_kv_table(_application_info(job, metadata)))
    lines.append("")

    _h(lines, "3. Scan Environment")
    lines.extend(
        _kv_table(
            {
                "Host analysis": "Local AppProbe backend (Milestone 1)",
                "Static tooling": "Built-in ZIP validation + AndroidManifest parser",
                "MobSF": "Not integrated",
                "JADX / apktool": "Not integrated",
                "bundletool": "Not integrated",
                "Android Emulator / ADB": "Not executed",
                "mitmproxy": "Not executed",
                "LLM": "Not executed",
            }
        )
    )
    lines.append("")

    _h(lines, "4. Testing Coverage")
    lines.append(f"Dynamic Testing Coverage: **{coverage.get('dynamic_percent', 0)}%**")
    lines.append("")
    unverified = coverage.get("unverified") or []
    if unverified:
        lines.append("The following areas could not be verified:")
        for item in unverified:
            lines.append(f"- {item}")
        lines.append("")
    lines.append("Never interpret this scan as complete application coverage.")
    lines.append("")

    _h(lines, "5. Overall Risk")
    lines.append(f"**{risk.value if risk else 'NONE'}**")
    lines.append("")
    lines.append(
        "Overall risk is the highest severity among confirmed static findings."
        " Informational items (permissions, libraries) do not raise overall risk by themselves."
    )
    lines.append("")

    _h(lines, "6. Severity Summary")
    for sev in Severity:
        lines.append(f"- {sev.value}: {counts.get(sev.value, 0)}")
    lines.append("")
    if groups:
        lines.append("Related finding groups:")
        for group in groups:
            lines.append(f"- **{group.title}** ({group.relationship}): {', '.join(group.finding_ids)}")
            if group.root_cause:
                lines.append(f"  - {group.root_cause}")
        lines.append("")

    severity_headings = {
        Severity.CRITICAL: "Critical Findings",
        Severity.HIGH: "High Findings",
        Severity.MEDIUM: "Medium Findings",
        Severity.LOW: "Low Findings",
        Severity.INFO: "Informational Findings",
    }
    for index, sev in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO],
        start=7,
    ):
        _h(lines, f"{index}. {severity_headings[sev]}")
        subset = [item for item in findings if item.severity == sev]
        if not subset:
            lines.append("None.")
            lines.append("")
            continue
        for finding in sorted(subset, key=lambda item: (-item.confidence, item.title)):
            lines.extend(_render_finding(finding))
        lines.append("")

    _h(lines, "12. Functional Test Results")
    lines.append("Functional testing was **not executed** in Milestone 1.")
    lines.append("")
    lines.append("Runtime Testing: **NOT EXECUTED**")
    lines.append(f"Reason: {coverage.get('runtime_reason', 'Android Emulator unavailable')}")
    lines.append("")

    _h(lines, "13. Crash Analysis")
    lines.append("Crash monitoring was not executed because the application was not launched.")
    lines.append("")

    _h(lines, "14. Network Analysis")
    lines.append(
        "Network interception was not executed. No HTTP/HTTPS traffic was observed."
        " Certificate pinning was not evaluated."
    )
    lines.append("")

    _h(lines, "15. Permissions")
    permissions = metadata.get("permissions") or []
    if permissions:
        for perm in permissions:
            lines.append(f"- `{perm}`")
    else:
        lines.append("No uses-permission entries were parsed, or the platform has no Android permission list.")
    lines.append("")

    _h(lines, "16. Dependencies")
    lines.append(
        "Dependency and known-vulnerable library analysis is not implemented in Milestone 1."
        " No dependency findings are reported."
    )
    lines.append("")

    _h(lines, "17. Technology Detection")
    tech = metadata.get("technology") or {}
    if tech:
        lines.extend(_kv_table(tech))
    else:
        lines.append("Limited to platform/package metadata extracted from the artifact.")
    native = metadata.get("native_libraries") or []
    if native:
        lines.append("")
        lines.append("Native libraries:")
        for lib in native[:50]:
            lines.append(f"- `{lib}`")
    lines.append("")

    _h(lines, "18. Screenshots/Evidence")
    lines.append("No runtime screenshots were captured.")
    lines.append("")
    lines.append("Static evidence is attached to each finding above. Snippets are redacted when they may contain secrets.")
    lines.append("")

    _h(lines, "19. Remediation Recommendations")
    recs = [item for item in findings if item.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}]
    recs = sorted(recs, key=lambda item: rank(item.severity), reverse=True)
    if not recs:
        lines.append("No medium-or-higher static findings were confirmed.")
    else:
        for finding in recs:
            lines.append(f"- **{finding.title}**: {finding.recommendation}")
    lines.append("")

    _h(lines, "20. Limitations")
    for note in coverage.get("limitations") or []:
        lines.append(f"- {note}")
    lines.append("")

    _h(lines, "21. Scan Metadata")
    lines.extend(
        _kv_table(
            {
                "scan_id": job.id,
                "status": job.status.value,
                "created_at": _ts(job.created_at),
                "started_at": _ts(job.started_at),
                "completed_at": _ts(job.completed_at),
                "artifact_path": job.artifact_path or "",
                "report_generated_at": datetime.now(UTC).isoformat(),
                "skipped_stages": ", ".join(job.skipped_stages) or "none",
            }
        )
    )
    if job.stage_notes:
        lines.append("")
        lines.append("Stage notes:")
        for stage, note in job.stage_notes.items():
            lines.append(f"- {stage}: {note}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_report(path: Path, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_text(markdown), encoding="utf-8")


def _h(lines: list[str], title: str) -> None:
    lines.append(f"## {title}")
    lines.append("")


def _ts(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def _kv_table(mapping: dict[str, Any]) -> list[str]:
    lines = ["| Field | Value |", "| --- | --- |"]
    for key, value in mapping.items():
        text = "" if value is None else str(value).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {key} | {text} |")
    return lines


def _application_info(job: ScanJob, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": job.filename,
        "platform": job.platform.value,
        "artifact_kind": job.artifact_kind.value,
        "package_name": metadata.get("package_name") or metadata.get("bundle_id") or "",
        "version_name": metadata.get("version_name") or metadata.get("version") or "",
        "version_code": metadata.get("version_code") or metadata.get("build") or "",
        "min_sdk": metadata.get("min_sdk") or metadata.get("minimum_os_version") or "",
        "target_sdk": metadata.get("target_sdk") or "",
        "debuggable": metadata.get("debuggable"),
        "allow_backup": metadata.get("allow_backup"),
        "uses_cleartext_traffic": metadata.get("uses_cleartext_traffic"),
    }


def _executive_summary(
    job: ScanJob,
    findings: list[Finding],
    risk: Severity | None,
    coverage: dict[str, Any],
) -> str:
    high = sum(1 for item in findings if item.severity in {Severity.CRITICAL, Severity.HIGH})
    return (
        f"AppProbe analyzed `{job.filename}` ({job.artifact_kind.value}) using Milestone 1 static"
        f" manifest/metadata checks. Overall risk: **{risk.value if risk else 'NONE'}**."
        f" {high} critical/high finding(s) were confirmed from scanner evidence."
        f" Dynamic testing was not executed ({coverage.get('runtime_reason', 'not available')})."
        " No MobSF, JADX, emulator, network, or LLM results are included because those integrations"
        " are not implemented yet."
    )


def _render_finding(finding: Finding) -> list[str]:
    label = "Potential Finding" if finding.potential else "Finding"
    lines = [
        f"### {label}: {finding.title}",
        "",
        f"- ID: `{finding.id}`",
        f"- Severity: {finding.severity.value} (confidence {finding.confidence:.2f})",
        f"- Category: {finding.category.value}",
        f"- Source: {finding.source}",
        f"- Rule: {finding.rule_id or 'n/a'}",
        f"- Component: {finding.affected_component or 'n/a'}",
        f"- CWE: {finding.cwe or ''}",
        f"- OWASP: {finding.owasp or ''}",
        f"- MASVS: {finding.masvs or ''}",
        "",
        finding.description,
        "",
        f"**Impact:** {finding.impact}",
        "",
        f"**Recommendation:** {finding.recommendation}",
        "",
        f"**Reproducibility:** {finding.reproducibility or 'Not specified'}",
        "",
        "**Evidence:**",
    ]
    if not finding.evidence:
        lines.append("- No evidence attached (should not occur for confirmed findings).")
    for item in finding.evidence:
        snippet = redact_text(item.snippet or "")
        location = item.location or ""
        lines.append(f"- [{item.kind}] {item.summary}" + (f" (`{location}`)" if location else ""))
        if snippet:
            lines.append(f"  - `{snippet}`")
    lines.append("")
    return lines
