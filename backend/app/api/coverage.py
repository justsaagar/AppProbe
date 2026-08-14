"""Safe dashboard projections. Never include secrets, API keys, or host paths."""

from __future__ import annotations

from app.models.enums import Platform, ToolStatus
from app.models.scan_job import ScanJob
from app.schemas.scan import PipelineStage, ScannerStatusItem

_STATUS_LABELS = {
    ToolStatus.AVAILABLE_AND_EXECUTED: "EXECUTED",
    ToolStatus.AVAILABLE_BUT_FAILED: "FAILED",
    ToolStatus.NOT_AVAILABLE: "NOT AVAILABLE",
    ToolStatus.NOT_EXECUTED: "NOT EXECUTED",
    ToolStatus.TIMEOUT: "TIMEOUT",
    ToolStatus.NOT_ENABLED: "NOT ENABLED",
    ToolStatus.AUTH_FAILED: "AUTH FAILED",
}

_PIPELINE: list[tuple[str, str, tuple[str, ...]]] = [
    ("validate", "Artifact validation", ("validate",)),
    ("metadata", "Metadata extraction", ("metadata",)),
    ("manifest", "Manifest analysis", ("manifest",)),
    ("mobsf", "MobSF", ()),
    ("jadx", "JADX", ()),
    ("apktool", "apktool", ()),
    ("secrets", "Secret scanner", ("secret-scanner", "secret-scanner_skipped")),
    ("dependencies", "Dependency scanner", ("dependency-scanner", "dependency-scanner_skipped")),
    ("vulnerabilities", "Vulnerability scanner", ("vulnerability-scanner", "vulnerability-scanner_skipped")),
    ("correlation", "Correlation", ("correlation",)),
    ("report", "Report", ("report",)),
]


def tool_status_label(status: ToolStatus) -> str:
    return _STATUS_LABELS.get(status, status.value)


def scanner_coverage(job: ScanJob) -> list[ScannerStatusItem]:
    by_name = {run.name: run for run in job.tool_runs}
    android = job.platform is not Platform.IOS
    executed = ToolStatus.AVAILABLE_AND_EXECUTED
    skipped = ToolStatus.NOT_EXECUTED
    items: list[ScannerStatusItem] = [
        _item(
            "manifest",
            "Manifest Scanner",
            executed if android else skipped,
            "AppProbe",
            "Custom manifest scanner" if android else "Not applicable for this artifact",
        )
    ]
    for key, label in (("jadx", "JADX"), ("apktool", "apktool"), ("mobsf", "MobSF")):
        run = by_name.get(key)
        if run is None:
            default = "NOT ENABLED" if key == "mobsf" else "NOT AVAILABLE"
            items.append(
                ScannerStatusItem(id=key, name=label, status=default, version=None, reason="")
            )
        else:
            version = run.version
            if key == "mobsf" and run.status is executed and not version:
                version = (job.mobsf_analysis.version if job.mobsf_analysis else None) or "Unknown"
            items.append(
                ScannerStatusItem(
                    id=key,
                    name=label,
                    status=tool_status_label(run.status),
                    version=version,
                    reason=run.reason,
                )
            )
    secret = executed if android else skipped
    secret_reason = ""
    if job.secret_scan_coverage and job.secret_scan_coverage.sources:
        secret_reason = ", ".join(job.secret_scan_coverage.sources)
    items.append(_item("secrets", "Secret Scanner", secret, "AppProbe", secret_reason))
    items.append(
        _item(
            "dependencies",
            "Dependency Scanner",
            executed if android else skipped,
            "AppProbe",
            "",
        )
    )
    vuln_status = skipped
    vuln_reason = ""
    vuln_version = "OSV"
    if android:
        assessment = job.vulnerability_assessment
        if assessment is None:
            vuln_status = ToolStatus.NOT_EXECUTED
        elif assessment.status == "COMPLETE":
            vuln_status = executed
            vuln_reason = assessment.reason
        elif assessment.status == "NOT_AVAILABLE":
            vuln_status = ToolStatus.NOT_AVAILABLE
            vuln_reason = assessment.reason
        else:
            vuln_status = ToolStatus.AVAILABLE_BUT_FAILED
            vuln_reason = assessment.reason
        vuln_version = (assessment.advisory_source if assessment else None) or "OSV"
    items.append(_item("vulnerabilities", "Vulnerability Scanner", vuln_status, vuln_version, vuln_reason))
    corr_status = (
        executed
        if job.correlation_summary is not None
        or any(note.area == "finding correlation" and note.executed for note in job.coverage)
        else skipped
    )
    items.append(_item("correlation", "Correlation", corr_status, "AppProbe", ""))
    return items


def pipeline_stages(job: ScanJob) -> list[PipelineStage]:
    completed = set(job.stages_completed)
    current = (job.current_stage or "").lower()
    terminal = job.status.value in {"COMPLETED", "FAILED", "PARTIAL"}
    stages: list[PipelineStage] = []
    seen_running = False
    for stage_id, label, aliases in _PIPELINE:
        status = _stage_status(job, stage_id, aliases, completed, current, terminal, seen_running)
        if status == "running":
            seen_running = True
        stages.append(PipelineStage(id=stage_id, label=label, status=status))
    return stages


def _stage_status(
    job: ScanJob,
    stage_id: str,
    aliases: tuple[str, ...],
    completed: set[str],
    current: str,
    terminal: bool,
    seen_running: bool,
) -> str:
    if stage_id in {"jadx", "apktool", "mobsf"}:
        run = next((item for item in job.tool_runs if item.name == stage_id), None)
        if run is not None:
            mapped = tool_status_label(run.status)
            if mapped == "EXECUTED":
                return "completed"
            if mapped == "FAILED":
                return "failed"
            if mapped == "TIMEOUT":
                return "failed"
            if mapped == "NOT ENABLED":
                return "not_enabled"
            if mapped == "AUTH FAILED":
                return "failed"
            if mapped == "NOT AVAILABLE":
                return "unavailable"
            if mapped == "NOT EXECUTED":
                return "skipped"
        if any(item.startswith(f"{stage_id}_") for item in completed):
            return "completed"
    elif any(alias in completed for alias in aliases):
        if stage_id in {"secrets", "dependencies", "vulnerabilities"} and any(
            alias.endswith("_skipped") and alias in completed for alias in aliases
        ):
            return "skipped"
        return "completed"

    if terminal:
        return "pending" if job.status.value == "FAILED" else "pending"
    if seen_running:
        return "pending"
    if job.status.value in {"QUEUED"}:
        return "pending"
    if stage_id in current or any(alias.replace("-", " ") in current for alias in aliases) or label_match(
        stage_id, current
    ):
        return "running"
    return "pending"


def label_match(stage_id: str, current: str) -> bool:
    tokens = {
        "validate": "validat",
        "metadata": "metadata",
        "manifest": "manifest",
        "mobsf": "mobsf",
        "jadx": "jadx",
        "apktool": "apktool",
        "secrets": "secret",
        "dependencies": "dependenc",
        "vulnerabilities": "vulnerab",
        "correlation": "correlat",
        "report": "report",
    }
    needle = tokens.get(stage_id, stage_id)
    return needle in current


def _item(scanner_id: str, name: str, status: ToolStatus, version: str | None, reason: str) -> ScannerStatusItem:
    return ScannerStatusItem(
        id=scanner_id,
        name=name,
        status=tool_status_label(status),
        version=version,
        reason=reason or "",
    )
