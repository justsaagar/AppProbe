"""Scan pipeline orchestrator.

Milestone 2 runs optional static tools (MobSF, JADX, apktool), secret and
dependency scanners, and deterministic correlation. Runtime/AI remain skipped.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.analyzers.correlation import correlate_findings
from app.analyzers.findings import normalize_finding
from app.analyzers.metadata import extract_metadata
from app.analyzers.severity import overall_risk, severity_counts
from app.analyzers.validator import ArtifactValidationError, validate_artifact
from app.config import Settings
from app.models.enums import (
    ArtifactKind,
    FindingCategory,
    Platform,
    ScanStatus,
    Severity,
    ToolStatus,
)
from app.models.finding import Evidence, Finding
from app.models.scan_job import CoverageNote, ScanJob, SecretScanCoverage, utcnow
from app.models.state import transition
from app.models.technology import DependencyScanCoverage, TechnologyRecord
from app.reporters.markdown import MarkdownReporter
from app.scanners.base import ScanContext, Scanner
from app.scanners.dependencies import DependencyScanner
from app.scanners.manifest import ManifestScanner
from app.scanners.secrets import SecretScanner
from app.scanners.tools.apktool import ApktoolTool, apktool_decoded_dir
from app.scanners.tools.base import ExternalTool, ToolRunResult
from app.scanners.tools.jadx import JadxTool, jadx_source_dir
from app.scanners.tools.mobsf import MobsfTool
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager

logger = logging.getLogger(__name__)

CLI_STAGES = [
    "Validating artifact",
    "Extracting metadata",
    "Running manifest analysis",
    "Running MobSF",
    "Running JADX",
    "Running apktool",
    "Running secret detection",
    "Running dependency analysis",
    "Correlating findings",
    "Generating report",
]


class ScanCancelled(RuntimeError):
    pass


class ScanOrchestrator:
    def __init__(
        self,
        store: JobStore,
        workspace: WorkspaceManager,
        settings: Settings,
        scanners: list[Scanner] | None = None,
        reporter: MarkdownReporter | None = None,
        tools: dict[str, ExternalTool] | None = None,
    ) -> None:
        self.store = store
        self.workspace = workspace
        self.settings = settings
        self.scanners = scanners or [ManifestScanner(), SecretScanner(settings), DependencyScanner()]
        self.reporter = reporter or MarkdownReporter()
        self.tools = tools or {
            "mobsf": MobsfTool(settings),
            "jadx": JadxTool(settings),
            "apktool": ApktoolTool(settings),
        }

    def _scanner(self, name: str) -> Scanner | None:
        for scanner in self.scanners:
            if scanner.name == name:
                return scanner
        return None

    async def run(self, scan_id: str, progress: Callable[[int, str], None] | None = None) -> ScanJob:
        job = await self.store.get(scan_id)
        if job is None:
            raise KeyError(scan_id)
        job.started_at = job.started_at or utcnow()
        extras: dict[str, Any] = {}
        await self.store.save(job)
        try:
            await self._stage_validate(job, progress)
            await self._stage_metadata(job, progress)
            await self._stage_manifest(job, extras, progress)
            await self._stage_tool(job, extras, "mobsf", 4, "Running MobSF", progress)
            await self._stage_tool(job, extras, "jadx", 5, "Running JADX", progress)
            await self._stage_tool(job, extras, "apktool", 6, "Running apktool", progress)
            await self._stage_named_scanner(job, extras, "secret-scanner", 7, "Running secret detection", progress)
            await self._stage_named_scanner(
                job, extras, "dependency-scanner", 8, "Running dependency analysis", progress
            )
            await self._persist_raw_findings(job)
            await self._stage_correlate(job, progress)
            await self._stage_skip_runtime(job, progress)
            await self._stage_skip_dynamic(job, progress)
            await self._stage_skip_ai(job, progress)
            await self._stage_report(job, progress)
            job.status = transition(job.status, ScanStatus.COMPLETED)
            job.progress = 100
            job.current_stage = "completed"
            job.completed_at = utcnow()
            job.overall_risk = overall_risk(job.findings).value
            job.severity_counts = severity_counts(job.findings)
        except ScanCancelled:
            job.status = transition(job.status, ScanStatus.FAILED)
            job.error = "Cancelled by user"
            job.completed_at = utcnow()
            job.current_stage = "cancelled"
        except ArtifactValidationError as exc:
            logger.warning("scan %s validation failed: %s", job.id, exc)
            job.status = transition(job.status, ScanStatus.FAILED)
            job.error = str(exc)
            job.completed_at = utcnow()
        except Exception as exc:  # noqa: BLE001 — job must record unexpected failures
            logger.exception("scan %s failed", job.id)
            job.status = transition(job.status, ScanStatus.FAILED)
            job.error = str(exc)
            job.completed_at = utcnow()
        await self.store.save(job)
        return job

    async def _refresh(self, job: ScanJob) -> ScanJob:
        latest = await self.store.get(job.id)
        if latest is None:
            return job
        job.cancel_requested = latest.cancel_requested
        if job.cancel_requested:
            raise ScanCancelled()
        return job

    async def _update(
        self,
        job: ScanJob,
        *,
        status: ScanStatus,
        stage: str,
        progress_value: int,
        callback: Callable[[int, str], None] | None,
        cli_index: int | None = None,
        cli_label: str | None = None,
    ) -> None:
        await self._refresh(job)
        job.status = transition(job.status, status)
        job.mark(stage=stage, progress=progress_value)
        await self.store.save(job)
        if callback:
            if cli_index is not None:
                callback(progress_value, f"[{cli_index}/10] {cli_label or stage}")
            else:
                callback(progress_value, stage)

    async def _stage_validate(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.VALIDATING,
            stage="Validating artifact",
            progress_value=10,
            callback=callback,
            cli_index=1,
        )
        result = validate_artifact(Path(job.artifact_path), original_filename=job.filename)
        job.platform = result.platform
        job.artifact_kind = result.kind
        scan_ws = self.workspace.for_scan(job.id)
        (scan_ws.artifacts / "validation.json").write_text(
            json.dumps(
                {
                    "kind": result.kind.value,
                    "platform": result.platform.value,
                    "size": result.size,
                    "notes": result.notes,
                    "entry_count": len(result.zip_entries),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        job.stages_completed.append("validate")
        job.coverage.append(
            CoverageNote(area="artifact validation", executed=True, reason="ZIP structure and type checks passed")
        )

    async def _stage_metadata(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.STATIC_ANALYSIS,
            stage="Extracting metadata",
            progress_value=20,
            callback=callback,
            cli_index=2,
        )
        validation = validate_artifact(Path(job.artifact_path), original_filename=job.filename)
        metadata = extract_metadata(Path(job.artifact_path), validation)
        job.metadata = metadata
        job.platform = metadata.platform
        job.artifact_kind = metadata.artifact_kind
        scan_ws = self.workspace.for_scan(job.id)
        (scan_ws.artifacts / "metadata.json").write_text(
            metadata.model_dump_json(indent=2),
            encoding="utf-8",
        )
        job.stages_completed.append("metadata")
        job.coverage.append(
            CoverageNote(area="metadata extraction", executed=True, reason="Package identity parsed from the artifact")
        )

    def _context(self, job: ScanJob, extras: dict[str, Any]) -> ScanContext:
        return ScanContext(
            job=job,
            workspace=self.workspace.for_scan(job.id),
            artifact_path=Path(job.artifact_path),
            metadata=job.metadata,
            extras=extras,
        )

    async def _stage_manifest(
        self,
        job: ScanJob,
        extras: dict[str, Any],
        callback: Callable[[int, str], None] | None,
    ) -> None:
        await self._update(
            job,
            status=ScanStatus.STATIC_ANALYSIS,
            stage="Running manifest analysis",
            progress_value=30,
            callback=callback,
            cli_index=3,
        )
        scanner = self._scanner("manifest") or ManifestScanner()
        context = self._context(job, extras)
        findings: list[Finding] = []
        if scanner.supports(context):
            findings.extend(await scanner.scan(context))
        if job.artifact_kind is ArtifactKind.AAB:
            findings.append(
                normalize_finding(
                    source="orchestrator",
                    rule_id="aab_not_converted",
                    title="AAB was not converted to an installable APK set",
                    category=FindingCategory.PROCESS,
                    severity=Severity.INFO,
                    description=(
                        "The upload is an Android App Bundle. Milestone 2 inspects bundle metadata "
                        "and the base module manifest. Google bundletool was not invoked, and the "
                        "AAB was not treated as an APK."
                    ),
                    confidence=1.0,
                    evidence=[
                        Evidence(
                            kind="process",
                            summary="bundletool APK-set generation not implemented",
                            location="base/manifest/AndroidManifest.xml",
                        )
                    ],
                    reproducibility="N/A — documented pipeline limitation.",
                )
            )
        if job.platform is Platform.IOS:
            findings.append(
                normalize_finding(
                    source="orchestrator",
                    rule_id="ios_dynamic_unavailable",
                    title="iOS dynamic testing unavailable",
                    category=FindingCategory.PLATFORM,
                    severity=Severity.INFO,
                    confidence=1.0,
                    description=(
                        "Dynamic iOS testing requires a supported macOS/device environment. "
                        "It was not executed."
                    ),
                    evidence=[
                        Evidence(
                            kind="process",
                            summary="iOS runtime not available on this host pipeline",
                        )
                    ],
                    reproducibility="N/A — environment limitation.",
                )
            )
        job.findings.extend(findings)
        job.stages_completed.append("manifest")
        job.coverage.append(
            CoverageNote(
                area="static manifest analysis",
                executed=True,
                reason="Custom manifest scanner",
            )
        )

    async def _stage_tool(
        self,
        job: ScanJob,
        extras: dict[str, Any],
        name: str,
        cli_index: int,
        running_label: str,
        callback: Callable[[int, str], None] | None,
    ) -> None:
        tool = self.tools.get(name)
        progress_value = 30 + cli_index * 5
        if tool is None:
            label = f"{name.upper() if name != 'apktool' else 'apktool'} - NOT AVAILABLE"
            await self._update(
                job,
                status=ScanStatus.STATIC_ANALYSIS,
                stage=label,
                progress_value=progress_value,
                callback=callback,
                cli_index=cli_index,
                cli_label=label,
            )
            return
        display_name = {"mobsf": "MobSF", "jadx": "JADX", "apktool": "apktool"}[name]
        if not tool.is_available():
            result = tool.skipped(
                reason=f"{display_name} was not available in the scan environment.",
                status=ToolStatus.NOT_AVAILABLE,
            )
            await self._update(
                job,
                status=ScanStatus.STATIC_ANALYSIS,
                stage=f"{display_name} - NOT AVAILABLE",
                progress_value=progress_value,
                callback=callback,
                cli_index=cli_index,
                cli_label=f"{display_name} - NOT AVAILABLE",
            )
        else:
            await self._update(
                job,
                status=ScanStatus.STATIC_ANALYSIS,
                stage=running_label,
                progress_value=progress_value,
                callback=callback,
                cli_index=cli_index,
                cli_label=running_label,
            )
            try:
                result = await tool.run(self._context(job, extras))
            except Exception as exc:  # noqa: BLE001
                logger.warning("%s failed: %s", name, exc)
                result = ToolRunResult(
                    name=name,
                    status=ToolStatus.AVAILABLE_BUT_FAILED,
                    reason=str(exc),
                )
            label = None
            if result.status is ToolStatus.NOT_AVAILABLE:
                label = f"{display_name} - NOT AVAILABLE"
            elif result.status is ToolStatus.TIMEOUT:
                label = f"{display_name} - TIMEOUT"
            elif result.status is ToolStatus.AVAILABLE_BUT_FAILED:
                label = f"{display_name} - FAILED"
            elif result.status is ToolStatus.NOT_EXECUTED:
                label = f"{display_name} - NOT EXECUTED"
            if label and callback:
                callback(progress_value, f"[{cli_index}/10] {label}")
        job.tool_runs.append(result.record())
        job.findings.extend(result.findings)
        if name == "jadx":
            source_dir = jadx_source_dir(result.output_dir)
            if source_dir:
                extras["jadx_source_dir"] = str(source_dir)
        if name == "apktool":
            decoded = apktool_decoded_dir(result.output_dir)
            if decoded:
                extras["apktool_decoded_dir"] = str(decoded)
        executed = result.status is ToolStatus.AVAILABLE_AND_EXECUTED
        job.coverage.append(
            CoverageNote(
                area=display_name,
                executed=executed,
                reason=result.reason or result.status.value,
            )
        )
        job.stages_completed.append(f"{name}_{result.status.value.lower()}")
        await self.store.save(job)

    async def _stage_named_scanner(
        self,
        job: ScanJob,
        extras: dict[str, Any],
        scanner_name: str,
        cli_index: int,
        label: str,
        callback: Callable[[int, str], None] | None,
    ) -> None:
        await self._update(
            job,
            status=ScanStatus.STATIC_ANALYSIS,
            stage=label,
            progress_value=30 + cli_index * 5,
            callback=callback,
            cli_index=cli_index,
            cli_label=label,
        )
        scanner = self._scanner(scanner_name)
        context = self._context(job, extras)
        executed = False
        reason = f"{scanner_name} not registered"
        if scanner is not None and scanner.supports(context):
            try:
                job.findings.extend(await scanner.scan(context))
                executed = True
                reason = f"{scanner_name} completed"
            except Exception as exc:  # noqa: BLE001
                logger.warning("%s failed: %s", scanner_name, exc)
                reason = f"{scanner_name} failed: {exc}"
        elif scanner is not None:
            reason = f"{scanner_name} not applicable for this artifact"
        if scanner_name == "secret-scanner":
            job.secret_scan_coverage = _coverage_from_extras(extras)
            if executed and job.secret_scan_coverage and job.secret_scan_coverage.sources:
                reason = (
                    f"{scanner_name} completed. Sources: "
                    + ", ".join(job.secret_scan_coverage.sources)
                )
        if scanner_name == "dependency-scanner":
            job.technology_inventory = _inventory_from_extras(extras)
            job.dependency_scan_coverage = _dependency_coverage_from_extras(extras)
            if executed and job.dependency_scan_coverage and job.dependency_scan_coverage.sources:
                reason = (
                    f"{scanner_name} completed. Sources: "
                    + ", ".join(job.dependency_scan_coverage.sources)
                )
        job.coverage.append(CoverageNote(area=scanner_name, executed=executed, reason=reason))
        job.stages_completed.append(scanner_name if executed else f"{scanner_name}_skipped")
        await self.store.save(job)

    async def _persist_raw_findings(self, job: ScanJob) -> None:
        scan_ws = self.workspace.for_scan(job.id)
        payload = [item.model_dump(mode="json") for item in job.findings]
        (scan_ws.findings_dir / "raw-findings.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        (scan_ws.artifacts / "raw-findings.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    async def _stage_correlate(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.STATIC_ANALYSIS,
            stage="Correlating findings",
            progress_value=80,
            callback=callback,
            cli_index=9,
        )
        merged, groups = correlate_findings(job.findings)
        job.findings = merged
        job.correlated_groups = groups
        scan_ws = self.workspace.for_scan(job.id)
        (scan_ws.findings_dir / "findings.json").write_text(
            json.dumps([item.model_dump(mode="json") for item in merged], indent=2),
            encoding="utf-8",
        )
        (scan_ws.artifacts / "findings.json").write_text(
            json.dumps([item.model_dump(mode="json") for item in merged], indent=2),
            encoding="utf-8",
        )
        (scan_ws.findings_dir / "correlated-groups.json").write_text(
            json.dumps([item.model_dump(mode="json") for item in groups], indent=2),
            encoding="utf-8",
        )
        job.stages_completed.append("correlation")
        job.coverage.append(
            CoverageNote(
                area="finding correlation",
                executed=True,
                reason=f"Deterministic merge produced {len(groups)} correlated group(s)",
            )
        )

    async def _stage_skip_runtime(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.PREPARING_RUNTIME,
            stage="Preparing Android runtime",
            progress_value=84,
            callback=None,
        )
        job.coverage.append(
            CoverageNote(
                area="Android emulator / ADB runtime",
                executed=False,
                reason="Android Emulator unavailable (not implemented in Milestone 2)",
            )
        )
        job.stages_completed.append("runtime_skipped")

    async def _stage_skip_dynamic(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.DYNAMIC_ANALYSIS,
            stage="Running dynamic analysis",
            progress_value=86,
            callback=None,
        )
        job.coverage.append(
            CoverageNote(
                area="dynamic UI / runtime security tests",
                executed=False,
                reason="Runtime Testing: NOT EXECUTED. Reason: Android Emulator unavailable",
            )
        )
        job.coverage.append(
            CoverageNote(
                area="iOS runtime",
                executed=False,
                reason="Dynamic iOS testing requires a supported macOS/device environment",
            )
        )
        job.coverage.append(
            CoverageNote(
                area="network interception",
                executed=False,
                reason="mitmproxy / runtime network analysis is Milestone 5",
            )
        )
        job.stages_completed.append("dynamic_skipped")

    async def _stage_skip_ai(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.AI_ANALYSIS,
            stage="Running AI analysis",
            progress_value=88,
            callback=None,
        )
        job.coverage.append(
            CoverageNote(
                area="LLM analysis",
                executed=False,
                reason="AI analyzer not implemented in Milestone 2; severity is deterministic",
            )
        )
        job.stages_completed.append("ai_skipped")

    async def _stage_report(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.GENERATING_REPORT,
            stage="Generating report",
            progress_value=92,
            callback=callback,
            cli_index=10,
        )
        job.overall_risk = overall_risk(job.findings).value
        job.severity_counts = severity_counts(job.findings)
        report_path = self.workspace.report_path(job.id)
        self.reporter.write(job, report_path)
        scan_ws = self.workspace.for_scan(job.id)
        self.reporter.write(job, scan_ws.report / "security-report.md")
        job.report_path = str(report_path)
        job.stages_completed.append("report")
        job.coverage.append(
            CoverageNote(area="markdown report", executed=True, reason="security-report.md generated from scanner evidence")
        )


def _coverage_from_extras(extras: dict[str, Any]) -> SecretScanCoverage | None:
    payload = extras.get("secret_scan_coverage")
    if payload is None:
        return None
    if isinstance(payload, SecretScanCoverage):
        return payload
    if isinstance(payload, dict):
        try:
            return SecretScanCoverage.model_validate(payload)
        except Exception:  # noqa: BLE001
            return None
    return None


def _dependency_coverage_from_extras(extras: dict[str, Any]) -> DependencyScanCoverage | None:
    payload = extras.get("dependency_scan_coverage")
    if payload is None:
        return None
    if isinstance(payload, DependencyScanCoverage):
        return payload
    if isinstance(payload, dict):
        try:
            return DependencyScanCoverage.model_validate(payload)
        except Exception:  # noqa: BLE001
            return None
    return None


def _inventory_from_extras(extras: dict[str, Any]) -> list[TechnologyRecord]:
    payload = extras.get("technology_inventory") or []
    records: list[TechnologyRecord] = []
    for item in payload:
        if isinstance(item, TechnologyRecord):
            records.append(item)
        elif isinstance(item, dict):
            try:
                records.append(TechnologyRecord.model_validate(item))
            except Exception:  # noqa: BLE001
                continue
    return records
