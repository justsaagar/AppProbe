"""Scan pipeline orchestrator.

Milestone 1 executes validation, metadata extraction, manifest static analysis,
and report generation. Later stages are recorded as NOT EXECUTED rather than faked.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

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
)
from app.models.finding import Evidence
from app.models.scan_job import CoverageNote, ScanJob, utcnow
from app.models.state import transition
from app.reporters.markdown import MarkdownReporter
from app.scanners.base import ScanContext, Scanner
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager

logger = logging.getLogger(__name__)

CLI_STAGES = [
    "Validating artifact",
    "Extracting metadata",
    "Running static analysis",
    "Preparing Android runtime",
    "Running dynamic analysis",
    "Correlating findings",
    "Running AI analysis",
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
        scanners: list[Scanner],
        reporter: MarkdownReporter | None = None,
    ) -> None:
        self.store = store
        self.workspace = workspace
        self.settings = settings
        self.scanners = scanners
        self.reporter = reporter or MarkdownReporter()

    async def run(self, scan_id: str, progress: Callable[[int, str], None] | None = None) -> ScanJob:
        job = await self.store.get(scan_id)
        if job is None:
            raise KeyError(scan_id)
        job.started_at = job.started_at or utcnow()
        await self.store.save(job)
        try:
            await self._stage_validate(job, progress)
            await self._stage_metadata(job, progress)
            await self._stage_static(job, progress)
            await self._stage_skip_runtime(job, progress)
            await self._stage_skip_dynamic(job, progress)
            await self._stage_skip_correlation(job, progress)
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
    ) -> None:
        await self._refresh(job)
        job.status = transition(job.status, status)
        job.mark(stage=stage, progress=progress_value)
        await self.store.save(job)
        if callback:
            callback(progress_value, stage)

    async def _stage_validate(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.VALIDATING,
            stage="Validating artifact",
            progress_value=10,
            callback=callback,
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
            progress_value=25,
            callback=callback,
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

    async def _stage_static(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.STATIC_ANALYSIS,
            stage="Running static analysis",
            progress_value=50,
            callback=callback,
        )
        context = ScanContext(
            job=job,
            workspace=self.workspace.for_scan(job.id),
            artifact_path=Path(job.artifact_path),
            metadata=job.metadata,
        )
        findings = []
        ran_any = False
        for scanner in self.scanners:
            if not scanner.is_available() or not scanner.supports(context):
                continue
            ran_any = True
            findings.extend(await scanner.scan(context))
        if job.artifact_kind is ArtifactKind.AAB:
            findings.append(
                normalize_finding(
                    source="orchestrator",
                    rule_id="aab_not_converted",
                    title="AAB was not converted to an installable APK set",
                    category=FindingCategory.PROCESS,
                    severity=Severity.INFO,
                    confidence=1.0,
                    description=(
                        "The upload is an Android App Bundle. Milestone 1 inspects bundle metadata "
                        "and the base module manifest. Google bundletool was not invoked, and the "
                        "AAB was not treated as an APK."
                    ),
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
                        "It was not executed. IPA support is architectural only in Milestone 1."
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
        job.findings = findings
        scan_ws = self.workspace.for_scan(job.id)
        payload = [item.model_dump(mode="json") for item in findings]
        (scan_ws.artifacts / "findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        job.stages_completed.append("static_analysis")
        job.coverage.append(
            CoverageNote(
                area="static manifest analysis",
                executed=ran_any or job.platform is Platform.IOS,
                reason="Custom manifest scanner" if ran_any else "No Android manifest scanner applicable",
            )
        )

    async def _stage_skip_runtime(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.PREPARING_RUNTIME,
            stage="Preparing Android runtime",
            progress_value=60,
            callback=callback,
        )
        job.coverage.append(
            CoverageNote(
                area="Android emulator / ADB runtime",
                executed=False,
                reason="Android Emulator unavailable (not implemented in Milestone 1)",
            )
        )
        job.stages_completed.append("runtime_skipped")

    async def _stage_skip_dynamic(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.DYNAMIC_ANALYSIS,
            stage="Running dynamic analysis",
            progress_value=70,
            callback=callback,
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

    async def _stage_skip_correlation(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.AI_ANALYSIS,
            stage="Correlating findings",
            progress_value=78,
            callback=callback,
        )
        job.coverage.append(
            CoverageNote(
                area="finding correlation",
                executed=False,
                reason="Correlation engine not implemented in Milestone 1",
            )
        )
        job.stages_completed.append("correlation_skipped")

    async def _stage_skip_ai(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.AI_ANALYSIS,
            stage="Running AI analysis",
            progress_value=82,
            callback=callback,
        )
        job.coverage.append(
            CoverageNote(
                area="LLM analysis",
                executed=False,
                reason="AI analyzer not implemented in Milestone 1; severity is deterministic",
            )
        )
        job.stages_completed.append("ai_skipped")

    async def _stage_report(self, job: ScanJob, callback: Callable[[int, str], None] | None) -> None:
        await self._update(
            job,
            status=ScanStatus.GENERATING_REPORT,
            stage="Generating report",
            progress_value=90,
            callback=callback,
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
