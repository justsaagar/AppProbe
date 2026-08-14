"""Scan pipeline for Milestone 1: validate, metadata, manifest static analysis, report."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from app.agents.ai import AIAnalyzer, NullAIAnalyzer
from app.analyzers.aab import inspect_aab
from app.analyzers.apk import extract_android_metadata
from app.analyzers.artifact import ArtifactValidationError, validate_artifact_file
from app.analyzers.correlation import FindingGroup, correlate_findings
from app.analyzers.ipa import IOS_DYNAMIC_UNAVAILABLE, inspect_ipa
from app.analyzers.manifest_parser import AndroidMetadata
from app.analyzers.severity import overall_risk
from app.config import Settings
from app.models.enums import ArtifactKind, Platform, ScanStatus, Severity
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.reporters.markdown import generate_markdown_report, write_report
from app.runners.android import ANDROID_EMULATOR_UNAVAILABLE, AndroidEmulatorRunner
from app.runners.base import RuntimeRunner
from app.runners.ios import IosRuntimeRunner
from app.scanners.base import ScanContext, Scanner
from app.scanners.manifest import ManifestScanner
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str], Awaitable[None] | None]

STAGE_LABELS = [
    "Validating artifact",
    "Extracting metadata",
    "Running static analysis",
    "Preparing Android runtime",
    "Running dynamic analysis",
    "Correlating findings",
    "Running AI analysis",
    "Generating report",
]


class ScanCancelled(Exception):
    pass


class ScanPipeline:
    def __init__(
        self,
        settings: Settings,
        workspace: WorkspaceManager,
        store: JobStore,
        scanners: list[Scanner] | None = None,
        runtime: RuntimeRunner | None = None,
        ios_runtime: RuntimeRunner | None = None,
        ai: AIAnalyzer | None = None,
    ) -> None:
        self.settings = settings
        self.workspace = workspace
        self.store = store
        self.scanners = scanners or [ManifestScanner()]
        self.runtime = runtime or AndroidEmulatorRunner()
        self.ios_runtime = ios_runtime or IosRuntimeRunner()
        self.ai = ai or NullAIAnalyzer()

    async def run(self, job: ScanJob, progress: ProgressCallback | None = None) -> ScanJob:
        findings: list[Finding] = []
        groups: list[FindingGroup] = []
        metadata: dict[str, Any] = {}
        coverage: dict[str, Any] = {}
        try:
            await self._ensure_not_cancelled(job)
            job.transition(ScanStatus.VALIDATING, "validating")
            await self.store.save(job)
            await self._emit(progress, STAGE_LABELS[0], "start")
            validation = validate_artifact_file(
                Path(job.artifact_path or ""),
                original_filename=job.filename,
                content_type=job.metadata.get("content_type"),
                settings=self.settings,
            )
            job.platform = validation.platform
            job.artifact_kind = validation.kind
            job.metadata["validation_notes"] = validation.notes
            await self.store.save(job)

            await self._ensure_not_cancelled(job)
            await self._emit(progress, STAGE_LABELS[1], "start")
            android_meta: AndroidMetadata | None = None
            notes = list(validation.notes)
            if validation.kind == ArtifactKind.APK:
                android_meta = extract_android_metadata(
                    Path(job.artifact_path or ""),
                    validation.kind,
                    validation.inventory,
                    self.settings,
                )
            elif validation.kind == ArtifactKind.AAB:
                android_meta, aab_notes = inspect_aab(
                    Path(job.artifact_path or ""),
                    validation.inventory,
                    self.settings,
                )
                notes.extend(aab_notes)
                findings.append(
                    _info_finding(
                        job,
                        rule_id="ANDROID_AAB_NOT_CONVERTED",
                        title="AAB was not converted to an installable APK",
                        description=(
                            "The uploaded artifact is an Android App Bundle. Milestone 1 inspected bundle"
                            " structure and extracted metadata but did not run bundletool to produce an APK set."
                        ),
                        location="BundleConfig.pb / base/manifest/AndroidManifest.xml",
                    )
                )
            elif validation.kind == ArtifactKind.IPA:
                ios_meta = inspect_ipa(
                    Path(job.artifact_path or ""),
                    validation.inventory,
                    self.settings,
                )
                metadata.update(ios_meta.to_dict())
                job.package_name = ios_meta.bundle_id
                job.version_name = ios_meta.version
                findings.append(
                    _info_finding(
                        job,
                        rule_id="IOS_DYNAMIC_UNAVAILABLE",
                        title="iOS dynamic testing not executed",
                        description=IOS_DYNAMIC_UNAVAILABLE,
                        location="Payload/*.app",
                    )
                )

            if android_meta is not None:
                metadata.update(android_meta.to_dict())
                job.package_name = android_meta.package_name
                job.version_name = android_meta.version_name

            job.transition(ScanStatus.STATIC_ANALYSIS, "static_analysis")
            await self.store.save(job)
            await self._emit(progress, STAGE_LABELS[2], "start")
            context = ScanContext(
                job=job,
                artifact_path=job.artifact_path or "",
                kind=job.artifact_kind,
                platform=job.platform,
                metadata=metadata,
                android=android_meta,
                notes=notes,
            )
            if android_meta is not None:
                for scanner in self.scanners:
                    findings.extend(await scanner.scan(context.artifact_path, context))

            runtime_reason = ANDROID_EMULATOR_UNAVAILABLE
            job.transition(ScanStatus.PREPARING_RUNTIME, "preparing_runtime")
            await self.store.save(job)
            await self._emit(progress, STAGE_LABELS[3], "start")
            if job.platform == Platform.IOS:
                runtime_status = await self.ios_runtime.prepare()
            else:
                runtime_status = await self.runtime.prepare()
            runtime_reason = runtime_status.reason
            job.mark_skipped("runtime_prepare", runtime_reason)

            job.transition(ScanStatus.DYNAMIC_ANALYSIS, "dynamic_analysis")
            await self.store.save(job)
            await self._emit(progress, STAGE_LABELS[4], "start")
            job.mark_skipped("dynamic_analysis", f"Runtime Testing: NOT EXECUTED. Reason: {runtime_reason}")

            await self._emit(progress, STAGE_LABELS[5], "start")
            findings, groups = correlate_findings(findings)

            job.transition(ScanStatus.AI_ANALYSIS, "ai_analysis")
            await self.store.save(job)
            await self._emit(progress, STAGE_LABELS[6], "start")
            ai_result = await self.ai.analyze_findings(findings, [])
            job.mark_skipped("ai_analysis", ai_result.reason)

            coverage = {
                "dynamic_percent": 0,
                "runtime_reason": runtime_reason,
                "unverified": [
                    "iOS runtime" if job.platform != Platform.IOS else IOS_DYNAMIC_UNAVAILABLE,
                    "Android emulator / ADB launch and UI exploration",
                    "authenticated flows because credentials were not provided",
                    "network interception / mitmproxy",
                    "JADX/apktool/MobSF code review",
                    "secret scanning beyond packaged config file presence",
                    "dependency vulnerability matching",
                    "AI correlation and severity adjustment",
                ],
                "limitations": [
                    "Milestone 1 performs APK/AAB/IPA validation, metadata extraction, and Android manifest analysis only.",
                    "No code decompilation, emulator execution, or LLM interpretation was performed.",
                    "Coverage is not 100% and must not be reported as complete.",
                    *notes,
                ],
            }
            metadata["technology"] = {
                "platform": job.platform.value,
                "artifact_kind": job.artifact_kind.value,
                "manifest_format": metadata.get("extra", {}).get("manifest_format")
                if isinstance(metadata.get("extra"), dict)
                else None,
            }

            job.transition(ScanStatus.GENERATING_REPORT, "generating_report")
            await self.store.save(job)
            await self._emit(progress, STAGE_LABELS[7], "start")
            report_dir = self.workspace.report_dir(job.id)
            report_path = report_dir / "security-report.md"
            markdown = generate_markdown_report(
                job=job,
                findings=findings,
                groups=groups,
                metadata=metadata,
                coverage=coverage,
            )
            write_report(report_path, markdown)
            self.workspace.write_json(
                self.workspace.scan_dir(job.id) / "findings.json",
                [item.model_dump(mode="json") for item in findings],
            )
            self.workspace.write_json(self.workspace.scan_dir(job.id) / "metadata.json", metadata)
            self.workspace.write_json(
                self.workspace.scan_dir(job.id) / "groups.json",
                [group.__dict__ for group in groups],
            )
            job.report_path = str(report_path)
            job.metadata["finding_counts"] = _counts(findings)
            job.metadata["overall_risk"] = (
                overall_risk(findings).value if overall_risk(findings) else None
            )
            job.transition(ScanStatus.COMPLETED, "completed")
            await self.store.save(job)
            await self._emit(progress, "Scan completed", "done")
            return job
        except ScanCancelled:
            job.status = ScanStatus.FAILED
            job.error = "Scan cancelled by user"
            job.current_stage = "cancelled"
            await self.store.save(job)
            return job
        except ArtifactValidationError as exc:
            logger.info("Scan %s validation failed: %s", job.id, exc)
            job.status = ScanStatus.FAILED
            job.error = str(exc)
            job.current_stage = "failed"
            await self.store.save(job)
            return job
        except Exception as exc:  # noqa: BLE001 — pipeline must record unexpected failures
            logger.exception("Scan %s failed", job.id)
            job.status = ScanStatus.FAILED
            job.error = str(exc)
            job.current_stage = "failed"
            await self.store.save(job)
            return job

    async def _ensure_not_cancelled(self, job: ScanJob) -> None:
        latest = await self.store.get(job.id)
        if latest and latest.cancel_requested:
            raise ScanCancelled()

    async def _emit(self, progress: ProgressCallback | None, label: str, state: str) -> None:
        if progress is None:
            return
        result = progress(label, state)
        if hasattr(result, "__await__"):
            await result  # type: ignore[misc]


def _counts(findings: list[Finding]) -> dict[str, int]:
    result = {item.value: 0 for item in Severity}
    for finding in findings:
        result[finding.severity.value] = result.get(finding.severity.value, 0) + 1
    return result


def _info_finding(job: ScanJob, *, rule_id: str, title: str, description: str, location: str) -> Finding:
    from app.analyzers.normalize import normalize_finding
    from app.analyzers.severity import apply_severity
    from app.models.enums import FindingCategory

    return apply_severity(
        normalize_finding(
            {
                "id": f"{job.id}-{rule_id.lower()}",
                "title": title,
                "category": FindingCategory.INFORMATIONAL,
                "severity": Severity.INFO,
                "confidence": 1.0,
                "source": "pipeline",
                "rule_id": rule_id,
                "description": description,
                "impact": "No direct vulnerability is asserted.",
                "recommendation": "Use a later milestone or a supported environment to complete this analysis.",
                "reproducibility": "Recorded by the scan pipeline from artifact type / environment checks.",
                "evidence": [
                    {
                        "kind": "tool_output",
                        "summary": description,
                        "location": location,
                    }
                ],
            },
            index=0,
            source="pipeline",
        )
    )
