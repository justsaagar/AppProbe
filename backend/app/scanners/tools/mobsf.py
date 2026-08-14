"""MobSF static-analysis adapter (REST only).

MobSF is an optional evidence-producing scanner. AppProbe remains usable when
MobSF is disabled or unreachable. Dynamic analysis is not invoked.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.mobsf.client import HttpMobSFClient, MobSFClient
from app.mobsf.normalize import (
    looks_like_report,
    parse_mobsf_report,
    report_not_ready,
    summarize_report,
)
from app.mobsf.url import validate_mobsf_url
from app.models.enums import ArtifactKind, ToolStatus
from app.models.mobsf import (
    MobSFAnalysis,
    MobSFAvailability,
    MobSFResult,
    analysis_from_result,
)
from app.scanners.base import ScanContext
from app.scanners.tools.base import ExternalTool, ToolRunResult, tool_output_dir
from app.utils.http import JsonHttpError
from app.utils.redact import redact_text

logger = logging.getLogger(__name__)

Sleep = Callable[[float], Awaitable[None]]

_STATUS_MAP = {
    MobSFAvailability.NOT_ENABLED: ToolStatus.NOT_ENABLED,
    MobSFAvailability.NOT_AVAILABLE: ToolStatus.NOT_AVAILABLE,
    MobSFAvailability.AUTH_FAILED: ToolStatus.AUTH_FAILED,
    MobSFAvailability.TIMEOUT: ToolStatus.TIMEOUT,
    MobSFAvailability.FAILED: ToolStatus.AVAILABLE_BUT_FAILED,
    MobSFAvailability.AVAILABLE: ToolStatus.AVAILABLE_AND_EXECUTED,
}


class MobsfTool(ExternalTool):
    name = "mobsf"

    def __init__(
        self,
        settings: Settings | None = None,
        client: MobSFClient | None = None,
        sleeper: Sleep | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = client
        self._sleep = sleeper or asyncio.sleep

    def is_available(self) -> bool:
        return bool(self.settings.mobsf_enabled and ((self.settings.mobsf_url or "").strip() or self._client))

    def version(self) -> str | None:
        return None

    async def run(self, context: ScanContext) -> ToolRunResult:
        output = tool_output_dir(context.workspace, self.name)
        started = time.monotonic()
        try:
            result = await self._analyze(context, output, started)
        except Exception as exc:  # noqa: BLE001
            logger.warning("mobsf failed: %s", redact_text(str(exc)))
            result = MobSFResult(
                status="FAILED",
                availability=MobSFAvailability.FAILED,
                reason=f"MobSF execution failed: {redact_text(str(exc))}",
                duration_seconds=_elapsed(started),
            )
        return self._to_tool_result(result, output)

    async def _analyze(self, context: ScanContext, output: Path, started: float) -> MobSFResult:
        if not self.settings.mobsf_enabled:
            return MobSFResult(
                status="NOT ENABLED",
                availability=MobSFAvailability.NOT_ENABLED,
                reason="MobSF is disabled (MOBSF_ENABLED=false).",
                duration_seconds=_elapsed(started),
            )
        if context.job.artifact_kind is not ArtifactKind.APK:
            kind = context.job.artifact_kind.value
            return MobSFResult(
                status="NOT EXECUTED",
                availability=MobSFAvailability.AVAILABLE,
                reason=f"MobSF static analysis in Milestone 2.8 supports APK only ({kind} skipped).",
                duration_seconds=_elapsed(started),
            )

        try:
            client = self._client or self._build_client()
        except JsonHttpError as exc:
            availability = (
                MobSFAvailability.NOT_AVAILABLE if exc.kind in {"unavailable", "invalid_url"} else MobSFAvailability.FAILED
            )
            return MobSFResult(
                status=_label(availability),
                availability=availability,
                reason=redact_text(exc.message),
                duration_seconds=_elapsed(started),
            )

        health = await client.health()
        if health.availability is not MobSFAvailability.AVAILABLE:
            return MobSFResult(
                status=_label(health.availability),
                availability=health.availability,
                mobsf_version=health.version,
                reason=health.reason,
                duration_seconds=_elapsed(started),
            )

        try:
            upload = await client.upload(context.artifact_path)
        except JsonHttpError as exc:
            return _error_result(exc, health.version, started, "upload")

        scan_id = upload.scan_id
        logger.info("mobsf scan_id=%s status=uploaded", scan_id)
        payload: dict[str, Any] | None = None
        try:
            initiated = await client.scan(
                scan_id=scan_id,
                scan_type=upload.scan_type or "apk",
                file_name=upload.file_name or context.job.filename,
            )
            logger.info("mobsf scan_id=%s status=initiated", scan_id)
            if looks_like_report(initiated):
                payload = initiated
        except JsonHttpError as exc:
            if exc.kind != "timeout":
                return _error_result(exc, health.version, started, "scan", scan_id=scan_id)
            logger.info("mobsf scan_id=%s status=scan-timeout-polling", scan_id)

        if payload is None:
            payload, wait_error = await self._poll_report(client, scan_id)
            if wait_error is not None:
                return wait_error.model_copy(
                    update={
                        "mobsf_version": wait_error.mobsf_version or health.version,
                        "duration_seconds": _elapsed(started),
                    }
                )

        assert payload is not None
        findings = parse_mobsf_report(payload)
        summary = summarize_report(payload)
        cleanup_ok: bool | None = None
        try:
            await client.cleanup(scan_id)
            cleanup_ok = True
        except Exception as exc:  # noqa: BLE001
            cleanup_ok = False
            logger.warning("mobsf cleanup failed scan_id=%s: %s", scan_id, redact_text(str(exc)))

        result = MobSFResult(
            status="EXECUTED",
            availability=MobSFAvailability.AVAILABLE,
            scan_id=scan_id,
            package_name=_safe_str(summary.get("package_name")),
            version=_safe_str(summary.get("version_name")),
            mobsf_version=_safe_str(summary.get("mobsf_version")) or health.version,
            score=summary.get("security_score") if isinstance(summary.get("security_score"), int | float) else None,
            findings=findings,
            metadata={"scan_type": upload.scan_type, "file_name": upload.file_name},
            raw_summary=summary,
            duration_seconds=_elapsed(started),
            cleanup_succeeded=cleanup_ok,
            reason="MobSF REST static analysis completed.",
        )
        _write_summary(output, result)
        return result

    async def _poll_report(
        self, client: MobSFClient, scan_id: str
    ) -> tuple[dict[str, Any] | None, MobSFResult | None]:
        max_wait = max(0.0, float(self.settings.mobsf_max_wait_seconds))
        interval = max(0.05, float(self.settings.mobsf_poll_interval_seconds))
        deadline = time.monotonic() + max_wait
        while True:
            try:
                progress = await client.status(scan_id)
            except JsonHttpError as exc:
                return None, _error_result(exc, None, time.monotonic(), "status", scan_id=scan_id)
            if progress.failed:
                return None, MobSFResult(
                    status="FAILED",
                    availability=MobSFAvailability.FAILED,
                    scan_id=scan_id,
                    reason="MobSF reported a failed scan.",
                )
            try:
                payload = await client.report(scan_id)
            except JsonHttpError as exc:
                if exc.kind == "timeout":
                    return None, _error_result(exc, None, time.monotonic(), "report", scan_id=scan_id)
                if exc.kind == "auth_failed":
                    return None, _error_result(exc, None, time.monotonic(), "report", scan_id=scan_id)
                if exc.status_code in {400, 404}:
                    payload = {"error": "Report not Found"}
                elif exc.kind == "invalid_response":
                    return None, MobSFResult(
                        status="FAILED",
                        availability=MobSFAvailability.FAILED,
                        scan_id=scan_id,
                        reason="MobSF returned malformed JSON.",
                    )
                else:
                    return None, _error_result(exc, None, time.monotonic(), "report", scan_id=scan_id)
            if looks_like_report(payload):
                logger.info("mobsf scan_id=%s status=completed", scan_id)
                return payload, None
            if isinstance(payload, dict) and payload.get("error") and not report_not_ready(payload):
                return None, MobSFResult(
                    status="FAILED",
                    availability=MobSFAvailability.FAILED,
                    scan_id=scan_id,
                    reason="MobSF returned a malformed or unusable report.",
                )
            if time.monotonic() >= deadline:
                logger.info("mobsf scan_id=%s status=timeout", scan_id)
                return None, MobSFResult(
                    status="TIMEOUT",
                    availability=MobSFAvailability.TIMEOUT,
                    scan_id=scan_id,
                    reason="MobSF static analysis exceeded MOBSF_MAX_WAIT_SECONDS.",
                )
            await self._sleep(interval)

    def _build_client(self) -> HttpMobSFClient:
        validate_mobsf_url(self.settings.mobsf_url)
        return HttpMobSFClient(
            base_url=self.settings.mobsf_url,
            api_key=self.settings.mobsf_api_key,
            timeout_seconds=float(self.settings.mobsf_timeout_seconds),
            connect_timeout_seconds=float(self.settings.mobsf_connect_timeout_seconds),
            max_response_bytes=int(self.settings.mobsf_max_response_bytes),
            scan_timeout_seconds=float(self.settings.mobsf_max_wait_seconds),
        )

    def _to_tool_result(self, result: MobSFResult, output: Path) -> ToolRunResult:
        if result.status == "NOT EXECUTED":
            status = ToolStatus.NOT_EXECUTED
        else:
            status = _STATUS_MAP.get(result.availability, ToolStatus.AVAILABLE_BUT_FAILED)
        analysis = analysis_from_result(result)
        if result.status == "EXECUTED":
            _write_summary(output, result)
        else:
            _write_analysis(output, analysis)
        return ToolRunResult(
            name=self.name,
            status=status,
            version=result.mobsf_version or ("Unknown" if status is ToolStatus.AVAILABLE_AND_EXECUTED else None),
            reason=result.reason,
            output_dir=output,
            findings=result.findings,
            extras={"analysis": analysis, "result": result},
            duration_seconds=result.duration_seconds,
        )


def _error_result(
    exc: JsonHttpError,
    version: str | None,
    started: float,
    stage: str,
    *,
    scan_id: str | None = None,
) -> MobSFResult:
    availability = _availability_for(exc)
    return MobSFResult(
        status=_label(availability),
        availability=availability,
        scan_id=scan_id,
        mobsf_version=version,
        reason=f"MobSF {stage} failed: {redact_text(exc.message)}",
        duration_seconds=_elapsed(started),
    )


def _availability_for(exc: JsonHttpError) -> MobSFAvailability:
    if exc.kind == "auth_failed":
        return MobSFAvailability.AUTH_FAILED
    if exc.kind == "timeout":
        return MobSFAvailability.TIMEOUT
    if exc.kind in {"unavailable", "invalid_url"}:
        return MobSFAvailability.NOT_AVAILABLE
    return MobSFAvailability.FAILED


def _label(availability: MobSFAvailability) -> str:
    return {
        MobSFAvailability.NOT_ENABLED: "NOT ENABLED",
        MobSFAvailability.NOT_AVAILABLE: "NOT AVAILABLE",
        MobSFAvailability.AUTH_FAILED: "AUTH FAILED",
        MobSFAvailability.TIMEOUT: "TIMEOUT",
        MobSFAvailability.FAILED: "FAILED",
        MobSFAvailability.AVAILABLE: "EXECUTED",
    }[availability]


def _elapsed(started: float) -> float:
    return round(max(0.0, time.monotonic() - started), 3)


def _safe_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _write_summary(output: Path, result: MobSFResult) -> None:
    output.mkdir(parents=True, exist_ok=True)
    analysis = analysis_from_result(result)
    _write_analysis(output, analysis)
    (output / "parsed-findings.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in result.findings], indent=2),
        encoding="utf-8",
    )
    (output / "summary.json").write_text(
        json.dumps(result.raw_summary, indent=2, default=str),
        encoding="utf-8",
    )


def _write_analysis(output: Path, analysis: MobSFAnalysis) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "analysis.json").write_text(
        json.dumps(analysis.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
