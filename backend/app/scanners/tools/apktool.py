"""apktool decode adapter.

Runs apktool through the Milestone 2.1 executor. Produces isolated decoded
resources/smali for later scanners. Does not emit security findings.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from app.config import Settings, get_settings
from app.models.enums import ArtifactKind, Platform, ToolExecutionStatus, ToolStatus
from app.scanners.base import ScanContext
from app.scanners.tools.base import ExternalTool, ToolRunResult
from app.tools.definition import ToolDefinition
from app.tools.discovery import resolve_executable
from app.tools.executor import ExternalToolExecutor
from app.tools.result import ToolExecutionResult

logger = logging.getLogger(__name__)

TOOL_NAME = "apktool"
OUTPUT_DIRNAME = "output"
VERSION_ARGS = ("--version",)


def apktool_definition(*, executable: str) -> ToolDefinition:
    return ToolDefinition(name=TOOL_NAME, executable=executable, version_args=VERSION_ARGS)


class ApktoolTool(ExternalTool):
    name = TOOL_NAME

    def __init__(
        self,
        settings: Settings | None = None,
        executor: ExternalToolExecutor | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.executor = executor or ExternalToolExecutor(self.settings)
        self._resolved = resolve_executable(self.settings.apktool_bin or None, "apktool")
        self.definition = apktool_definition(
            executable=self._resolved or (self.settings.apktool_bin or "apktool")
        )
        self._version: str | None = None

    def is_available(self) -> bool:
        return self._resolved is not None and self.executor.is_available(self.definition)

    def version(self) -> str | None:
        return self._version

    async def run(self, context: ScanContext) -> ToolRunResult:
        tool_root = context.workspace.tool_dir(self.name)
        if not _is_apk(context):
            return self._skip(
                status=ToolStatus.NOT_EXECUTED,
                reason="apktool adapter currently requires an APK input.",
                output_dir=tool_root,
                execution_status=None,
            )
        if not self.is_available():
            return self._skip(
                status=ToolStatus.NOT_AVAILABLE,
                reason="apktool executable was not found in PATH.",
                output_dir=tool_root,
                execution_status=ToolExecutionStatus.NOT_AVAILABLE,
            )

        output_dir = tool_root / OUTPUT_DIRNAME
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self._version = await self.executor.version(self.definition)
        executed = await self.executor.run(
            self.definition,
            self._apktool_args(output_dir, context.artifact_path),
            cwd=tool_root,
            timeout=float(self.settings.tool_timeout_seconds),
        )
        return self._from_execution(executed, tool_root=tool_root, output_dir=output_dir)

    def _apktool_args(self, output_dir: Path, artifact: Path) -> list[str]:
        return ["d", "-f", "-o", str(output_dir), str(artifact)]

    def _from_execution(
        self,
        executed: ToolExecutionResult,
        *,
        tool_root: Path,
        output_dir: Path,
    ) -> ToolRunResult:
        inspection = inspect_decoded_project(output_dir)
        status, reason = _map_status(executed, inspection)
        _write_metadata(
            tool_root,
            {
                "tool": self.name,
                "status": status.value,
                "execution_status": executed.status.value,
                "version": self._version,
                "exit_code": executed.exit_code,
                "duration_seconds": executed.duration_seconds,
                "output_directory": f"tools/{TOOL_NAME}/{OUTPUT_DIRNAME}",
                "output_exists": inspection.produced,
                "has_manifest": inspection.has_manifest,
                "has_res": inspection.has_res,
                "has_smali": inspection.has_smali,
                "has_apktool_yml": inspection.has_apktool_yml,
                "stdout_truncated": executed.stdout_truncated,
                "stderr_truncated": executed.stderr_truncated,
                "error": executed.error,
            },
        )
        logger.info(
            "apktool adapter name=%s status=%s version=%s exit_code=%s "
            "duration_seconds=%.3f output=%s has_manifest=%s has_res=%s has_smali=%s",
            self.name,
            status.value,
            self._version,
            executed.exit_code,
            executed.duration_seconds,
            output_dir.name,
            inspection.has_manifest,
            inspection.has_res,
            inspection.has_smali,
        )
        return ToolRunResult(
            name=self.name,
            status=status,
            version=self._version,
            reason=reason,
            output_dir=tool_root,
            findings=[],
            extras={
                "decoded_dir": str(output_dir) if inspection.meaningful else None,
                "has_manifest": inspection.has_manifest,
                "has_res": inspection.has_res,
                "has_smali": inspection.has_smali,
            },
            execution_status=executed.status,
            exit_code=executed.exit_code,
            duration_seconds=executed.duration_seconds,
            stdout_truncated=executed.stdout_truncated,
            stderr_truncated=executed.stderr_truncated,
        )

    def _skip(
        self,
        *,
        status: ToolStatus,
        reason: str,
        output_dir: Path,
        execution_status: ToolExecutionStatus | None,
    ) -> ToolRunResult:
        logger.info("apktool adapter name=%s status=%s reason=%s", self.name, status.value, reason)
        return ToolRunResult(
            name=self.name,
            status=status,
            version=self._version,
            reason=reason,
            output_dir=output_dir,
            findings=[],
            execution_status=execution_status,
        )


class DecodedInspection:
    def __init__(self, output_dir: Path) -> None:
        self.produced = output_dir.is_dir() and any(output_dir.iterdir())
        self.has_manifest = (output_dir / "AndroidManifest.xml").is_file()
        self.has_apktool_yml = (output_dir / "apktool.yml").is_file()
        self.has_res = (output_dir / "res").is_dir()
        self.has_smali = False
        if output_dir.is_dir():
            self.has_smali = any(
                path.is_dir() and path.name.startswith("smali") for path in output_dir.iterdir()
            )
        self.meaningful = self.has_manifest or (
            self.has_apktool_yml and (self.has_res or self.has_smali)
        )


def inspect_decoded_project(output_dir: Path) -> DecodedInspection:
    return DecodedInspection(output_dir)


def _is_apk(context: ScanContext) -> bool:
    return context.job.platform is Platform.ANDROID and context.job.artifact_kind is ArtifactKind.APK


def _map_status(executed: ToolExecutionResult, inspection: DecodedInspection) -> tuple[ToolStatus, str]:
    if executed.status is ToolExecutionStatus.NOT_AVAILABLE:
        return ToolStatus.NOT_AVAILABLE, "apktool executable was not found in PATH."
    if executed.status is ToolExecutionStatus.TIMEOUT:
        return ToolStatus.TIMEOUT, executed.error or "apktool timed out"
    if executed.status is ToolExecutionStatus.FAILED:
        return ToolStatus.AVAILABLE_BUT_FAILED, executed.error or "apktool execution failed"
    if executed.status is ToolExecutionStatus.EXECUTED and not inspection.produced:
        return ToolStatus.AVAILABLE_BUT_FAILED, "apktool reported success but produced no output"
    if executed.status is ToolExecutionStatus.EXECUTED and not inspection.meaningful:
        return ToolStatus.AVAILABLE_BUT_FAILED, "apktool output is missing expected decoded artifacts"
    if executed.status is ToolExecutionStatus.EXECUTED:
        return (
            ToolStatus.AVAILABLE_AND_EXECUTED,
            f"apktool wrote output under tools/{TOOL_NAME}/{OUTPUT_DIRNAME}/",
        )
    return ToolStatus.AVAILABLE_BUT_FAILED, executed.error or "apktool execution failed"


def _write_metadata(tool_root: Path, payload: dict[str, object]) -> None:
    path = tool_root / "apktool-meta.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def apktool_decoded_dir(output_dir: Path | None) -> Path | None:
    if output_dir is None:
        return None
    candidate = output_dir / OUTPUT_DIRNAME
    if candidate.is_dir():
        return candidate
    decoded = output_dir / "decoded"
    if decoded.is_dir():
        return decoded
    return output_dir if output_dir.is_dir() else None
