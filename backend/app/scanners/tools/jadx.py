"""JADX decompilation adapter.

Runs JADX through the Milestone 2.1 executor. Produces isolated source for
later scanners. Does not emit security findings.
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

TOOL_NAME = "jadx"
OUTPUT_DIRNAME = "output"
VERSION_ARGS = ("--version",)


def jadx_definition(*, executable: str) -> ToolDefinition:
    return ToolDefinition(name=TOOL_NAME, executable=executable, version_args=VERSION_ARGS)


class JadxTool(ExternalTool):
    name = TOOL_NAME

    def __init__(
        self,
        settings: Settings | None = None,
        executor: ExternalToolExecutor | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.executor = executor or ExternalToolExecutor(self.settings)
        self._resolved = resolve_executable(self.settings.jadx_bin or None, "jadx", "jadx-cli")
        self.definition = jadx_definition(executable=self._resolved or (self.settings.jadx_bin or "jadx"))
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
                reason="JADX adapter currently requires an APK input.",
                output_dir=tool_root,
                execution_status=None,
            )
        if not self.is_available():
            return self._skip(
                status=ToolStatus.NOT_AVAILABLE,
                reason="JADX executable was not found in PATH.",
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
            self._jadx_args(output_dir, context.artifact_path),
            cwd=tool_root,
            timeout=float(self.settings.tool_timeout_seconds),
        )
        return self._from_execution(executed, tool_root=tool_root, output_dir=output_dir)

    def _jadx_args(self, output_dir: Path, artifact: Path) -> list[str]:
        return [
            "--quiet",
            "--threads-count",
            "2",
            "-d",
            str(output_dir),
            str(artifact),
        ]

    def _from_execution(
        self,
        executed: ToolExecutionResult,
        *,
        tool_root: Path,
        output_dir: Path,
    ) -> ToolRunResult:
        java_files = list(output_dir.rglob("*.java")) if output_dir.exists() else []
        produced = output_dir.is_dir() and any(output_dir.iterdir())
        status, reason = _map_status(executed, produced=produced)
        _write_metadata(
            tool_root,
            {
                "tool": self.name,
                "status": status.value,
                "execution_status": executed.status.value,
                "version": self._version,
                "exit_code": executed.exit_code,
                "duration_seconds": executed.duration_seconds,
                "output_dir": str(output_dir),
                "output_exists": produced,
                "java_file_count": len(java_files),
                "stdout_truncated": executed.stdout_truncated,
                "stderr_truncated": executed.stderr_truncated,
                "error": executed.error,
            },
        )
        logger.info(
            "jadx adapter name=%s status=%s version=%s exit_code=%s "
            "duration_seconds=%.3f java_file_count=%s output=%s",
            self.name,
            status.value,
            self._version,
            executed.exit_code,
            executed.duration_seconds,
            len(java_files),
            output_dir.name,
        )
        return ToolRunResult(
            name=self.name,
            status=status,
            version=self._version,
            reason=reason,
            output_dir=tool_root,
            findings=[],
            extras={
                "source_dir": str(output_dir) if produced else None,
                "java_file_count": len(java_files),
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
        logger.info("jadx adapter name=%s status=%s reason=%s", self.name, status.value, reason)
        return ToolRunResult(
            name=self.name,
            status=status,
            version=self._version,
            reason=reason,
            output_dir=output_dir,
            findings=[],
            execution_status=execution_status,
        )


def _is_apk(context: ScanContext) -> bool:
    return context.job.platform is Platform.ANDROID and context.job.artifact_kind is ArtifactKind.APK


def _map_status(executed: ToolExecutionResult, *, produced: bool) -> tuple[ToolStatus, str]:
    if executed.status is ToolExecutionStatus.NOT_AVAILABLE:
        return ToolStatus.NOT_AVAILABLE, "JADX executable was not found in PATH."
    if executed.status is ToolExecutionStatus.TIMEOUT:
        return ToolStatus.TIMEOUT, executed.error or "JADX timed out"
    if executed.status is ToolExecutionStatus.FAILED:
        return ToolStatus.AVAILABLE_BUT_FAILED, executed.error or "JADX execution failed"
    if executed.status is ToolExecutionStatus.EXECUTED and not produced:
        return ToolStatus.AVAILABLE_BUT_FAILED, "JADX reported success but produced no output"
    if executed.status is ToolExecutionStatus.EXECUTED:
        return (
            ToolStatus.AVAILABLE_AND_EXECUTED,
            f"JADX wrote output under tools/{TOOL_NAME}/{OUTPUT_DIRNAME}/",
        )
    return ToolStatus.AVAILABLE_BUT_FAILED, executed.error or "JADX execution failed"


def _write_metadata(tool_root: Path, payload: dict[str, object]) -> None:
    path = tool_root / "jadx-meta.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def jadx_source_dir(output_dir: Path | None) -> Path | None:
    if output_dir is None:
        return None
    candidate = output_dir / OUTPUT_DIRNAME
    if candidate.is_dir():
        return candidate
    return output_dir if output_dir.is_dir() else None
