"""JADX decompiler adapter. Produces isolated source for other scanners."""

from __future__ import annotations

import logging
from pathlib import Path

from app.config import Settings, get_settings
from app.models.enums import ArtifactKind, Platform, ToolStatus
from app.scanners.base import ScanContext
from app.scanners.tools.base import (
    ExternalTool,
    ToolRunResult,
    capture_version,
    resolve_binary,
    tool_output_dir,
    write_tool_logs,
)
from app.utils.subprocess import SubprocessError, run_command

logger = logging.getLogger(__name__)


class JadxTool(ExternalTool):
    name = "jadx"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._bin = resolve_binary(self.settings.jadx_bin or None, "jadx", "jadx-cli")

    def is_available(self) -> bool:
        return self._bin is not None

    def version(self) -> str | None:
        return None

    async def run(self, context: ScanContext) -> ToolRunResult:
        if context.job.platform is not Platform.ANDROID:
            return self.skipped(
                reason="JADX applies to Android artifacts only.",
                status=ToolStatus.NOT_EXECUTED,
            )
        if context.job.artifact_kind is ArtifactKind.AAB:
            return self.skipped(
                reason="JADX was not run against the AAB; APK-set generation is not implemented.",
                status=ToolStatus.NOT_EXECUTED,
            )
        if not self.is_available():
            return self.skipped(
                reason="JADX was not available in the scan environment.",
                status=ToolStatus.NOT_AVAILABLE,
            )
        assert self._bin
        output = tool_output_dir(context.workspace, self.name)
        sources = output / "sources"
        sources.mkdir(parents=True, exist_ok=True)
        version = await capture_version([self._bin, "--version"])
        args = [
            self._bin,
            "--quiet",
            "--no-imports",
            "--threads-count",
            "2",
            "-d",
            str(sources),
            str(context.artifact_path),
        ]
        try:
            result = await run_command(
                args,
                timeout=self.settings.tool_timeout_seconds,
                check=False,
            )
        except SubprocessError as exc:
            reason = "JADX timed out" if "timed out" in str(exc) else str(exc)
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version=version,
                reason=reason,
                output_dir=output,
            )
        write_tool_logs(output, result)
        java_files = list(sources.rglob("*.java")) if sources.exists() else []
        if result.returncode != 0 and not java_files:
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version=version,
                reason=f"JADX exited {result.returncode}",
                output_dir=output,
            )
        (output / "summary.txt").write_text(
            f"java_files={len(java_files)}\nreturncode={result.returncode}\n",
            encoding="utf-8",
        )
        return ToolRunResult(
            name=self.name,
            status=ToolStatus.AVAILABLE_AND_EXECUTED,
            version=version,
            reason=f"JADX wrote {len(java_files)} Java files",
            output_dir=output,
            extras={"source_dir": str(sources), "java_file_count": len(java_files)},
        )


def jadx_source_dir(output_dir: Path | None) -> Path | None:
    if output_dir is None:
        return None
    sources = output_dir / "sources"
    return sources if sources.is_dir() else None
