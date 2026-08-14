"""apktool adapter. Decodes resources; does not replace the Milestone 1 AXML parser."""

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


class ApktoolTool(ExternalTool):
    name = "apktool"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._bin = resolve_binary(self.settings.apktool_bin or None, "apktool")

    def is_available(self) -> bool:
        return self._bin is not None

    async def run(self, context: ScanContext) -> ToolRunResult:
        if context.job.platform is not Platform.ANDROID:
            return self.skipped(
                reason="apktool applies to Android artifacts only.",
                status=ToolStatus.NOT_EXECUTED,
            )
        if context.job.artifact_kind is ArtifactKind.AAB:
            return self.skipped(
                reason="apktool was not run against the AAB; it is not an installable APK.",
                status=ToolStatus.NOT_EXECUTED,
            )
        if not self.is_available():
            return self.skipped(
                reason="apktool was not available in the scan environment.",
                status=ToolStatus.NOT_AVAILABLE,
            )
        assert self._bin
        output = tool_output_dir(context.workspace, self.name)
        decoded = output / "decoded"
        version = await capture_version([self._bin, "--version"])
        args = [
            self._bin,
            "d",
            "-f",
            "-o",
            str(decoded),
            str(context.artifact_path),
        ]
        try:
            result = await run_command(
                args,
                timeout=self.settings.tool_timeout_seconds,
                check=False,
            )
        except SubprocessError as exc:
            reason = "apktool timed out" if "timed out" in str(exc) else str(exc)
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version=version,
                reason=reason,
                output_dir=output,
            )
        write_tool_logs(output, result)
        if result.returncode != 0 and not decoded.exists():
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version=version,
                reason=f"apktool exited {result.returncode}",
                output_dir=output,
            )
        manifest = decoded / "AndroidManifest.xml"
        (output / "summary.txt").write_text(
            f"decoded={decoded.exists()}\nmanifest={manifest.is_file()}\nreturncode={result.returncode}\n",
            encoding="utf-8",
        )
        return ToolRunResult(
            name=self.name,
            status=ToolStatus.AVAILABLE_AND_EXECUTED,
            version=version,
            reason="apktool decode completed" if result.returncode == 0 else f"apktool exited {result.returncode}",
            output_dir=output,
            extras={"decoded_dir": str(decoded), "has_manifest": manifest.is_file()},
        )


def apktool_decoded_dir(output_dir: Path | None) -> Path | None:
    if output_dir is None:
        return None
    decoded = output_dir / "decoded"
    return decoded if decoded.is_dir() else None
