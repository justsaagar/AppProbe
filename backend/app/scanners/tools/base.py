"""External static-analysis tool adapters.

Adapters detect availability, run with argument arrays and timeouts, and
return structured status. They never invent findings when a tool is absent.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.enums import ToolExecutionStatus, ToolStatus
from app.models.finding import Finding
from app.models.scan_job import ToolRunRecord
from app.scanners.base import ScanContext
from app.storage.workspace import ScanWorkspace
from app.tools.discovery import resolve_executable
from app.tools.executor import ExternalToolExecutor
from app.utils.redact import redact_text
from app.utils.subprocess import SubprocessResult

logger = logging.getLogger(__name__)


@dataclass
class ToolRunResult:
    name: str
    status: ToolStatus
    version: str | None = None
    reason: str = ""
    output_dir: Path | None = None
    findings: list[Finding] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)
    execution_status: ToolExecutionStatus | None = None
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    def record(self) -> ToolRunRecord:
        return ToolRunRecord(
            name=self.name,
            status=self.status,
            version=self.version,
            reason=self.reason,
            output_dir=str(self.output_dir) if self.output_dir else None,
            execution_status=self.execution_status,
            exit_code=self.exit_code,
            duration_seconds=self.duration_seconds,
            stdout_truncated=self.stdout_truncated,
            stderr_truncated=self.stderr_truncated,
        )


class ExternalTool(ABC):
    name: str

    def is_available(self) -> bool:
        return False

    def version(self) -> str | None:
        return None

    @abstractmethod
    async def run(self, context: ScanContext) -> ToolRunResult:
        """Execute the tool against the scan artifact. Must not raise for unavailability."""

    def skipped(self, *, reason: str, status: ToolStatus = ToolStatus.NOT_AVAILABLE) -> ToolRunResult:
        return ToolRunResult(name=self.name, status=status, version=self.version(), reason=reason)


def resolve_binary(explicit: str | None, *candidates: str) -> str | None:
    return resolve_executable(explicit, *candidates)


async def capture_version(args: list[str], *, timeout: float = 15.0) -> str | None:
    if not args:
        return None
    return await ExternalToolExecutor().get_version(args[0], list(args[1:]), timeout=timeout)


def write_tool_logs(directory: Path, result: SubprocessResult) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (directory / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    logger.info(
        "tool finished executable=%s returncode=%s stdout_chars=%s",
        result.args[0] if result.args else "unknown",
        result.returncode,
        len(result.stdout),
    )
    if result.stderr:
        logger.debug("tool stderr redacted=%s", redact_text(result.stderr[:500]))


def tool_output_dir(workspace: ScanWorkspace, name: str) -> Path:
    return workspace.tool_dir(name)
