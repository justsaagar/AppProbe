"""External static-analysis tool adapters.

Adapters detect availability, run with argument arrays and timeouts, and
return structured status. They never invent findings when a tool is absent.
"""

from __future__ import annotations

import logging
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.enums import ToolStatus
from app.models.finding import Finding
from app.models.scan_job import ToolRunRecord
from app.scanners.base import ScanContext
from app.storage.workspace import ScanWorkspace
from app.utils.paths import safe_join
from app.utils.redact import redact_text
from app.utils.subprocess import SubprocessError, SubprocessResult, run_command

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

    def record(self) -> ToolRunRecord:
        return ToolRunRecord(
            name=self.name,
            status=self.status,
            version=self.version,
            reason=self.reason,
            output_dir=str(self.output_dir) if self.output_dir else None,
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
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path)
        found = shutil.which(explicit)
        if found:
            return found
    for name in candidates:
        found = shutil.which(name)
        if found:
            return found
    return None


async def capture_version(args: list[str], *, timeout: float = 15.0) -> str | None:
    try:
        result = await run_command(args, timeout=timeout, check=False)
    except SubprocessError:
        return None
    text = (result.stdout or result.stderr).strip()
    if not text:
        return None
    return text.splitlines()[0][:120]


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
    path = safe_join(workspace.tools, name)
    path.mkdir(parents=True, exist_ok=True)
    return path
