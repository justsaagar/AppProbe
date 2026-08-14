"""Normalized result of one external-tool invocation."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import ToolExecutionStatus


@dataclass(frozen=True)
class ToolExecutionResult:
    status: ToolExecutionStatus
    command_name: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    version: str | None = None
    error: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    executable: str | None = None
