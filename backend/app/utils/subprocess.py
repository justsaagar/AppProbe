"""Safe subprocess invocation. Never uses shell interpolation.

Process spawning lives in ``app.tools.executor``. This module keeps the
historical ``run_command`` helpers used by existing scanners.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from app.models.enums import ToolExecutionStatus
from app.tools.definition import ToolDefinition
from app.tools.executor import ExternalToolExecutor, merge_env


class SubprocessError(RuntimeError):
    def __init__(self, message: str, *, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


@dataclass(frozen=True)
class SubprocessResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


async def run_command(
    args: list[str],
    *,
    timeout: float = 60.0,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> SubprocessResult:
    """Run a command as an argument array. ``shell`` is never enabled."""
    if not args:
        raise SubprocessError("empty command")
    if any(not isinstance(arg, str) for arg in args):
        raise SubprocessError("command arguments must be strings")
    if any("\x00" in arg for arg in args):
        raise SubprocessError("NUL byte in command argument")

    definition = ToolDefinition(name=Path(args[0]).name, executable=args[0])
    executed = await ExternalToolExecutor().run(
        definition,
        list(args[1:]),
        cwd=cwd,
        timeout=timeout,
        env=extra_env,
        input_bytes=input_bytes,
    )
    if executed.status is ToolExecutionStatus.NOT_AVAILABLE:
        raise SubprocessError(executed.error or f"executable not found: {args[0]}")
    if executed.status is ToolExecutionStatus.TIMEOUT:
        raise SubprocessError(
            executed.error or f"command timed out after {timeout}s: {args[0]}",
            returncode=executed.exit_code,
            stderr=executed.stderr,
        )
    returncode = executed.exit_code if executed.exit_code is not None else 1
    if check and executed.status is not ToolExecutionStatus.EXECUTED:
        raise SubprocessError(
            executed.error or f"command failed ({returncode}): {args[0]}",
            returncode=returncode,
            stderr=executed.stderr,
        )
    return SubprocessResult(
        args=list(args),
        returncode=returncode,
        stdout=executed.stdout,
        stderr=executed.stderr,
    )


def run_command_sync(
    args: list[str],
    *,
    timeout: float = 60.0,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
    check: bool = True,
) -> SubprocessResult:
    """Synchronous wrapper used by unit tests and non-async callers."""
    return asyncio.run(
        run_command(args, timeout=timeout, cwd=cwd, extra_env=extra_env, check=check)
    )


__all__ = [
    "SubprocessError",
    "SubprocessResult",
    "merge_env",
    "run_command",
    "run_command_sync",
]
