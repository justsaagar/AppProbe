"""Safe subprocess invocation. Never use shell interpolation."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


class CommandError(RuntimeError):
    """Raised when a subprocess cannot be started or violates policy."""


class CommandTimeoutError(TimeoutError):
    """Raised when a subprocess exceeds its timeout."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        raise CommandError("Command argv must not be empty")
    if isinstance(argv, str):
        raise CommandError("Command must be an argument list, not a shell string")
    cleaned: list[str] = []
    for item in argv:
        if not isinstance(item, str):
            raise CommandError("Command arguments must be strings")
        if "\x00" in item:
            raise CommandError("Null byte in command argument")
        cleaned.append(item)
    return tuple(cleaned)


async def run_command(
    argv: Sequence[str],
    *,
    timeout: float = 60.0,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = 2_000_000,
) -> CommandResult:
    """Run a process with an argument array, timeout, and captured output."""
    args = _validate_argv(argv)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"Executable not found: {args[0]}") from exc
    except OSError as exc:
        raise CommandError(f"Failed to start {args[0]}: {exc}") from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise CommandTimeoutError(f"Command timed out after {timeout}s: {args[0]}") from exc

    stdout = stdout_b[:max_output_bytes].decode("utf-8", errors="replace")
    stderr = stderr_b[:max_output_bytes].decode("utf-8", errors="replace")
    return CommandResult(
        argv=args,
        returncode=process.returncode or 0,
        stdout=stdout,
        stderr=stderr,
    )
