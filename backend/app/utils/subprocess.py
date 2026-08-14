"""Safe subprocess invocation. Never uses shell interpolation."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


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


_ALLOWED_ENV = {
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TMP",
    "TEMP",
    "USER",
    "LOGNAME",
    "ANDROID_SDK_ROOT",
    "ANDROID_HOME",
    "JAVA_HOME",
}


def _sanitize_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in _ALLOWED_ENV}
    if extra:
        env.update(extra)
    return env


async def run_command(
    args: list[str],
    *,
    timeout: float = 60.0,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> SubprocessResult:
    """Run a command as an argument array. ``shell`` is never enabled."""
    if not args:
        raise SubprocessError("empty command")
    if any(not isinstance(arg, str) for arg in args):
        raise SubprocessError("command arguments must be strings")
    if any("\x00" in arg for arg in args):
        raise SubprocessError("NUL byte in command argument")

    logger.debug("running command args=%s cwd=%s", args, cwd)
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=_sanitize_env(extra_env),
        )
    except FileNotFoundError as exc:
        raise SubprocessError(f"executable not found: {args[0]}") from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            process.communicate(input=input_bytes),
            timeout=timeout,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise SubprocessError(
            f"command timed out after {timeout}s: {args[0]}",
            returncode=None,
        ) from exc

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    returncode = process.returncode or 0
    if returncode != 0:
        raise SubprocessError(
            f"command failed ({returncode}): {args[0]}",
            returncode=returncode,
            stderr=stderr,
        )
    return SubprocessResult(args=list(args), returncode=returncode, stdout=stdout, stderr=stderr)


def run_command_sync(
    args: list[str],
    *,
    timeout: float = 60.0,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> SubprocessResult:
    """Synchronous wrapper used by unit tests and non-async callers."""
    return asyncio.run(
        run_command(args, timeout=timeout, cwd=cwd, extra_env=extra_env)
    )
