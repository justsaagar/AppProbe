"""Safe asyncio subprocess runner for untrusted APK/AAB/IPA analysis tools."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from pathlib import Path

from app.config import Settings, get_settings
from app.models.enums import ToolExecutionStatus
from app.tools.definition import ToolDefinition
from app.tools.discovery import resolve_executable
from app.tools.result import ToolExecutionResult

logger = logging.getLogger(__name__)

_ALLOWED_ENV = frozenset(
    {
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
)
_READ_CHUNK = 65_536
_TERMINATE_WAIT_SECONDS = 2.0


def merge_env(override: dict[str, str] | None = None) -> dict[str, str]:
    """Allowlisted process env plus optional overrides. Never logged."""
    env = {key: value for key, value in os.environ.items() if key in _ALLOWED_ENV}
    if override:
        env.update(override)
    return env


async def _read_stream_limited(stream: asyncio.StreamReader, max_bytes: int) -> tuple[bytes, bool]:
    buf = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(_READ_CHUNK)
        if not chunk:
            break
        if truncated:
            continue
        remaining = max_bytes - len(buf)
        if remaining <= 0:
            truncated = True
            continue
        if len(chunk) > remaining:
            buf.extend(chunk[:remaining])
            truncated = True
        else:
            buf.extend(chunk)
    return bytes(buf), truncated


async def _write_stdin(stream: asyncio.StreamWriter, payload: bytes) -> None:
    stream.write(payload)
    await stream.drain()
    stream.close()
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        await stream.wait_closed()


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=_TERMINATE_WAIT_SECONDS)
        return
    except TimeoutError:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=_TERMINATE_WAIT_SECONDS)
    except TimeoutError:
        logger.warning("tool process did not exit after kill pid=%s", process.pid)


class ExternalToolExecutor:
    """Discover and run external executables without coupling to scan orchestration."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def resolve(self, definition: ToolDefinition) -> str | None:
        return resolve_executable(definition.executable)

    def is_available(self, definition: ToolDefinition) -> bool:
        return self.resolve(definition) is not None

    def probe(self, definition: ToolDefinition) -> ToolExecutionResult:
        resolved = self.resolve(definition)
        if resolved is None:
            return ToolExecutionResult(
                status=ToolExecutionStatus.NOT_AVAILABLE,
                command_name=definition.name,
                error=f"executable not found: {definition.executable}",
            )
        return ToolExecutionResult(
            status=ToolExecutionStatus.AVAILABLE,
            command_name=definition.name,
            executable=resolved,
        )

    async def get_version(
        self,
        executable: str,
        version_args: list[str] | None = None,
        *,
        timeout: float = 15.0,
    ) -> str | None:
        """Run ``executable`` with adapter-supplied version args. Never fails a scan."""
        args = list(version_args) if version_args is not None else ["--version"]
        definition = ToolDefinition(
            name=Path(executable).name,
            executable=executable,
            version_args=tuple(args),
        )
        result = await self.run(definition, args, timeout=timeout)
        if result.status is not ToolExecutionStatus.EXECUTED:
            return None
        text = (result.stdout or result.stderr).strip()
        if not text:
            return None
        return text.splitlines()[0][:120]

    async def version(self, definition: ToolDefinition, *, timeout: float = 15.0) -> str | None:
        return await self.get_version(
            definition.executable,
            list(definition.version_args),
            timeout=timeout,
        )

    async def run(
        self,
        definition: ToolDefinition,
        args: list[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        max_output_bytes: int | None = None,
        input_bytes: bytes | None = None,
    ) -> ToolExecutionResult:
        started = time.perf_counter()
        timeout_s = float(self.settings.tool_timeout_seconds if timeout is None else timeout)
        limit = int(self.settings.tool_max_output_bytes if max_output_bytes is None else max_output_bytes)
        if limit < 0:
            limit = 0

        if any(not isinstance(arg, str) for arg in args) or any("\x00" in arg for arg in args):
            result = ToolExecutionResult(
                status=ToolExecutionStatus.FAILED,
                command_name=definition.name,
                error="command arguments must be NUL-free strings",
                duration_seconds=time.perf_counter() - started,
            )
            self._log(result, timeout_s, cwd)
            return result

        resolved = self.resolve(definition)
        if resolved is None:
            result = ToolExecutionResult(
                status=ToolExecutionStatus.NOT_AVAILABLE,
                command_name=definition.name,
                error=f"executable not found: {definition.executable}",
                duration_seconds=time.perf_counter() - started,
            )
            self._log(result, timeout_s, cwd)
            return result

        argv = [resolved, *args]
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=merge_env(env),
            )
        except FileNotFoundError:
            result = ToolExecutionResult(
                status=ToolExecutionStatus.NOT_AVAILABLE,
                command_name=definition.name,
                executable=resolved,
                error=f"executable not found: {resolved}",
                duration_seconds=time.perf_counter() - started,
            )
            self._log(result, timeout_s, cwd)
            return result
        except PermissionError:
            result = ToolExecutionResult(
                status=ToolExecutionStatus.FAILED,
                command_name=definition.name,
                executable=resolved,
                error="permission denied",
                duration_seconds=time.perf_counter() - started,
            )
            self._log(result, timeout_s, cwd)
            return result
        except OSError as exc:
            result = ToolExecutionResult(
                status=ToolExecutionStatus.FAILED,
                command_name=definition.name,
                executable=resolved,
                error=str(exc),
                duration_seconds=time.perf_counter() - started,
            )
            self._log(result, timeout_s, cwd)
            return result

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(_read_stream_limited(process.stdout, limit))
        stderr_task = asyncio.create_task(_read_stream_limited(process.stderr, limit))
        stdin_task: asyncio.Task[None] | None = None
        if input_bytes is not None and process.stdin is not None:
            stdin_task = asyncio.create_task(_write_stdin(process.stdin, input_bytes))

        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout_s)
        except TimeoutError:
            timed_out = True
            await _terminate_process(process)

        if stdin_task is not None:
            stdin_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await stdin_task

        stdout_b, stdout_truncated = await stdout_task
        stderr_b, stderr_truncated = await stderr_task
        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        exit_code = process.returncode
        duration = time.perf_counter() - started

        if timed_out:
            status = ToolExecutionStatus.TIMEOUT
            error = f"timed out after {timeout_s}s"
        elif exit_code == 0:
            status = ToolExecutionStatus.EXECUTED
            error = None
        else:
            status = ToolExecutionStatus.FAILED
            error = f"exit code {exit_code}"

        result = ToolExecutionResult(
            status=status,
            command_name=definition.name,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            error=error,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            executable=resolved,
        )
        self._log(result, timeout_s, cwd)
        return result

    def _log(
        self,
        result: ToolExecutionResult,
        timeout_s: float,
        cwd: Path | None,
    ) -> None:
        executable_name = Path(result.executable).name if result.executable else result.command_name
        cwd_name = cwd.name if cwd is not None else None
        logger.info(
            "tool execution name=%s executable=%s status=%s exit_code=%s "
            "duration_seconds=%.3f timeout_seconds=%s stdout_truncated=%s "
            "stderr_truncated=%s cwd=%s",
            result.command_name,
            executable_name,
            result.status.value,
            result.exit_code,
            result.duration_seconds,
            timeout_s,
            result.stdout_truncated,
            result.stderr_truncated,
            cwd_name,
        )
