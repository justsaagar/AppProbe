"""Tests for the generic external-tool execution layer.

Uses the interpreter and tiny local scripts. Does not require JADX, apktool, or MobSF.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import ToolExecutionStatus
from app.storage.workspace import ScanWorkspace
from app.tools.definition import ToolDefinition
from app.tools.discovery import resolve_executable
from app.tools.executor import ExternalToolExecutor

PYTHON = sys.executable


def _executor(tmp_path: Path, **kwargs: int) -> ExternalToolExecutor:
    settings = Settings(
        workspace_dir=tmp_path / "ws",
        tool_timeout_seconds=kwargs.get("tool_timeout_seconds", 30),
        tool_max_output_bytes=kwargs.get("tool_max_output_bytes", 1_048_576),
    )
    return ExternalToolExecutor(settings)


def _python() -> ToolDefinition:
    return ToolDefinition(name="python", executable=PYTHON, version_args=("--version",))


@pytest.mark.asyncio
async def test_discovery_executable_exists() -> None:
    assert resolve_executable(PYTHON) is not None
    executor = ExternalToolExecutor(Settings())
    probe = executor.probe(_python())
    assert probe.status is ToolExecutionStatus.AVAILABLE
    assert executor.is_available(_python())


@pytest.mark.asyncio
async def test_discovery_executable_missing(tmp_path: Path) -> None:
    missing = ToolDefinition(name="missing", executable=str(tmp_path / "no-such-tool-appprobe"))
    executor = _executor(tmp_path)
    assert executor.is_available(missing) is False
    probe = executor.probe(missing)
    assert probe.status is ToolExecutionStatus.NOT_AVAILABLE
    result = await executor.run(missing, ["--help"])
    assert result.status is ToolExecutionStatus.NOT_AVAILABLE
    assert result.exit_code is None


@pytest.mark.asyncio
async def test_version_command_succeeds(tmp_path: Path) -> None:
    version = await _executor(tmp_path).get_version(PYTHON, ["--version"])
    assert version is not None
    assert "Python" in version


@pytest.mark.asyncio
async def test_version_command_fails(tmp_path: Path) -> None:
    version = await _executor(tmp_path).get_version(
        PYTHON,
        ["-c", "raise SystemExit(2)"],
    )
    assert version is None


@pytest.mark.asyncio
async def test_version_command_times_out(tmp_path: Path) -> None:
    version = await _executor(tmp_path).get_version(
        PYTHON,
        ["-c", "import time; time.sleep(30)"],
        timeout=0.3,
    )
    assert version is None


@pytest.mark.asyncio
async def test_successful_command_captures_stdout_stderr(tmp_path: Path) -> None:
    result = await _executor(tmp_path).run(
        _python(),
        ["-c", "import sys; sys.stdout.write('out-ok'); sys.stderr.write('err-ok')"],
    )
    assert result.status is ToolExecutionStatus.EXECUTED
    assert result.exit_code == 0
    assert "out-ok" in result.stdout
    assert "err-ok" in result.stderr
    assert result.duration_seconds > 0
    assert result.stdout_truncated is False
    assert result.stderr_truncated is False


@pytest.mark.asyncio
async def test_nonzero_exit_code_is_failed_not_exception(tmp_path: Path) -> None:
    result = await _executor(tmp_path).run(_python(), ["-c", "raise SystemExit(7)"])
    assert result.status is ToolExecutionStatus.FAILED
    assert result.exit_code == 7


@pytest.mark.asyncio
async def test_permission_failure(tmp_path: Path) -> None:
    script = tmp_path / "not-executable"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    script.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    result = await _executor(tmp_path).run(
        ToolDefinition(name="noexec", executable=str(script)),
        [],
    )
    assert result.status is ToolExecutionStatus.FAILED
    assert result.error is not None


@pytest.mark.asyncio
async def test_timeout_terminates_process(tmp_path: Path) -> None:
    pidfile = tmp_path / "pid.txt"
    result = await _executor(tmp_path).run(
        _python(),
        [
            "-c",
            "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)",
            str(pidfile),
        ],
        timeout=0.4,
    )
    assert result.status is ToolExecutionStatus.TIMEOUT
    assert result.error is not None
    assert result.duration_seconds < 5
    if pidfile.exists() and pidfile.read_text().strip().isdigit():
        pid = int(pidfile.read_text())
        with pytest.raises(OSError):
            os.kill(pid, 0)


@pytest.mark.asyncio
async def test_shell_metacharacters_are_literal_arguments(tmp_path: Path) -> None:
    marker = tmp_path / "should-not-exist"
    payload = f"$(touch {marker})"
    result = await _executor(tmp_path).run(
        _python(),
        ["-c", "import sys; print(sys.argv[1])", payload],
    )
    assert result.status is ToolExecutionStatus.EXECUTED
    assert payload in result.stdout
    assert not marker.exists()


@pytest.mark.asyncio
async def test_spaces_and_special_characters_in_paths(tmp_path: Path) -> None:
    folder = tmp_path / "dir with spaces"
    folder.mkdir()
    target = folder / "file;name.txt"
    target.write_text("ok", encoding="utf-8")
    result = await _executor(tmp_path).run(
        _python(),
        ["-c", "import sys; print(open(sys.argv[1]).read())", str(target)],
    )
    assert result.status is ToolExecutionStatus.EXECUTED
    assert "ok" in result.stdout


@pytest.mark.asyncio
async def test_stdout_and_stderr_truncation(tmp_path: Path) -> None:
    executor = _executor(tmp_path, tool_max_output_bytes=32)
    result = await executor.run(
        _python(),
        ["-c", "import sys; sys.stdout.write('O'*200); sys.stderr.write('E'*200)"],
        max_output_bytes=32,
    )
    assert result.status is ToolExecutionStatus.EXECUTED
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert len(result.stdout.encode()) <= 32
    assert len(result.stderr.encode()) <= 32
    assert result.stdout
    assert result.stderr


@pytest.mark.asyncio
async def test_environment_override_and_secrets_not_logged(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    marker = "FAKE_TOOL_ENV_VALUE_FOR_TEST_ONLY"
    caplog.set_level(logging.DEBUG)
    result = await _executor(tmp_path).run(
        _python(),
        ["-c", "import os; print(os.environ.get('APPPROBE_TOOL_TEST',''))"],
        env={"APPPROBE_TOOL_TEST": "visible-fixture", "MOBSF_API_KEY": marker},
    )
    assert result.status is ToolExecutionStatus.EXECUTED
    assert "visible-fixture" in result.stdout
    assert marker not in caplog.text
    assert "MOBSF_API_KEY" not in caplog.text


@pytest.mark.asyncio
async def test_workspace_cwd_isolation(tmp_path: Path) -> None:
    workspace = ScanWorkspace(tmp_path / "scans" / "scan-demo")
    workspace.ensure()
    cwd = workspace.tool_dir("demo-tool")
    result = await _executor(tmp_path).run(
        _python(),
        ["-c", "import os; print(os.getcwd())"],
        cwd=cwd,
    )
    assert result.status is ToolExecutionStatus.EXECUTED
    assert Path(result.stdout.strip()) == cwd
    assert cwd.is_relative_to(workspace.root)
