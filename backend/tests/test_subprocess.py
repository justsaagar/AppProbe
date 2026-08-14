import asyncio
from pathlib import Path

import pytest

from app.utils.subprocess import SubprocessError, run_command


@pytest.mark.asyncio
async def test_run_command_argument_array() -> None:
    result = await run_command(["/bin/echo", "hello world"])
    assert result.returncode == 0
    assert "hello world" in result.stdout


@pytest.mark.asyncio
async def test_does_not_evaluate_shell_metacharacters() -> None:
    result = await run_command(["/bin/echo", "a; rm -rf /"])
    assert "a; rm -rf /" in result.stdout


@pytest.mark.asyncio
async def test_timeout(tmp_path: Path) -> None:
    with pytest.raises(SubprocessError, match="timed out"):
        await run_command(["/bin/sleep", "5"], timeout=0.2)


@pytest.mark.asyncio
async def test_check_false_returns_nonzero() -> None:
    result = await run_command(["/bin/false"], check=False)
    assert result.returncode != 0


@pytest.mark.asyncio
async def test_missing_executable() -> None:
    with pytest.raises(SubprocessError, match="not found"):
        await run_command(["/definitely/not/a/binary"])


def test_rejects_nul_in_args() -> None:
    with pytest.raises(SubprocessError):
        asyncio.run(run_command(["/bin/echo", "bad\x00arg"]))
