import sys

import pytest

from app.utils.subprocess import CommandError, CommandTimeoutError, run_command


@pytest.mark.asyncio
async def test_run_command_argument_list() -> None:
    result = await run_command([sys.executable, "-c", "print('ok-subprocess')"], timeout=10)
    assert result.returncode == 0
    assert "ok-subprocess" in result.stdout
    assert result.argv[0] == sys.executable


@pytest.mark.asyncio
async def test_rejects_shell_string() -> None:
    with pytest.raises(CommandError, match="argument list"):
        await run_command("echo hi")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_timeout() -> None:
    with pytest.raises(CommandTimeoutError):
        await run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
