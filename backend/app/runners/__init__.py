"""Runtime runners (Milestone 3+)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class RuntimeUnavailable(RuntimeError):
    """Raised when a runtime environment is not present. Never treat as a vuln."""


class RuntimeRunner(ABC):
    name: str

    @abstractmethod
    async def is_available(self) -> bool: ...

    @abstractmethod
    async def prepare(self) -> None: ...

    @abstractmethod
    async def install(self, artifact: Path) -> None: ...

    @abstractmethod
    async def launch(self, package_name: str) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def collect_logs(self) -> str: ...

    @abstractmethod
    async def capture_screenshot(self) -> Path | None: ...


class UnavailableRuntimeRunner(RuntimeRunner):
    """Used until emulator/ADB integration lands in Milestone 3."""

    name = "unavailable"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    async def is_available(self) -> bool:
        return False

    async def prepare(self) -> None:
        raise RuntimeUnavailable(self.reason)

    async def install(self, artifact: Path) -> None:
        raise RuntimeUnavailable(self.reason)

    async def launch(self, package_name: str) -> None:
        raise RuntimeUnavailable(self.reason)

    async def stop(self) -> None:
        return None

    async def collect_logs(self) -> str:
        raise RuntimeUnavailable(self.reason)

    async def capture_screenshot(self) -> Path | None:
        raise RuntimeUnavailable(self.reason)
