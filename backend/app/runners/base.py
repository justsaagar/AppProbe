from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuntimeStatus:
    executed: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


class RuntimeRunner(ABC):
    name: str

    @abstractmethod
    async def available(self) -> RuntimeStatus:
        raise NotImplementedError

    async def prepare(self) -> RuntimeStatus:
        return await self.available()

    async def install(self, artifact: str) -> RuntimeStatus:
        return await self.available()

    async def launch(self, package_name: str) -> RuntimeStatus:
        return await self.available()

    async def stop(self) -> RuntimeStatus:
        return RuntimeStatus(executed=False, reason="Runtime was not started")

    async def collect_logs(self) -> RuntimeStatus:
        return RuntimeStatus(executed=False, reason="Runtime was not started")

    async def capture_screenshot(self) -> RuntimeStatus:
        return RuntimeStatus(executed=False, reason="Runtime was not started")
