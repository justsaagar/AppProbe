"""Pluggable scanner interface. Additional engines should implement Scanner."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.finding import Finding
from app.models.scan_job import ApplicationMetadata, ScanJob
from app.storage.workspace import ScanWorkspace


@dataclass
class ScanContext:
    job: ScanJob
    workspace: ScanWorkspace
    artifact_path: Path
    metadata: ApplicationMetadata | None = None
    extras: dict[str, Any] = field(default_factory=dict)


class Scanner(ABC):
    name: str
    description: str = ""

    def is_available(self) -> bool:
        return True

    def supports(self, context: ScanContext) -> bool:
        return True

    @abstractmethod
    async def scan(self, context: ScanContext) -> list[Finding]:
        """Return normalized findings. Must not invent evidence."""
