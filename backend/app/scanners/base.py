from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.analyzers.manifest_parser import AndroidMetadata
from app.models.enums import ArtifactKind, Platform
from app.models.finding import Finding
from app.models.scan_job import ScanJob


@dataclass
class ScanContext:
    job: ScanJob
    artifact_path: str
    kind: ArtifactKind
    platform: Platform
    metadata: dict[str, Any] = field(default_factory=dict)
    android: AndroidMetadata | None = None
    notes: list[str] = field(default_factory=list)


class Scanner(ABC):
    name: str

    @abstractmethod
    async def scan(self, artifact_path: str, context: ScanContext) -> list[Finding]:
        raise NotImplementedError
