"""Technology inventory records for the dependency/SDK scanner."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.models.finding import Evidence


class TechCategory(StrEnum):
    FRAMEWORK = "FRAMEWORK"
    SDK = "SDK"
    LIBRARY = "LIBRARY"
    PAYMENT = "PAYMENT"
    ANALYTICS = "ANALYTICS"
    NETWORKING = "NETWORKING"
    MAPS = "MAPS"
    DATABASE = "DATABASE"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    NATIVE_LIBRARY = "NATIVE_LIBRARY"
    AUTHENTICATION = "AUTHENTICATION"
    MESSAGING = "MESSAGING"
    OTHER = "OTHER"


class BundledKind(StrEnum):
    APPLICATION_BUNDLED = "APPLICATION_BUNDLED"
    PLATFORM_SYSTEM = "PLATFORM_SYSTEM"
    UNKNOWN = "UNKNOWN"


class TechnologyRecord(BaseModel):
    """One detected library/SDK/framework. Informational — not a vulnerability."""

    name: str
    vendor: str = ""
    category: TechCategory | str = TechCategory.OTHER
    version: str | None = None
    version_confidence: float = 0.0
    detection_source: str = ""
    sources: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    evidence: list[Evidence] = Field(default_factory=list)
    bundled: BundledKind | str = BundledKind.APPLICATION_BUNDLED
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def version_label(self) -> str:
        return self.version if self.version else "Unknown"


class DependencyScanCoverage(BaseModel):
    """Measured dependency-scanner coverage. Values are never fabricated."""

    technologies_detected: int = 0
    versions_identified: int = 0
    versions_unknown: int = 0
    sources: list[str] = Field(default_factory=list)
