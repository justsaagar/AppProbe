"""Advisory provider abstraction.

VulnerabilityScanner talks only to this interface. HTTP and OSV JSON live in
the OSV provider so additional sources (GitHub Advisory, NVD, vendors) can be
added without rewriting the scanner.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from app.models.advisory import Advisory


class AdvisoryProviderError(Exception):
    """Raised when a provider cannot complete a lookup safely."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class PackageQuery:
    ecosystem: str
    package: str
    version: str

    @property
    def cache_key(self) -> str:
        return f"{self.ecosystem}:{self.package}:{self.version}"


@dataclass
class AdvisoryLookup:
    query: PackageQuery
    advisories: list[Advisory] = field(default_factory=list)
    error: AdvisoryProviderError | None = None


class AdvisoryProvider(Protocol):
    name: str

    async def query(self, package: str, ecosystem: str, version: str) -> list[Advisory]:
        """Return advisories for one package/version.

        Implementations must not claim a match when identity or version is
        uncertain. Network failures should raise AdvisoryProviderError.
        """

    async def query_batch(self, queries: Sequence[PackageQuery]) -> list[AdvisoryLookup]:
        """Look up many package/version pairs. Results align with ``queries``."""
