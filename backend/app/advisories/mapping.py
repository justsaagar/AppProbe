"""Deterministic technology → package ecosystem mapping.

Coordinates are taken from known signatures or Maven pom.properties evidence.
Identifiers are never invented or fuzzy-matched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.advisories.maven_version import is_usable_version
from app.advisories.provider import PackageQuery
from app.models.technology import BundledKind, TechnologyRecord

if TYPE_CHECKING:
    from app.scanners.tech_signatures import TechSignature

POM_PATH_RE = re.compile(
    r"META-INF/maven/([^/]+)/([^/]+)/pom\.properties$",
    re.IGNORECASE,
)

REASON_IDENTITY = "Package identity unavailable."
REASON_VERSION = "Dependency version could not be determined reliably."
REASON_INVALID_VERSION = "Dependency version is not a usable release identifier."
REASON_PLATFORM = "Platform/system component is not mapped to an advisory package."
REASON_FLUTTER_VERSION = "Dart/Flutter package version could not be determined reliably."


@dataclass(frozen=True)
class MappedPackage:
    technology: str
    query: PackageQuery | None
    skip_reason: str | None = None
    identity: str = "none"


_BY_NAME: dict[str, TechSignature] | None = None


def _signatures_by_name() -> dict[str, TechSignature]:
    global _BY_NAME
    if _BY_NAME is None:
        from app.scanners.tech_signatures import SIGNATURES

        _BY_NAME = {item.name: item for item in SIGNATURES}
    return _BY_NAME


def map_technology(record: TechnologyRecord) -> MappedPackage:
    """Return a query only when identity and version are both known."""

    if _is_platform(record):
        return MappedPackage(record.name, None, REASON_PLATFORM)

    signature = _signatures_by_name().get(record.name)
    coordinate = _coordinate_from_evidence(record) or _coordinate_from_signature(signature)
    ecosystem, package, identity = coordinate if coordinate else (None, None, "none")

    if ecosystem is None or package is None:
        return MappedPackage(record.name, None, REASON_IDENTITY)

    version = record.version
    if not version:
        reason = REASON_FLUTTER_VERSION if ecosystem == "Pub" else REASON_VERSION
        return MappedPackage(record.name, None, reason, identity=identity)
    if not is_usable_version(version):
        return MappedPackage(record.name, None, REASON_INVALID_VERSION, identity=identity)

    return MappedPackage(
        technology=record.name,
        query=PackageQuery(ecosystem=ecosystem, package=package, version=version),
        identity=identity,
    )


def _is_platform(record: TechnologyRecord) -> bool:
    bundled = record.bundled.value if isinstance(record.bundled, BundledKind) else str(record.bundled)
    return bundled == BundledKind.PLATFORM_SYSTEM.value


def _coordinate_from_evidence(record: TechnologyRecord) -> tuple[str, str, str] | None:
    for item in record.evidence:
        location = item.location or ""
        pom = POM_PATH_RE.search(location.replace("\\", "/"))
        if pom:
            group, artifact = pom.group(1), pom.group(2)
            if group and artifact:
                return ("Maven", f"{group}:{artifact}", "exact")
    return None


def _coordinate_from_signature(signature: TechSignature | None) -> tuple[str, str, str] | None:
    if signature is None:
        return None
    if len(signature.maven) == 1:
        group, artifact = signature.maven[0]
        return ("Maven", f"{group}:{artifact}", "exact")
    if signature.maven:
        # Multiple Maven coordinates without pom evidence — do not guess.
        return None
    if len(signature.flutter_packages) == 1:
        return ("Pub", signature.flutter_packages[0], "exact")
    return None
