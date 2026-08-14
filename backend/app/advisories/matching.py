"""Version/range matching using provider-supplied range semantics."""

from __future__ import annotations

from collections.abc import Callable

from packaging.version import InvalidVersion
from packaging.version import Version as SemVer

from app.advisories.maven_version import MavenVersion
from app.models.advisory import Advisory, AffectedRange, MatchStatus

Comparator = Callable[[str, str], int]


def match_advisory(version: str, advisory: Advisory, *, ecosystem: str) -> MatchStatus:
    """Return affected / not_affected / unknown. Never guess affected."""

    if advisory.affected_versions:
        if version in advisory.affected_versions:
            return "affected"
    if not advisory.affected_ranges and not advisory.affected_versions:
        return "unknown"
    if not advisory.affected_ranges:
        return "not_affected" if advisory.affected_versions else "unknown"

    usable = [item for item in advisory.affected_ranges if item.type.upper() in {"ECOSYSTEM", "SEMVER"}]
    if not usable:
        return "unknown"

    comparator = _comparator_for(ecosystem, usable)
    if comparator is None:
        if version in advisory.affected_versions:
            return "affected"
        return "unknown"

    saw_unknown = False
    for item in usable:
        status = _match_range(version, item, comparator)
        if status == "affected":
            return "affected"
        if status == "unknown":
            saw_unknown = True
    if saw_unknown:
        return "unknown"
    return "not_affected"


def _comparator_for(ecosystem: str, ranges: list[AffectedRange]) -> Comparator | None:
    types = {item.type.upper() for item in ranges}
    eco = ecosystem.lower()
    if types <= {"ECOSYSTEM"} and eco == "maven":
        return _maven_cmp
    if types <= {"SEMVER"}:
        return _semver_cmp
    if types <= {"ECOSYSTEM", "SEMVER"} and eco == "maven":
        return _maven_cmp
    if types <= {"ECOSYSTEM", "SEMVER"} and eco == "pub":
        return _semver_cmp
    if types <= {"ECOSYSTEM"} and eco == "pub":
        return _semver_cmp
    return None


def _maven_cmp(left: str, right: str) -> int:
    return (MavenVersion(left) > MavenVersion(right)) - (MavenVersion(left) < MavenVersion(right))


def _semver_cmp(left: str, right: str) -> int:
    l_ver = SemVer(left)
    r_ver = SemVer(right)
    return (l_ver > r_ver) - (l_ver < r_ver)


def _match_range(version: str, item: AffectedRange, default_cmp: Comparator) -> MatchStatus:
    rtype = item.type.upper()
    if rtype == "GIT":
        return "unknown"
    if rtype == "SEMVER":
        comparator: Comparator = _semver_cmp
    elif rtype == "ECOSYSTEM":
        comparator = default_cmp
    else:
        return "unknown"
    try:
        return _apply_bounds(version, item, comparator)
    except (ValueError, InvalidVersion):
        return "unknown"


def _apply_bounds(version: str, item: AffectedRange, comparator: Comparator) -> MatchStatus:
    introduced = item.introduced or "0"
    if comparator(version, introduced) < 0:
        return "not_affected"
    if item.limit and comparator(version, item.limit) >= 0:
        return "not_affected"
    if item.fixed and comparator(version, item.fixed) >= 0:
        return "not_affected"
    if item.last_affected is not None:
        if comparator(version, item.last_affected) <= 0:
            return "affected"
        return "not_affected"
    if item.fixed or item.limit:
        return "affected"
    # introduced only, no upper bound: still affected (unfixed).
    return "affected"
