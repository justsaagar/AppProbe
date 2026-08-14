"""Deterministic cross-scanner finding correlation.

Extends the Milestone 1/2 merge helper. Correlation is not AI and does not
guess: when evidence is insufficient to establish a relationship, findings
remain separate. Original findings are never discarded.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

from app.analyzers.severity import rank
from app.models.enums import FindingCategory, RelationshipType, Severity, Verification
from app.models.finding import Finding
from app.models.scan_job import CorrelatedGroup, CorrelationSummary

_FAMILY = {
    "cleartext_traffic": "cleartext",
    "network_security_config_missing": "cleartext",
    "http_endpoint": "http_endpoint",
    "debuggable": "debuggable",
    "allow_backup": "backup",
    "exported_activity": "exported",
    "exported_service": "exported",
    "exported_receiver": "exported",
    "exported_provider": "exported",
    "dangerous_permission": "permission",
    "hardcoded_secret": "secret",
    "private_key": "secret",
    "jwt": "secret",
    "cloud_credential": "secret",
    "sdk_detected": "sdk",
    "weak_crypto": "crypto",
    "webview": "webview",
    "advisory_assessment": "process",
}

_TITLE_HINTS = (
    ("cleartext", "cleartext"),
    ("clear text", "cleartext"),
    ("usescleartexttraffic", "cleartext"),
    ("debuggable", "debuggable"),
    ("allowbackup", "backup"),
    ("allow backup", "backup"),
    ("exported", "exported"),
)

_LINE_SUFFIX = re.compile(r":(\d+)$")
_SECRETISH = re.compile(
    r"(sk_live_|sk_test_|rk_live_|rk_test_|ghp_|AKIA|AIza|eyJ[A-Za-z0-9_\-]{8,}\.|BEGIN PRIVATE)",
    re.I,
)
_MARKER_PREFIXES = (
    "tools/jadx/output/",
    "tools/apktool/output/",
)


@dataclass
class CorrelationResult:
    findings: list[Finding]
    groups: list[CorrelatedGroup]
    summary: CorrelationSummary
    raw_findings: list[Finding]


@dataclass
class _Normalized:
    finding: Finding
    family: str
    path: str
    line: int | None
    secret_type: str
    technology: str
    package: str
    advisory_id: str
    duplicate_key: str
    fingerprint: str
    originals: list[Finding] = field(default_factory=list)


def family_of(finding: Finding) -> str:
    if finding.rule_id and finding.rule_id in _FAMILY:
        return _FAMILY[finding.rule_id]
    if finding.rule_id and (
        finding.rule_id == "advisory_match" or finding.rule_id.startswith("advisory_match:")
    ):
        return "advisory"
    title = finding.title.lower()
    for needle, family in _TITLE_HINTS:
        if needle.lower() in title:
            return family
    if finding.category == FindingCategory.SECRETS or finding.category == "secrets":
        return "secret"
    if finding.category == FindingCategory.DEPENDENCY or finding.category == "dependency":
        if finding.rule_id == "sdk_detected":
            return "sdk"
        return "advisory" if finding.severity is not Severity.INFO else "sdk"
    if finding.category == FindingCategory.PROCESS or finding.category == "process":
        return "process"
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    return slug or "other"


def normalize_path(location: str | None) -> str:
    """Scan-relative path. Absolute machine paths are stripped from fingerprints."""

    if not location:
        return ""
    text = location.strip().replace("\\", "/")
    match = _LINE_SUFFIX.search(text)
    if match:
        text = text[: match.start()]
    while text.startswith("./"):
        text = text[2:]
    text = re.sub(r"/+", "/", text)
    lower = text.lower()
    for marker in _MARKER_PREFIXES:
        idx = lower.find(marker)
        if idx >= 0:
            text = text[idx:]
            break
    else:
        if text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
            parts = [part for part in text.split("/") if part]
            text = "/".join(parts[-3:]) if parts else ""
    return text.lower()


def split_location(location: str | None) -> tuple[str, int | None]:
    if not location:
        return "", None
    match = _LINE_SUFFIX.search(location.strip().replace("\\", "/"))
    line = int(match.group(1)) if match else None
    return normalize_path(location), line


def fingerprint_for(finding: Finding) -> str:
    """Stable duplicate fingerprint. Never includes secret values."""

    return _normalize(finding).fingerprint


def correlate_findings(findings: list[Finding]) -> tuple[list[Finding], list[CorrelatedGroup]]:
    """Backward-compatible wrapper around :func:`correlate`."""

    result = correlate(findings)
    return result.findings, result.groups


def correlate(findings: list[Finding]) -> CorrelationResult:
    raw = [item.model_copy(deep=True) for item in findings]
    if not findings:
        empty = CorrelationSummary()
        return CorrelationResult(findings=[], groups=[], summary=empty, raw_findings=raw)

    records = [_normalize(item) for item in findings]
    duplicate_buckets: dict[str, list[_Normalized]] = defaultdict(list)
    for record in records:
        duplicate_buckets[record.duplicate_key].append(record)

    merged_records: list[_Normalized] = []
    duplicate_groups: list[CorrelatedGroup] = []
    extras_merged = 0
    for key, bucket in duplicate_buckets.items():
        originals = [item.finding for item in bucket]
        primary = select_primary(originals)
        if len(bucket) == 1:
            record = bucket[0]
            record.finding.fingerprint = record.fingerprint
            if not record.finding.sources:
                record.finding.sources = [record.finding.source]
            record.originals = originals
            merged_records.append(record)
            continue
        extras_merged += len(bucket) - 1
        merged_finding = _merge_duplicates(originals, primary)
        merged_finding.fingerprint = bucket[0].fingerprint
        merged = _normalize(merged_finding)
        merged.originals = originals
        merged.fingerprint = bucket[0].fingerprint
        merged.duplicate_key = key
        merged_records.append(merged)
        duplicate_groups.append(
            _group_from(
                relationship=RelationshipType.DUPLICATE,
                fingerprint=merged.fingerprint,
                primary=merged_finding,
                members=originals,
                note=f"Merged {len(originals)} duplicate findings from " + ", ".join(merged_finding.sources),
            )
        )

    related_groups = _related_groups(merged_records)
    groups = _assign_group_ids(duplicate_groups + related_groups)
    reported = [item.finding for item in merged_records]
    reported.sort(key=lambda item: (rank(item.severity), item.title, item.id))

    grouped_ids: set[str] = set()
    for group in groups:
        grouped_ids.update(group.finding_ids)
        if group.canonical_id:
            grouped_ids.add(group.canonical_id)
    independent = sum(1 for item in reported if item.id not in grouped_ids)
    related_count = sum(
        1 for item in groups if item.relationship is not RelationshipType.DUPLICATE
    )
    duplicate_count = sum(1 for item in groups if item.relationship is RelationshipType.DUPLICATE)
    unique_issues = independent + len(groups)
    summary = CorrelationSummary(
        raw_findings=len(raw),
        correlated_findings=unique_issues,
        exact_duplicates_merged=extras_merged,
        related_groups=related_count,
        independent_findings=independent,
        duplicate_groups=duplicate_count,
    )
    return CorrelationResult(findings=reported, groups=groups, summary=summary, raw_findings=raw)


def select_primary(items: list[Finding]) -> Finding:
    """Deterministic primary selection. Vulnerability and confirmed secrets win."""

    def _key(item: Finding) -> tuple:
        family = family_of(item)
        is_vuln = family == "advisory" and item.verification is Verification.CONFIRMED
        is_secret = family == "secret" and item.verification is Verification.CONFIRMED
        is_info_inventory = item.rule_id == "sdk_detected" or (
            family == "sdk" and item.severity is Severity.INFO
        )
        verification_rank = {
            Verification.CONFIRMED: 0,
            Verification.POTENTIAL: 1,
            Verification.INFO: 2,
        }.get(item.verification, 3)
        return (
            0 if is_vuln else 1,
            0 if is_secret else 1,
            verification_rank,
            rank(item.severity),
            -item.confidence,
            1 if is_info_inventory else 0,
            0 if item.source == "manifest-scanner" else 1,
            item.id,
        )

    return sorted(items, key=_key)[0]


def reconcile_severity(items: list[Finding]) -> Severity:
    """Strongest justified severity. INFO-only observations cannot raise CONFIRMED groups."""

    confirmed = [
        item
        for item in items
        if item.verification is Verification.CONFIRMED and not item.potential
    ]
    if confirmed:
        return min((item.severity for item in confirmed), key=rank)
    potential = [
        item
        for item in items
        if item.verification is Verification.POTENTIAL or item.potential
    ]
    if potential:
        return min((item.severity for item in potential), key=rank)
    return min((item.severity for item in items), key=rank)


def reconcile_confidence(items: list[Finding]) -> float:
    """Independent corroboration increases confidence; never exceeds 1.0."""

    if len(items) == 1:
        return max(0.0, min(1.0, items[0].confidence))
    sources = {item.source for item in items}
    if len(sources) < 2:
        return max(0.0, min(1.0, max(item.confidence for item in items)))
    combined = 0.0
    for item in items:
        combined = 1.0 - (1.0 - combined) * (1.0 - max(0.0, min(1.0, item.confidence)))
    return min(1.0, combined)


def _normalize(finding: Finding) -> _Normalized:
    family = family_of(finding)
    location = ""
    if finding.evidence:
        location = finding.evidence[0].location or ""
        data_path = finding.evidence[0].data.get("path")
        if not location and isinstance(data_path, str):
            location = data_path
    path, line = split_location(location)
    if not path:
        path, line = split_location(finding.affected_component)
    secret_type = _secret_type(finding)
    package = _package_of(finding)
    technology = _technology_of(finding, package)
    advisory_id = _advisory_id(finding)
    duplicate_key = _duplicate_key(
        family=family,
        finding=finding,
        path=path,
        line=line,
        secret_type=secret_type,
        package=package,
        advisory_id=advisory_id,
    )
    digest = hashlib.sha256(duplicate_key.encode("utf-8")).hexdigest()[:16]
    return _Normalized(
        finding=finding,
        family=family,
        path=path,
        line=line,
        secret_type=secret_type,
        technology=technology,
        package=package,
        advisory_id=advisory_id,
        duplicate_key=duplicate_key,
        fingerprint=f"{family}-{digest}",
    )


def _duplicate_key(
    *,
    family: str,
    finding: Finding,
    path: str,
    line: int | None,
    secret_type: str,
    package: str,
    advisory_id: str,
) -> str:
    rule = finding.rule_id or ""
    component = _safe_token((finding.affected_component or "").lower())
    if family == "secret":
        line_part = str(line) if line is not None else ""
        return f"secret|{rule}|{secret_type}|{path}|{line_part}"
    if family == "cleartext":
        return f"cleartext|config|{component or 'application'}"
    if family == "http_endpoint":
        line_part = str(line) if line is not None else ""
        return f"http_endpoint|{path}|{line_part}"
    if family == "exported":
        return f"exported|{component}"
    if family == "sdk":
        return f"sdk|{_technology_of(finding, package)}"
    if family == "advisory":
        return f"advisory|{advisory_id}|{package or component}"
    return f"{family}|{rule}|{path}|{component}"


def _secret_type(finding: Finding) -> str:
    for item in finding.evidence:
        for key in ("secret_type", "category"):
            value = item.data.get(key)
            if isinstance(value, str) and value and not _SECRETISH.search(value):
                return value.lower()
    if finding.rule_id:
        return finding.rule_id.lower()
    return ""


def _package_of(finding: Finding) -> str:
    for item in finding.evidence:
        value = item.data.get("package")
        if isinstance(value, str) and value and not _SECRETISH.search(value):
            return value
    component = finding.affected_component or ""
    if ":" in component and not _SECRETISH.search(component):
        return component
    return ""


def _advisory_id(finding: Finding) -> str:
    if finding.rule_id and finding.rule_id.startswith("advisory_match:"):
        return finding.rule_id.split(":", 1)[1]
    for item in finding.evidence:
        for key in ("osv_id", "advisory_id"):
            value = item.data.get(key)
            if isinstance(value, str) and value and not _SECRETISH.search(value):
                return value
        cves = item.data.get("cve")
        if isinstance(cves, list) and cves and isinstance(cves[0], str):
            return cves[0]
        if isinstance(cves, str) and cves:
            return cves
    return finding.rule_id or ""


def _technology_of(finding: Finding, package: str) -> str:
    family = family_of(finding)
    if family == "sdk" or finding.rule_id == "sdk_detected":
        return _safe_token((finding.affected_component or finding.title).lower())
    title = finding.title.strip()
    lowered = title.lower()
    if lowered.startswith("vulnerable ") and lowered.endswith(" version"):
        return _safe_token(title[11:-8].strip().lower())
    mapped = _maven_technology(package)
    if mapped:
        return mapped
    if family == "advisory":
        return _safe_token((finding.affected_component or "").lower())
    return _safe_token((finding.affected_component or "").lower())


def _maven_technology(package: str) -> str:
    if not package or ":" not in package:
        return ""
    group, artifact = package.split(":", 1)
    try:
        from app.scanners.tech_signatures import MAVEN_INDEX
    except Exception:  # noqa: BLE001
        return ""
    name = MAVEN_INDEX.get((group, artifact))
    return name.lower() if name else ""


def _safe_token(value: str) -> str:
    if not value or _SECRETISH.search(value):
        return ""
    return value


def _merge_duplicates(items: list[Finding], primary: Finding) -> Finding:
    canonical = primary.model_copy(deep=True)
    sources: list[str] = []
    evidence = []
    seen_ev: set[tuple[str, str, str | None]] = set()
    for item in _stable_members(items, primary):
        for source in item.sources or [item.source]:
            if source not in sources:
                sources.append(source)
        for ev in item.evidence:
            key = (ev.kind, ev.summary, ev.location)
            if key in seen_ev:
                continue
            seen_ev.add(key)
            evidence.append(ev)
    canonical.sources = sources
    canonical.source = sources[0] if sources else canonical.source
    canonical.evidence = evidence
    canonical.severity = reconcile_severity(items)
    canonical.confidence = reconcile_confidence(items)
    if canonical.verification is Verification.INFO and any(
        item.verification is Verification.CONFIRMED for item in items
    ):
        canonical.verification = Verification.CONFIRMED
        canonical.potential = False
    if len(sources) > 1:
        extra = f" Corroborated by: {', '.join(sources)}."
        if extra.strip() not in canonical.description:
            canonical.description = canonical.description.rstrip() + extra
    return canonical


def _stable_members(items: list[Finding], primary: Finding) -> list[Finding]:
    rest = [item for item in items if item.id != primary.id]
    rest.sort(key=lambda item: item.id)
    return [primary, *rest]


def _related_groups(merged: list[_Normalized]) -> list[CorrelatedGroup]:
    groups: list[CorrelatedGroup] = []
    cleartext = [item for item in merged if item.family == "cleartext"]
    http_endpoints = [item for item in merged if item.family == "http_endpoint"]
    if cleartext and http_endpoints:
        primary_record = min(cleartext, key=lambda item: _primary_sort(item.finding))
        originals = _expand_originals([primary_record, *http_endpoints])
        groups.append(
            _group_from(
                relationship=RelationshipType.RELATED,
                fingerprint=_related_fingerprint("cleartext-http", primary_record.fingerprint),
                primary=primary_record.finding,
                members=originals,
                related=[item.finding for item in http_endpoints],
                note="Cleartext configuration related to HTTP endpoint evidence.",
            )
        )

    sdk_by_tech: dict[str, list[_Normalized]] = defaultdict(list)
    advisories: list[_Normalized] = []
    for item in merged:
        if item.family == "sdk" and item.technology:
            sdk_by_tech[item.technology].append(item)
        elif item.family == "advisory" and item.technology:
            advisories.append(item)
    for advisory in advisories:
        supports = sdk_by_tech.get(advisory.technology) or []
        if not supports:
            continue
        originals = _expand_originals([advisory, *supports])
        groups.append(
            _group_from(
                relationship=RelationshipType.SUPPORTING_EVIDENCE,
                fingerprint=_related_fingerprint("advisory-sdk", advisory.fingerprint),
                primary=advisory.finding,
                members=originals,
                related=[item.finding for item in supports],
                note="Technology inventory supports the advisory match; inventory is not a second vulnerability.",
            )
        )
    return groups


def _expand_originals(records: list[_Normalized]) -> list[Finding]:
    seen: set[str] = set()
    originals: list[Finding] = []
    for record in records:
        pool = record.originals or [record.finding]
        for item in pool:
            if item.id in seen:
                continue
            seen.add(item.id)
            originals.append(item)
    return originals


def _related_fingerprint(kind: str, seed: str) -> str:
    digest = hashlib.sha256(f"{kind}|{seed}".encode()).hexdigest()[:16]
    return f"{kind}-{digest}"


def _primary_sort(item: Finding) -> tuple:
    primary = select_primary([item])
    return (
        rank(primary.severity),
        -primary.confidence,
        primary.id,
    )


def _group_from(
    *,
    relationship: RelationshipType,
    fingerprint: str,
    primary: Finding,
    members: list[Finding],
    note: str,
    related: list[Finding] | None = None,
) -> CorrelatedGroup:
    related_items = related or [item for item in members if item.id != primary.id]
    sources: list[str] = []
    for item in members:
        for source in item.sources or [item.source]:
            if source not in sources:
                sources.append(source)
    return CorrelatedGroup(
        fingerprint=fingerprint,
        title=primary.title,
        finding_ids=[item.id for item in members],
        sources=sources,
        canonical_id=primary.id,
        note=note,
        relationship=relationship,
        primary_finding_id=primary.id,
        related_finding_ids=[item.id for item in related_items],
        severity=primary.severity if relationship is not RelationshipType.DUPLICATE else reconcile_severity(members),
        confidence=primary.confidence
        if relationship is not RelationshipType.DUPLICATE
        else reconcile_confidence(members),
    )


def _assign_group_ids(groups: list[CorrelatedGroup]) -> list[CorrelatedGroup]:
    order = {
        RelationshipType.DUPLICATE: 0,
        RelationshipType.RELATED: 1,
        RelationshipType.SUPPORTING_EVIDENCE: 2,
    }
    ordered = sorted(groups, key=lambda item: (order.get(item.relationship, 9), item.fingerprint, item.title))
    for index, group in enumerate(ordered, start=1):
        group.group_id = f"CORR-{index:03d}"
    return ordered
