"""Deterministic finding correlation and deduplication."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from app.analyzers.severity import rank
from app.models.enums import FindingCategory, Verification
from app.models.finding import Finding
from app.models.scan_job import CorrelatedGroup

_FAMILY = {
    "cleartext_traffic": "cleartext",
    "network_security_config_missing": "cleartext",
    "http_endpoint": "cleartext",
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
}

_TITLE_HINTS = (
    ("cleartext", "cleartext"),
    ("clear text", "cleartext"),
    ("usesCleartextTraffic", "cleartext"),
    ("debuggable", "debuggable"),
    ("allowbackup", "backup"),
    ("allow backup", "backup"),
    ("exported", "exported"),
)


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
        return "sdk"
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    return slug or "other"


def fingerprint_for(finding: Finding) -> str:
    family = family_of(finding)
    if family == "secret":
        location = ""
        if finding.evidence:
            location = finding.evidence[0].location or ""
        material = "|".join(
            [
                family,
                finding.rule_id or "",
                (finding.affected_component or location).lower(),
                re.sub(r"[^a-z0-9]+", "", finding.title.lower()),
            ]
        )
    elif family == "cleartext":
        material = "cleartext|application"
    elif family == "sdk":
        component = (finding.affected_component or finding.title).lower()
        material = f"sdk|{component}"
    elif family == "advisory":
        material = f"advisory|{finding.rule_id}|{(finding.affected_component or '').lower()}"
    elif family == "exported":
        material = f"exported|{(finding.affected_component or '').lower()}"
    else:
        material = "|".join(
            [
                family,
                (finding.affected_component or "").lower(),
                re.sub(r"[^a-z0-9]+", "", finding.title.lower())[:40],
            ]
        )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{family}-{digest}"


def correlate_findings(findings: list[Finding]) -> tuple[list[Finding], list[CorrelatedGroup]]:
    """Merge duplicates, keep evidence and sources, return canonical findings plus groups."""
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        finding.fingerprint = fingerprint_for(finding)
        buckets[finding.fingerprint].append(finding)

    merged: list[Finding] = []
    groups: list[CorrelatedGroup] = []
    for fingerprint, items in buckets.items():
        canonical = _merge_group(items)
        merged.append(canonical)
        if len(items) > 1:
            groups.append(
                CorrelatedGroup(
                    fingerprint=fingerprint,
                    title=canonical.title,
                    finding_ids=[item.id for item in items],
                    sources=canonical.sources,
                    canonical_id=canonical.id,
                    note=(
                        f"Merged {len(items)} related findings from "
                        + ", ".join(canonical.sources)
                    ),
                )
            )
    merged.sort(key=lambda item: (rank(item.severity), item.title))
    return merged, groups


def _merge_group(items: list[Finding]) -> Finding:
    if len(items) == 1:
        item = items[0]
        if not item.sources:
            item.sources = [item.source]
        return item
    items_sorted = sorted(
        items,
        key=lambda item: (
            0 if item.verification is Verification.CONFIRMED else 1,
            rank(item.severity),
            -item.confidence,
            0 if item.source == "manifest-scanner" else 1,
        ),
    )
    canonical = items_sorted[0].model_copy(deep=True)
    sources: list[str] = []
    evidence = []
    seen_ev = set()
    for item in items_sorted:
        for source in item.sources or [item.source]:
            if source not in sources:
                sources.append(source)
        for ev in item.evidence:
            key = (ev.kind, ev.summary, ev.location)
            if key in seen_ev:
                continue
            seen_ev.add(key)
            evidence.append(ev)
        canonical.confidence = max(canonical.confidence, item.confidence)
        if rank(item.severity) < rank(canonical.severity) and not item.potential:
            canonical.severity = item.severity
    canonical.sources = sources
    canonical.source = sources[0]
    canonical.evidence = evidence
    if len(sources) > 1:
        extra = f" Corroborated by: {', '.join(sources)}."
        if extra.strip() not in canonical.description:
            canonical.description = canonical.description.rstrip() + extra
    return canonical
