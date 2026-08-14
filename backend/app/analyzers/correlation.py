"""Deterministic finding correlation. AI-assisted merging belongs to Milestone 6."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.finding import Finding


@dataclass
class FindingGroup:
    id: str
    title: str
    relationship: str
    finding_ids: list[str] = field(default_factory=list)
    root_cause: str | None = None


def correlate_findings(findings: list[Finding]) -> tuple[list[Finding], list[FindingGroup]]:
    """Merge exact duplicates and group related exported-component / cleartext issues."""
    merged = _merge_duplicates(findings)
    groups: list[FindingGroup] = []

    exported = [item for item in merged if (item.rule_id or "").startswith("ANDROID_EXPORTED_")]
    if len(exported) >= 2:
        groups.append(
            FindingGroup(
                id="group-exported-components",
                title="Exported Android components",
                relationship="related",
                finding_ids=[item.id for item in exported],
                root_cause=(
                    "Multiple components are exported and may enlarge the app's attack surface."
                    " Review whether each export is required and whether it is permission-protected."
                ),
            )
        )

    cleartext = [item for item in merged if item.rule_id == "ANDROID_CLEARTEXT_TRAFFIC"]
    if cleartext:
        groups.append(
            FindingGroup(
                id="group-cleartext",
                title="Cleartext network traffic configuration",
                relationship="related",
                finding_ids=[item.id for item in cleartext],
                root_cause=(
                    "usesCleartextTraffic enables HTTP. Related HTTP endpoint findings, when present,"
                    " should be treated as one communication-security issue rather than isolated alerts."
                ),
            )
        )
    return merged, groups


def _merge_duplicates(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str | None, str, str | None], Finding] = {}
    extras: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.title, finding.affected_component)
        if finding.rule_id is None:
            extras.append(finding)
            continue
        existing = unique.get(key)
        if existing is None:
            unique[key] = finding
            continue
        existing.evidence.extend(finding.evidence)
        existing.confidence = max(existing.confidence, finding.confidence)
        if finding.description and finding.description not in existing.description:
            existing.description = existing.description + " " + finding.description
    return list(unique.values()) + extras
