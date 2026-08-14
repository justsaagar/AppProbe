"""Vulnerability / advisory scanner.

Consumes the Milestone 2.5 technology inventory and matches known advisories
via an AdvisoryProvider (OSV by default). Advisory matching only — no
exploit validation, credential checks, or runtime interaction.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.advisories.mapping import MappedPackage, map_technology
from app.advisories.matching import match_advisory
from app.advisories.osv import OSVProvider
from app.advisories.provider import (
    AdvisoryLookup,
    AdvisoryProvider,
    AdvisoryProviderError,
    PackageQuery,
)
from app.advisories.severity import to_finding_severity
from app.analyzers.findings import normalize_finding
from app.config import Settings, get_settings
from app.models.advisory import (
    Advisory,
    PackageSkip,
    VulnerabilityAssessment,
)
from app.models.enums import FindingCategory, Platform, Severity, Verification
from app.models.finding import Evidence, Finding
from app.models.technology import TechnologyRecord
from app.scanners.base import ScanContext, Scanner

logger = logging.getLogger(__name__)

SOURCE = "vulnerability-scanner"
CONFIRMED_CONFIDENCE = 0.99


class VulnerabilityScanner(Scanner):
    name = "vulnerability-scanner"
    description = "Match detected dependency versions against advisory providers"

    def __init__(
        self,
        settings: Settings | None = None,
        provider: AdvisoryProvider | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.provider = provider or OSVProvider(self.settings)
        self._scan_cache: dict[str, AdvisoryLookup] = {}

    def supports(self, context: ScanContext) -> bool:
        return context.job.platform is Platform.ANDROID

    async def scan(self, context: ScanContext) -> list[Finding]:
        self._scan_cache.clear()
        begin = getattr(self.provider, "begin_scan", None)
        if callable(begin):
            begin()

        inventory = _inventory(context)
        source_name = getattr(self.provider, "name", "OSV") or "OSV"

        if not getattr(self.settings, "advisory_network_enabled", True):
            assessment = VulnerabilityAssessment(
                status="NOT_AVAILABLE",
                advisory_source=source_name,
                reason="Advisory provider network access is disabled.",
                packages_not_evaluated=len(inventory),
                skipped=[
                    PackageSkip(technology=item.name, reason="Advisory provider network access is disabled.", version=item.version)
                    for item in inventory
                ],
            )
            return _finish(context, assessment, [_status_finding(assessment)])

        mapped = [map_technology(record) for record in inventory]
        skipped = [item for item in mapped if item.query is None]
        eligible = [item for item in mapped if item.query is not None]

        try:
            lookups = await self._lookup_all([item.query for item in eligible if item.query is not None])
        except AdvisoryProviderError as exc:
            assessment = _failed_assessment(source_name, exc, inventory, skipped)
            return _finish(context, assessment, [_status_finding(assessment)])

        findings: list[Finding] = []
        vulnerable_keys: set[str] = set()
        no_advisory = 0
        evaluated = 0
        extra_skips: list[MappedPackage] = []
        provider_failed = False
        provider_error: AdvisoryProviderError | None = None

        lookup_by_key = {item.query.cache_key: item for item in lookups}

        for item in eligible:
            query = item.query
            assert query is not None
            lookup = lookup_by_key.get(query.cache_key)
            if lookup is None or lookup.error is not None:
                provider_failed = True
                provider_error = (lookup.error if lookup is not None else None) or provider_error
                extra_skips.append(
                    MappedPackage(
                        item.technology,
                        None,
                        "Advisory provider unavailable.",
                        identity=item.identity,
                    )
                )
                continue
            evaluated += 1
            record = _record_for(inventory, item.technology)
            matched, unknown = _advisories_for_version(lookup.advisories, query)
            if unknown and not matched:
                extra_skips.append(
                    MappedPackage(
                        item.technology,
                        None,
                        "Advisory data could not be interpreted safely.",
                        identity=item.identity,
                    )
                )
                evaluated -= 1
                continue
            if not matched:
                no_advisory += 1
                continue
            vulnerable_keys.add(query.cache_key)
            for advisory in matched:
                findings.append(_vuln_finding(item, query, advisory, record))

        skip_models = [_to_skip(item) for item in skipped + extra_skips]
        if provider_failed:
            reason = (
                provider_error.message
                if provider_error is not None
                else "Advisory provider unavailable."
            )
            assessment = VulnerabilityAssessment(
                status="INCOMPLETE",
                advisory_source=source_name,
                reason=reason,
                packages_evaluated=evaluated,
                vulnerable_packages=len(vulnerable_keys),
                packages_no_advisories=no_advisory,
                packages_not_evaluated=len(skip_models),
                vulnerability_findings=len(findings),
                skipped=skip_models,
                provider_error=provider_error.kind if provider_error else "unavailable",
            )
            findings.insert(0, _status_finding(assessment))
            return _finish(context, assessment, findings)

        assessment = VulnerabilityAssessment(
            status="COMPLETE",
            advisory_source=source_name,
            reason="",
            packages_evaluated=evaluated,
            vulnerable_packages=len(vulnerable_keys),
            packages_no_advisories=no_advisory,
            packages_not_evaluated=len(skip_models),
            vulnerability_findings=len(findings),
            skipped=skip_models,
        )
        return _finish(context, assessment, findings)

    async def _lookup_all(self, queries: Sequence[PackageQuery]) -> list[AdvisoryLookup]:
        unique: list[PackageQuery] = []
        seen: set[str] = set()
        for query in queries:
            if query.cache_key in seen:
                continue
            seen.add(query.cache_key)
            unique.append(query)

        pending: list[PackageQuery] = []
        for query in unique:
            if query.cache_key not in self._scan_cache:
                pending.append(query)

        if pending:
            batch = getattr(self.provider, "query_batch", None)
            if callable(batch):
                fetched = await batch(pending)
            else:
                fetched = []
                for query in pending:
                    try:
                        advisories = await self.provider.query(query.package, query.ecosystem, query.version)
                        fetched.append(AdvisoryLookup(query=query, advisories=advisories))
                    except AdvisoryProviderError as exc:
                        fetched.append(AdvisoryLookup(query=query, error=exc))
                    except Exception as exc:  # noqa: BLE001 — provider bugs must not crash the scan
                        fetched.append(
                            AdvisoryLookup(
                                query=query,
                                error=AdvisoryProviderError("unavailable", str(exc)),
                            )
                        )
            if len(fetched) != len(pending):
                raise AdvisoryProviderError("invalid_response", "Advisory provider returned a mismatched batch")
            for lookup in fetched:
                self._scan_cache[lookup.query.cache_key] = lookup

        # If every unique query failed with the same outage, surface it.
        results = [self._scan_cache[query.cache_key] for query in unique]
        if results and all(item.error is not None for item in results):
            raise results[0].error or AdvisoryProviderError("unavailable", "Advisory provider unavailable.")
        return results


def _inventory(context: ScanContext) -> list[TechnologyRecord]:
    payload = context.extras.get("technology_inventory")
    if payload is None:
        payload = context.job.technology_inventory
    records: list[TechnologyRecord] = []
    for item in payload or []:
        if isinstance(item, TechnologyRecord):
            records.append(item)
        elif isinstance(item, dict):
            try:
                records.append(TechnologyRecord.model_validate(item))
            except Exception:  # noqa: BLE001
                continue
    return records


def _record_for(inventory: list[TechnologyRecord], name: str) -> TechnologyRecord | None:
    for item in inventory:
        if item.name == name:
            return item
    return None


def _advisories_for_version(advisories: list[Advisory], query: PackageQuery) -> tuple[list[Advisory], bool]:
    matched: list[Advisory] = []
    unknown = False
    for advisory in advisories:
        status = match_advisory(query.version, advisory, ecosystem=query.ecosystem)
        if status == "affected":
            matched.append(advisory)
        elif status == "unknown":
            unknown = True
    return matched, unknown


def _to_skip(item: MappedPackage) -> PackageSkip:
    return PackageSkip(
        technology=item.technology,
        reason=item.skip_reason or "Not evaluated.",
        version=item.query.version if item.query else None,
    )


def _failed_assessment(
    source_name: str,
    exc: AdvisoryProviderError,
    inventory: list[TechnologyRecord],
    skipped: list[MappedPackage],
) -> VulnerabilityAssessment:
    del skipped
    if exc.kind == "unavailable":
        status_value = "NOT_AVAILABLE"
        reason = "Advisory provider could not be reached."
    elif exc.kind == "rate_limited":
        status_value = "INCOMPLETE"
        reason = "Advisory provider rate-limited the scan."
    else:
        status_value = "INCOMPLETE"
        reason = "Advisory provider unavailable."
    return VulnerabilityAssessment(
        status=status_value,
        advisory_source=source_name,
        reason=reason,
        packages_evaluated=0,
        packages_not_evaluated=len(inventory),
        skipped=_skip_all(inventory, reason),
        provider_error=exc.kind,
    )


def _skip_all(inventory: list[TechnologyRecord], reason: str) -> list[PackageSkip]:
    return [PackageSkip(technology=item.name, reason=reason, version=item.version) for item in inventory]


def _finish(context: ScanContext, assessment: VulnerabilityAssessment, findings: list[Finding]) -> list[Finding]:
    context.extras["vulnerability_assessment"] = assessment
    try:
        (context.workspace.findings_dir / "vulnerability-assessment.json").write_text(
            assessment.model_dump_json(indent=2),
            encoding="utf-8",
        )
    except OSError:
        logger.debug("could not persist vulnerability assessment", exc_info=True)
    return findings


def _status_finding(assessment: VulnerabilityAssessment) -> Finding:
    title = f"Dependency vulnerability assessment: {assessment.status}"
    description = (
        f"Dependency vulnerability assessment: {assessment.status}. "
        f"Advisory source: {assessment.advisory_source}. "
        f"{assessment.reason} ".strip()
        + " A failed advisory lookup does NOT mean that the dependency is safe. "
        "Vulnerability status: NOT DETERMINED."
    )
    return normalize_finding(
        source=SOURCE,
        rule_id="advisory_assessment",
        title=title,
        category=FindingCategory.PROCESS,
        severity=Severity.INFO,
        confidence=1.0,
        description=description,
        recommendation="Retry the scan when the advisory provider is reachable. Do not treat this result as a clean bill of health.",
        evidence=[
            Evidence(
                kind="process",
                summary=assessment.reason or assessment.status,
                data={
                    "status": assessment.status,
                    "advisory_source": assessment.advisory_source,
                    "packages_evaluated": assessment.packages_evaluated,
                },
            )
        ],
        affected_component="dependencies",
        reproducibility="N/A — advisory provider coverage.",
        verification=Verification.INFO,
    )


def _vuln_finding(
    mapped: MappedPackage,
    query: PackageQuery,
    advisory: Advisory,
    record: TechnologyRecord | None,
) -> Finding:
    cves = advisory.cve_ids
    ghsas = advisory.ghsa_ids
    if advisory.id.upper().startswith("GHSA-") and advisory.id not in ghsas:
        ghsas = [advisory.id, *ghsas]
    if advisory.id.upper().startswith("CVE-") and advisory.id not in cves:
        cves = [advisory.id, *cves]
    range_text = advisory.range_display()
    tech = mapped.technology
    title = f"Vulnerable {tech} version"
    cve_text = ", ".join(cves) if cves else "none listed"
    ghsa_text = ", ".join(ghsas) if ghsas else "none listed"
    description = (
        f"OSV: {advisory.id}. "
        f"CVE: {cve_text}. "
        f"GHSA: {ghsa_text}. "
        f"Package: {query.package}. "
        f"Installed: {query.version}. "
        f"Affected: {range_text}. "
        f"Advisory severity: {advisory.severity.value}. "
        f"Source: {advisory.source}."
    )
    if advisory.summary:
        description += f" {advisory.summary}"
    recommendation = _recommendation(query, advisory)
    version_source = ""
    if record is not None:
        for item in record.evidence:
            if item.kind == "version":
                version_source = item.location or item.summary
                break
    evidence = [
        Evidence(
            kind="advisory",
            summary=f"{advisory.id} affects {query.package} {query.version}",
            data={
                "osv_id": advisory.id,
                "cve": cves,
                "ghsa": ghsas,
                "package": query.package,
                "ecosystem": query.ecosystem,
                "installed_version": query.version,
                "affected_range": range_text,
                "advisory_severity": advisory.severity.value,
                "source": advisory.source,
                "references": [item.url for item in advisory.references],
            },
        ),
        Evidence(
            kind="verification",
            summary=(
                f"package_identity: {mapped.identity}; "
                f"installed_version: {query.version}; "
                f"advisory_source: {advisory.source}; "
                f"affected_range: {range_text}; "
                f"version_match: true"
            ),
            location=version_source or None,
            data={
                "package_identity": mapped.identity,
                "installed_version": query.version,
                "advisory_source": advisory.source,
                "affected_range": range_text,
                "version_match": True,
                "version_source": version_source,
            },
        ),
    ]
    if record is not None:
        for item in record.evidence[:4]:
            evidence.append(item)
    return normalize_finding(
        source=SOURCE,
        rule_id=f"advisory_match:{advisory.id}",
        title=title,
        category=FindingCategory.DEPENDENCY,
        severity=to_finding_severity(advisory.severity),
        confidence=CONFIRMED_CONFIDENCE if mapped.identity == "exact" else 0.5,
        description=description,
        impact="The installed dependency version is in an affected range published by the advisory source.",
        recommendation=recommendation,
        evidence=evidence,
        affected_component=query.package,
        reproducibility=(
            "Advisory matching only. package_identity=exact; "
            f"installed_version={query.version}; advisory_source={advisory.source}; "
            f"affected_range={range_text}; version_match=true. "
            "This is not an exploitability test."
        ),
        verification=Verification.CONFIRMED,
    )


def _recommendation(query: PackageQuery, advisory: Advisory) -> str:
    fixed = advisory.preferred_fixed_version()
    if fixed:
        return f"Upgrade {query.package} to >= {fixed}."
    return (
        f"Upgrade {query.package} to a version that is not affected by the advisory. "
        "Review the vendor advisory for the recommended remediation."
    )
