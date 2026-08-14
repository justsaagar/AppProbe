"""OSV.dev advisory provider.

Queries only package ecosystem, name, and installed version. Never sends
application source, secrets, or artifacts. Treats OSV JSON as untrusted.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from app.advisories.provider import (
    AdvisoryLookup,
    AdvisoryProviderError,
    PackageQuery,
)
from app.advisories.sanitize import (
    MAX_ALIASES,
    MAX_RANGES,
    MAX_REFERENCES,
    MAX_VERSIONS,
    as_dict,
    as_list,
    sanitize_alias,
    sanitize_id,
    sanitize_package,
    sanitize_text,
    sanitize_url,
    sanitize_version,
)
from app.advisories.severity import normalize_osv_severity
from app.config import Settings, get_settings
from app.models.advisory import Advisory, AdvisoryReference, AffectedRange
from app.utils.http import JsonHttpClient, JsonHttpError

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.osv.dev"
MAX_BATCH = 20


class OSVProvider:
    name = "OSV"

    def __init__(
        self,
        settings: Settings | None = None,
        client: JsonHttpClient | None = None,
        base_url: str | None = None,
        batch_size: int | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.base_url = (base_url or getattr(self.settings, "osv_base_url", DEFAULT_BASE_URL)).rstrip("/")
        self.batch_size = max(1, min(batch_size or getattr(self.settings, "advisory_batch_size", MAX_BATCH), 100))
        self.max_concurrency = max(1, min(max_concurrency or getattr(self.settings, "advisory_max_concurrency", 2), 4))
        self.client = client or JsonHttpClient(
            timeout_seconds=getattr(self.settings, "advisory_timeout_seconds", 20.0),
            connect_timeout_seconds=getattr(self.settings, "advisory_connect_timeout_seconds", 5.0),
            max_response_bytes=getattr(self.settings, "advisory_max_response_bytes", 1_048_576),
            retry_transient=1,
        )
        self._query_cache: dict[str, AdvisoryLookup] = {}
        self._vuln_cache: dict[str, Advisory | AdvisoryProviderError] = {}

    def begin_scan(self) -> None:
        """Drop scan-local caches. Call once per scan."""
        self._query_cache.clear()
        self._vuln_cache.clear()

    async def query(self, package: str, ecosystem: str, version: str) -> list[Advisory]:
        lookup = (await self.query_batch([PackageQuery(ecosystem, package, version)]))[0]
        if lookup.error is not None:
            raise lookup.error
        return lookup.advisories

    async def query_batch(self, queries: Sequence[PackageQuery]) -> list[AdvisoryLookup]:
        results: list[AdvisoryLookup | None] = [None] * len(queries)
        pending_indexes: list[int] = []
        pending_queries: list[PackageQuery] = []
        for index, query in enumerate(queries):
            cached = self._query_cache.get(query.cache_key)
            if cached is not None:
                results[index] = AdvisoryLookup(
                    query=query,
                    advisories=list(cached.advisories),
                    error=cached.error,
                )
            else:
                pending_indexes.append(index)
                pending_queries.append(query)

        for start in range(0, len(pending_queries), self.batch_size):
            chunk = pending_queries[start : start + self.batch_size]
            chunk_indexes = pending_indexes[start : start + self.batch_size]
            chunk_results = await self._query_chunk(chunk)
            for index, lookup in zip(chunk_indexes, chunk_results, strict=True):
                self._query_cache[lookup.query.cache_key] = lookup
                results[index] = lookup

        return [item if item is not None else AdvisoryLookup(query=queries[i]) for i, item in enumerate(results)]

    async def _query_chunk(self, queries: list[PackageQuery]) -> list[AdvisoryLookup]:
        payload = {
            "queries": [
                {
                    "package": {"name": item.package, "ecosystem": item.ecosystem},
                    "version": item.version,
                }
                for item in queries
            ]
        }
        try:
            body = await self.client.post_json(f"{self.base_url}/v1/querybatch", payload)
        except JsonHttpError as exc:
            error = _to_provider_error(exc)
            return [AdvisoryLookup(query=item, error=error) for item in queries]

        if not isinstance(body, dict):
            error = AdvisoryProviderError("invalid_response", "OSV batch response was not an object")
            return [AdvisoryLookup(query=item, error=error) for item in queries]

        rows = as_list(body.get("results"))
        if len(rows) != len(queries):
            error = AdvisoryProviderError(
                "invalid_response",
                f"OSV batch result count {len(rows)} did not match query count {len(queries)}",
            )
            return [AdvisoryLookup(query=item, error=error) for item in queries]

        lookups: list[AdvisoryLookup] = []
        for query, row in zip(queries, rows, strict=True):
            lookups.append(await self._lookup_from_batch_row(query, row))
        return lookups

    async def _lookup_from_batch_row(self, query: PackageQuery, row: Any) -> AdvisoryLookup:
        if not isinstance(row, dict):
            return AdvisoryLookup(
                query=query,
                error=AdvisoryProviderError("invalid_response", "OSV batch row was not an object"),
            )
        ids: list[str] = []
        for item in as_list(row.get("vulns")):
            ident = None
            if isinstance(item, dict):
                ident = sanitize_id(item.get("id"))
            elif isinstance(item, str):
                ident = sanitize_id(item)
            if ident:
                ids.append(ident)
        # Preserve order, drop duplicates.
        unique_ids = list(dict.fromkeys(ids))
        try:
            advisories = await self._fetch_advisories(unique_ids, query)
        except AdvisoryProviderError as exc:
            return AdvisoryLookup(query=query, error=exc)
        return AdvisoryLookup(query=query, advisories=advisories)

    async def _fetch_advisories(self, ids: list[str], query: PackageQuery) -> list[Advisory]:
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _one(ident: str) -> Advisory | AdvisoryProviderError:
            cached = self._vuln_cache.get(ident)
            if cached is not None:
                return cached
            async with semaphore:
                try:
                    advisory = await self._fetch_vuln(ident, query)
                except AdvisoryProviderError as exc:
                    self._vuln_cache[ident] = exc
                    return exc
                self._vuln_cache[ident] = advisory
                return advisory

        fetched = await asyncio.gather(*[_one(ident) for ident in ids])
        advisories: list[Advisory] = []
        first_error: AdvisoryProviderError | None = None
        for item in fetched:
            if isinstance(item, AdvisoryProviderError):
                first_error = first_error or item
                continue
            advisories.append(item)
        if first_error is not None and not advisories:
            raise first_error
        if first_error is not None:
            # Partial vuln fetch failure: do not treat remaining IDs as clean.
            raise AdvisoryProviderError(
                first_error.kind,
                f"Partial OSV vulnerability fetch failure: {first_error.message}",
            )
        return advisories

    async def _fetch_vuln(self, ident: str, query: PackageQuery) -> Advisory:
        url = f"{self.base_url}/v1/vulns/{quote(ident, safe='')}"
        try:
            payload = await self.client.get_json(url)
        except JsonHttpError as exc:
            raise _to_provider_error(exc) from exc
        parsed = parse_osv_vulnerability(payload, query)
        if parsed is None:
            raise AdvisoryProviderError("invalid_response", f"OSV vulnerability {ident} could not be parsed safely")
        return parsed


def parse_osv_vulnerability(payload: Any, query: PackageQuery) -> Advisory | None:
    data = as_dict(payload)
    if data is None:
        return None
    ident = sanitize_id(data.get("id"))
    if ident is None:
        return None

    aliases: list[str] = []
    for item in as_list(data.get("aliases")):
        alias = sanitize_alias(item)
        if alias and alias not in aliases and alias != ident:
            aliases.append(alias)
        if len(aliases) >= MAX_ALIASES:
            break
    if sanitize_alias(ident) and ident not in aliases:
        # Keep GHSA/CVE identifiers in alias lists when the primary id is one of them.
        pass

    ranges: list[AffectedRange] = []
    versions: list[str] = []
    package_name = query.package
    ecosystem = query.ecosystem
    for affected in as_list(data.get("affected")):
        entry = as_dict(affected)
        if entry is None:
            continue
        pkg = as_dict(entry.get("package")) or {}
        name = sanitize_package(pkg.get("name"))
        eco = sanitize_text(pkg.get("ecosystem"), limit=32)
        if name != query.package or eco != query.ecosystem:
            continue
        package_name = name
        ecosystem = eco
        for raw_range in as_list(entry.get("ranges")):
            parsed_range = _parse_range(raw_range)
            if parsed_range is not None:
                ranges.append(parsed_range)
            if len(ranges) >= MAX_RANGES:
                break
        for raw_version in as_list(entry.get("versions")):
            version = sanitize_version(raw_version)
            if version and version not in versions:
                versions.append(version)
            if len(versions) >= MAX_VERSIONS:
                break

    references: list[AdvisoryReference] = []
    for raw in as_list(data.get("references")):
        item = as_dict(raw)
        if item is None:
            continue
        url = sanitize_url(item.get("url"))
        if url is None:
            continue
        ref_type = sanitize_text(item.get("type"), limit=32)
        references.append(AdvisoryReference(type=ref_type, url=url))
        if len(references) >= MAX_REFERENCES:
            break

    severity, cvss_score, cvss_vector = normalize_osv_severity(data)
    published = sanitize_text(data.get("published"), limit=64) or None
    modified = sanitize_text(data.get("modified"), limit=64) or None
    return Advisory(
        id=ident,
        aliases=aliases,
        summary=sanitize_text(data.get("summary")),
        details=sanitize_text(data.get("details"), limit=2000),
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        affected_package=package_name,
        affected_ecosystem=ecosystem,
        affected_ranges=ranges,
        affected_versions=versions,
        references=references,
        published=published,
        modified=modified,
        source="OSV",
    )


def _parse_range(raw: Any) -> AffectedRange | None:
    data = as_dict(raw)
    if data is None:
        return None
    rtype = sanitize_text(data.get("type"), limit=16).upper()
    if rtype not in {"ECOSYSTEM", "SEMVER", "GIT"}:
        return None
    introduced = "0"
    fixed = None
    last_affected = None
    limit = None
    for event in as_list(data.get("events")):
        item = as_dict(event)
        if item is None:
            continue
        if "introduced" in item:
            introduced = sanitize_version(item.get("introduced")) or "0"
        if "fixed" in item:
            fixed = sanitize_version(item.get("fixed"))
        if "last_affected" in item:
            last_affected = sanitize_version(item.get("last_affected"))
        if "limit" in item:
            limit = sanitize_version(item.get("limit"))
    return AffectedRange(
        type=rtype,
        introduced=introduced,
        fixed=fixed,
        last_affected=last_affected,
        limit=limit,
    )


def _to_provider_error(exc: JsonHttpError) -> AdvisoryProviderError:
    kind = exc.kind
    if kind == "timeout":
        kind = "timeout"
    elif kind == "rate_limited":
        kind = "rate_limited"
    elif kind in {"unavailable", "too_large"}:
        kind = "unavailable" if kind == "unavailable" else "invalid_response"
    elif kind == "invalid_response":
        kind = "invalid_response"
    else:
        kind = "http_error"
    return AdvisoryProviderError(kind, exc.message)
