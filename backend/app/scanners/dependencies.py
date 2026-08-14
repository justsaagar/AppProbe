"""Third-party SDK / library detection. Does not invent CVEs."""

from __future__ import annotations

import json
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.analyzers.findings import normalize_finding
from app.config import Settings, get_settings
from app.models.enums import (
    ArtifactKind,
    FindingCategory,
    Platform,
    Severity,
    Verification,
)
from app.models.finding import Evidence, Finding
from app.models.technology import (
    DependencyScanCoverage,
    TechCategory,
    TechnologyRecord,
)
from app.scanners.base import ScanContext, Scanner
from app.scanners.files import SOURCE_APKTOOL, SOURCE_JADX, extract_printable_strings
from app.scanners.tech_signatures import (
    MAVEN_INDEX,
    PLATFORM_NATIVE_SKIP,
    SIGNATURES,
    TechSignature,
)
from app.utils.paths import UnsafePathError, assert_relative_zip_entry

logger = logging.getLogger(__name__)

SOURCE = "dependency-scanner"
VERSION_RE = re.compile(r"^(?:v)?(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)?)$", re.I)
INVALID_VERSIONS = {"latest", "unknown", "null", "undefined", "none", "snapshot"}
POM_VERSION_RE = re.compile(r"(?im)^version\s*=\s*(\S+)$")
POM_GROUP_RE = re.compile(r"(?im)^groupId\s*=\s*(\S+)$")
POM_ARTIFACT_RE = re.compile(r"(?im)^artifactId\s*=\s*(\S+)$")
BUILDCONFIG_VERSION_RE = re.compile(r"""VERSION(?:_NAME)?\s*=\s*["']([^"']+)["']""")
SMALI_PREFIX_RE = re.compile(r"^smali(?:_classes\d+)?/")
MAX_METADATA_BYTES = 16_384
MAX_DEX_READ_BYTES = 2 * 1024 * 1024
MAX_TREE_PATHS = 20_000


@dataclass
class EvidenceHit:
    source: str
    path: str
    summary: str


@dataclass
class TechMatch:
    signature: TechSignature
    hits: list[EvidenceHit] = field(default_factory=list)
    version: str | None = None
    version_confidence: float = 0.0
    version_evidence: str = ""


class DependencyScanner(Scanner):
    name = "dependency-scanner"
    description = "Detect embedded SDKs and libraries from package paths"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def supports(self, context: ScanContext) -> bool:
        return context.job.platform is Platform.ANDROID

    async def scan(self, context: ScanContext) -> list[Finding]:
        index = _ArtifactIndex()
        try:
            index.ingest_apk(context.artifact_path)
            jadx_dir = context.extras.get("jadx_source_dir")
            if jadx_dir:
                index.ingest_tree(Path(jadx_dir), SOURCE_JADX)
            apktool_dir = context.extras.get("apktool_decoded_dir")
            if apktool_dir:
                index.ingest_tree(Path(apktool_dir), SOURCE_APKTOOL)
        except Exception:
            logger.warning("dependency scanner indexing failed; continuing", exc_info=True)

        matches = _match_signatures(index)
        _apply_versions(index, matches)
        records = [_to_record(match) for match in matches.values()]
        records.sort(key=lambda item: (str(item.category), item.name.lower()))

        coverage = DependencyScanCoverage(
            technologies_detected=len(records),
            versions_identified=sum(1 for item in records if item.version),
            versions_unknown=sum(1 for item in records if not item.version),
            sources=list(index.sources),
        )
        context.extras["technology_inventory"] = records
        context.extras["dependency_scan_coverage"] = coverage
        _persist_inventory(context, records, coverage)

        findings = [_tech_finding(record) for record in records]
        if context.job.artifact_kind in {ArtifactKind.APK, ArtifactKind.AAB}:
            findings.append(_no_cve_notice())
        return findings


class _ArtifactIndex:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.native_libs: list[tuple[str, str]] = []
        self.sources: list[str] = []
        self.metadata: list[tuple[str, str]] = []
        self.dex_haystack = ""

    def _note(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def ingest_apk(self, archive_path: Path) -> None:
        self._note("APK entries")
        try:
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    try:
                        name = assert_relative_zip_entry(info.filename)
                    except UnsafePathError:
                        continue
                    self.paths.append(name)
                    lowered = name.lower().replace("\\", "/")
                    base = Path(lowered).name
                    if lowered.endswith(".so"):
                        self.native_libs.append((name, base))
                    if base == "pom.properties" and 0 < info.file_size <= MAX_METADATA_BYTES:
                        self._read_zip_metadata(archive, info, name)
                    if lowered.endswith(".dex"):
                        self._note("DEX")
                        self._read_zip_dex(archive, info)
        except zipfile.BadZipFile:
            return

    def ingest_tree(self, root: Path, kind: str) -> None:
        if not root.is_dir():
            return
        label = "JADX output" if kind == SOURCE_JADX else "apktool output"
        self._note(label)
        confine = root.resolve()
        count = 0
        for path in root.rglob("*"):
            if count >= MAX_TREE_PATHS:
                break
            if path.is_symlink() or not path.is_file():
                continue
            try:
                path.resolve().relative_to(confine)
                rel = path.relative_to(root).as_posix()
            except (ValueError, OSError):
                continue
            tagged = f"{kind}:{rel}"
            self.paths.append(tagged)
            count += 1
            lowered = rel.lower()
            base = Path(lowered).name
            if lowered.endswith(".so"):
                self.native_libs.append((tagged, base))
            if base in {"pom.properties", "buildconfig.java"}:
                try:
                    size = path.stat().st_size
                    if 0 < size <= MAX_METADATA_BYTES:
                        text = path.read_text(encoding="utf-8", errors="replace")
                        self.metadata.append((tagged, text))
                except OSError:
                    continue

    def _read_zip_metadata(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo, name: str) -> None:
        try:
            data = archive.read(info)
        except Exception:
            return
        self.metadata.append((name, data.decode("utf-8", errors="replace")))

    def _read_zip_dex(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
        try:
            with archive.open(info) as handle:
                blob = handle.read(MAX_DEX_READ_BYTES)
        except Exception:
            return
        extracted = extract_printable_strings(blob, min_len=6, max_strings=4000)
        if extracted:
            self.dex_haystack = f"{self.dex_haystack}\n{extracted}".lower()


def _persist_inventory(
    context: ScanContext,
    records: list[TechnologyRecord],
    coverage: DependencyScanCoverage,
) -> None:
    try:
        (context.workspace.findings_dir / "dependency-scan-coverage.json").write_text(
            coverage.model_dump_json(indent=2), encoding="utf-8"
        )
        (context.workspace.findings_dir / "technology-inventory.json").write_text(
            json.dumps([item.model_dump(mode="json") for item in records], indent=2),
            encoding="utf-8",
        )
    except OSError:
        logger.debug("could not persist dependency coverage", exc_info=True)


def _match_signatures(index: _ArtifactIndex) -> dict[str, TechMatch]:
    matches: dict[str, TechMatch] = {}
    normalized_paths = [(_normalize_code_path(path), path) for path in index.paths]
    for signature in SIGNATURES:
        hits: list[EvidenceHit] = []
        for normalized, original in normalized_paths:
            source = _source_for_path(original)
            if _path_matches_signature(normalized, original, signature):
                hits.append(
                    EvidenceHit(source=source, path=_display_path(original), summary=f"package path: {_untag(original)}")
                )
        for path, base in index.native_libs:
            if base.lower() in PLATFORM_NATIVE_SKIP:
                continue
            if base.lower() in {name.lower() for name in signature.native_libs}:
                hits.append(
                    EvidenceHit(
                        source=_source_for_path(path),
                        path=_display_path(path),
                        summary=f"native library: {base}",
                    )
                )
        if signature.file_names:
            wanted = {name.lower() for name in signature.file_names}
            for original in index.paths:
                base = Path(_untag(original)).name.lower()
                if base in wanted:
                    hits.append(
                        EvidenceHit(
                            source=_source_for_path(original),
                            path=_display_path(original),
                            summary=f"file: {base}",
                        )
                    )
        if signature.flutter_packages:
            for normalized, original in normalized_paths:
                for pkg in signature.flutter_packages:
                    token = f"assets/flutter_assets/packages/{pkg}/"
                    if token in normalized or normalized.rstrip("/").endswith(
                        f"assets/flutter_assets/packages/{pkg}"
                    ):
                        hits.append(
                            EvidenceHit(
                                source=_source_for_path(original),
                                path=_display_path(original),
                                summary=f"Flutter package: {pkg}",
                            )
                        )
        if index.dex_haystack and signature.path_prefixes:
            for prefix in signature.path_prefixes:
                if _dex_contains(index.dex_haystack, prefix):
                    hits.append(
                        EvidenceHit(
                            source="DEX",
                            path="classes.dex",
                            summary=f"DEX descriptor: {prefix.rstrip('/')}",
                        )
                    )
                    break
        if not hits:
            continue
        if signature.name == "Flutter" and not _flutter_evidence_is_strong(hits):
            continue
        matches[signature.name] = TechMatch(signature=signature, hits=_dedupe_hits(hits))
    return matches


def _flutter_evidence_is_strong(hits: list[EvidenceHit]) -> bool:
    blob = " ".join(f"{hit.path} {hit.summary}" for hit in hits).lower()
    return "libflutter.so" in blob or "flutter_assets" in blob or "io/flutter" in blob


def _apply_versions(index: _ArtifactIndex, matches: dict[str, TechMatch]) -> None:
    for path, text in index.metadata:
        group = _first(POM_GROUP_RE, text)
        artifact = _first(POM_ARTIFACT_RE, text)
        parsed = _parse_version(_first(POM_VERSION_RE, text))
        if group and artifact and parsed:
            name = MAVEN_INDEX.get((group, artifact))
            if name and name in matches:
                _set_version(matches[name], parsed, 0.98, path)
        if "buildconfig" in path.lower():
            raw = BUILDCONFIG_VERSION_RE.search(text)
            parsed_bc = _parse_version(raw.group(1) if raw else None)
            if not parsed_bc:
                continue
            normalized = _normalize_code_path(path)
            for match in matches.values():
                if any(
                    normalized.startswith(prefix.rstrip("/") + "/") or prefix.rstrip("/") in normalized
                    for prefix in match.signature.path_prefixes
                ):
                    _set_version(match, parsed_bc, 0.90, path)


def _set_version(match: TechMatch, version: str, confidence: float, path: str) -> None:
    if match.version_confidence >= confidence:
        return
    match.version = version
    match.version_confidence = confidence
    match.version_evidence = _display_path(path)
    match.hits.append(
        EvidenceHit(source="APK entries", path=_display_path(path), summary=f"version metadata: {version}")
    )


def _to_record(match: TechMatch) -> TechnologyRecord:
    sources: list[str] = []
    for hit in match.hits:
        if hit.source not in sources:
            sources.append(hit.source)
    confidence = match.signature.confidence
    if len(sources) > 1:
        confidence = min(0.99, confidence + 0.03)
    evidence = [
        Evidence(
            kind="sdk",
            summary=hit.summary,
            location=hit.path,
            data={"source": hit.source, "path": hit.path},
        )
        for hit in match.hits[:8]
    ]
    if match.version:
        evidence.append(
            Evidence(
                kind="version",
                summary=f"version {match.version}",
                location=match.version_evidence or None,
                data={
                    "version": match.version,
                    "version_confidence": match.version_confidence,
                    "security_assessment": "NOT EVALUATED",
                },
            )
        )
    return TechnologyRecord(
        name=match.signature.name,
        vendor=match.signature.vendor,
        category=match.signature.category,
        version=match.version,
        version_confidence=match.version_confidence if match.version else 0.0,
        detection_source=sources[0] if sources else "APK entries",
        sources=sources,
        confidence=confidence,
        evidence=evidence,
        bundled=match.signature.bundled,
    )


def _tech_finding(record: TechnologyRecord) -> Finding:
    category = record.category.value if isinstance(record.category, TechCategory) else str(record.category)
    title = (
        f"{record.name} framework detected"
        if category == TechCategory.FRAMEWORK.value
        else f"{record.name} detected"
    )
    version_note = (
        f"Version {record.version} (confidence {record.version_confidence:.2f})."
        if record.version
        else "Version: Unknown."
    )
    description = (
        f"{record.name} appears to be embedded in the application. {version_note} "
        "Security assessment: NOT EVALUATED. "
        "Dependency detected; vulnerability version verification not available in this milestone. "
        "Vulnerability database integration is not part of Milestone 2.5. CVEs are not invented."
    )
    return normalize_finding(
        source=SOURCE,
        rule_id="sdk_detected",
        title=title,
        category=FindingCategory.DEPENDENCY,
        severity=Severity.INFO,
        confidence=record.confidence,
        description=description,
        impact="Third-party code expands attack surface; this finding is informational only.",
        recommendation=(
            "Inventory SDKs and keep them updated. This detection is not a vulnerability finding."
        ),
        evidence=record.evidence,
        affected_component=record.name,
        reproducibility="Static package/native/library signature match.",
        verification=Verification.INFO,
    )


def _no_cve_notice() -> Finding:
    return normalize_finding(
        source=SOURCE,
        rule_id="sdk_detected",
        title="Dependency vulnerability assessment: NOT EXECUTED",
        category=FindingCategory.PROCESS,
        severity=Severity.INFO,
        confidence=1.0,
        description=(
            "Dependency vulnerability assessment: NOT EXECUTED. "
            "No vulnerability database is integrated in Milestone 2.5. Detected SDKs are not "
            "classified as vulnerable merely because they are present or appear old. "
            "Dependency detected; vulnerability version verification not available in this milestone. "
            "CVEs are not invented."
        ),
        evidence=[
            Evidence(
                kind="process",
                summary="No CVE/advisory database configured",
            )
        ],
        affected_component="dependencies",
        reproducibility="N/A — pipeline limitation.",
        verification=Verification.INFO,
    )


def _untag(path: str) -> str:
    if path.startswith(f"{SOURCE_JADX}:") or path.startswith(f"{SOURCE_APKTOOL}:"):
        return path.split(":", 1)[1]
    return path


def _display_path(path: str) -> str:
    if path.startswith(f"{SOURCE_JADX}:"):
        return f"tools/jadx/output/{path.split(':', 1)[1]}"
    if path.startswith(f"{SOURCE_APKTOOL}:"):
        return f"tools/apktool/output/{path.split(':', 1)[1]}"
    return path


def _normalize_code_path(path: str) -> str:
    lowered = _untag(path).replace("\\", "/").lstrip("/").lower()
    for prefix in ("tools/jadx/output/", "tools/apktool/output/", "sources/", "java/", "kotlin/"):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
    return SMALI_PREFIX_RE.sub("", lowered)


def _path_matches_signature(normalized: str, original: str, signature: TechSignature) -> bool:
    candidates = (normalized, _untag(original).replace("\\", "/").lower())
    for prefix in signature.path_prefixes:
        token = prefix.replace("\\", "/").lower().rstrip("/")
        if not token:
            continue
        for path in candidates:
            if path == token or path.startswith(token + "/") or path.startswith(token + "."):
                return True
            if f"/{token}/" in f"/{path}/":
                return True
    return False


def _dex_contains(haystack: str, prefix: str) -> bool:
    token = prefix.replace("\\", "/").lower().rstrip("/")
    if len(token) < 5:
        return False
    dotted = token.replace("/", ".")
    return (
        f"l{token}/" in haystack
        or f"{token}/" in haystack
        or f"{dotted}." in haystack
        or f"l{dotted};" in haystack
    )


def _source_for_path(path: str) -> str:
    if path.startswith(f"{SOURCE_JADX}:") or "jadx" in path.lower():
        return "JADX"
    if path.startswith(f"{SOURCE_APKTOOL}:") or path.lower().startswith("smali"):
        return "apktool"
    if path.lower().endswith(".dex"):
        return "DEX"
    return "APK entries"


def _dedupe_hits(hits: list[EvidenceHit]) -> list[EvidenceHit]:
    seen: set[tuple[str, str]] = set()
    unique: list[EvidenceHit] = []
    for hit in hits:
        key = (hit.source, hit.path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)
        if len(unique) >= 12:
            break
    return unique


def _parse_version(value: str | None) -> str | None:
    if not value:
        return None
    stripped = value.strip().strip("\"'")
    if stripped.lower() in INVALID_VERSIONS:
        return None
    match = VERSION_RE.match(stripped)
    if not match:
        return None
    return match.group(1)


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    found = pattern.search(text)
    return found.group(1).strip() if found else None
