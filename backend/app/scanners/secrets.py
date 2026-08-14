"""Deterministic secret and sensitive-string detector.

Performs local analysis only. It does not validate credentials against
external services, does not attempt to use or exploit discovered values,
and does not invoke an LLM.
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass
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
from app.scanners.base import ScanContext, Scanner
from app.scanners.files import (
    SOURCE_APKTOOL,
    SOURCE_JADX,
    SOURCE_RAW_APK,
    FileRecord,
    SecretFileCollector,
    SecretScanLimits,
)
from app.utils.redact import redact_private_key, redact_secret

logger = logging.getLogger(__name__)

SOURCE = "secret-scanner"

PLACEHOLDER_RE = re.compile(
    r"(placeholder|changeme|your[-_]?api[-_]?key|your[-_]?password|your[-_]?token|"
    r"example|sample|xxxx+|todo|for[_-]?testing|fake[_-]?api[_-]?key|"
    r"insert[_-]?key|dummy|xxx-xxx|redacted)",
    re.I,
)
INTERPOLATION_RE = re.compile(
    r"^(\$\{[^}]+\}$|<[A-Z][A-Z0-9_]+>$|process\.env\.)"
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
HEX_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
PACKAGE_RE = re.compile(r"^(com|org|net|io|android)\.[A-Za-z0-9_.]+$")
VERSION_RE = re.compile(r"^v?\d+(\.\d+){1,4}(-[A-Za-z0-9.]+)?$")
AUTH_CONTEXT_RE = re.compile(
    r"(?i)(authorization|bearer|\bjwt\b|id[_-]?token|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|(?<![A-Za-z])token(?![A-Za-z]))"
)
WEAK_VALUES = {
    "password",
    "password123",
    "passw0rd",
    "admin",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "letmein",
    "secret",
    "changeme",
    "example",
    "test",
    "example_password",
    "test_password",
    "your_password",
    "pwd",
    "pass",
    "admin123",
    "root",
    "guest",
    "default",
}

FIREBASE_PUBLIC_HINTS = (
    "google-services.json",
    "google_app_id",
    "gcm_defaultsenderid",
    "mobilesdk_app_id",
    "project_id",
    "storage_bucket",
    "firebase_url",
    "current_key",
)

HTTP_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+")
PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.+?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.S,
)
PASSWORD_ASSIGN_RE = re.compile(
    r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"']([^\"']{6,})[\"']"
)
APIKEY_ASSIGN_RE = re.compile(
    r"(?i)(api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|secret)"
    r"\s*[=:]\s*[\"']([^\"']{8,})[\"']"
)


@dataclass(frozen=True)
class SecretPattern:
    secret_type: str
    rule_id: str
    regex: re.Pattern[str]
    min_length: int
    confidence: float
    severity: Severity
    verification: Verification
    reason: str


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "stripe_key",
        "hardcoded_secret",
        re.compile(r"(?:sk_live_|rk_live_)[A-Za-z0-9]{16,}"),
        24,
        0.97,
        Severity.CRITICAL,
        Verification.CONFIRMED,
        "Stripe live secret/restricted key prefix",
    ),
    SecretPattern(
        "stripe_test_key",
        "hardcoded_secret",
        re.compile(r"(?:sk_test_|rk_test_)[A-Za-z0-9]{16,}"),
        24,
        0.90,
        Severity.HIGH,
        Verification.CONFIRMED,
        "Stripe test secret key prefix",
    ),
    SecretPattern(
        "aws_access_key",
        "cloud_credential",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        20,
        0.95,
        Severity.CRITICAL,
        Verification.CONFIRMED,
        "AWS access key ID prefix AKIA",
    ),
    SecretPattern(
        "github_token",
        "hardcoded_secret",
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        24,
        0.95,
        Severity.HIGH,
        Verification.CONFIRMED,
        "GitHub personal access token prefix",
    ),
    SecretPattern(
        "slack_token",
        "hardcoded_secret",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        20,
        0.90,
        Severity.HIGH,
        Verification.CONFIRMED,
        "Slack token prefix",
    ),
    SecretPattern(
        "openai_api_key",
        "hardcoded_secret",
        re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
        23,
        0.93,
        Severity.HIGH,
        Verification.CONFIRMED,
        "OpenAI API key prefix",
    ),
    SecretPattern(
        "azure_credential",
        "cloud_credential",
        re.compile(
            r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]{3,};AccountKey=[^;\s\"']{16,}"
        ),
        40,
        0.95,
        Severity.CRITICAL,
        Verification.CONFIRMED,
        "Azure storage connection string with AccountKey",
    ),
    SecretPattern(
        "google_api_key",
        "hardcoded_secret",
        re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
        24,
        0.50,
        Severity.INFO,
        Verification.INFO,
        "Google API client key prefix; public client identifier",
    ),
    SecretPattern(
        "jwt",
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        40,
        0.70,
        Severity.HIGH,
        Verification.POTENTIAL,
        "JWT compact serialization (three base64url segments)",
    ),
    SecretPattern(
        "bearer_token",
        "hardcoded_secret",
        re.compile(r"(?i)(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9\-._~+/]+=*"),
        20,
        0.80,
        Severity.HIGH,
        Verification.POTENTIAL,
        "Bearer token assignment",
    ),
    SecretPattern(
        "database_url",
        "hardcoded_secret",
        re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|amqps)://"
            r"[^\s\"'/:]+\:[^\s\"'/@]+@[^\s\"']+"
        ),
        16,
        0.90,
        Severity.HIGH,
        Verification.CONFIRMED,
        "Database connection URL containing username and password",
    ),
)

TITLES = {
    "private_key": "Embedded Private Key",
    "stripe_key": "Embedded Stripe Secret Key",
    "stripe_test_key": "Embedded Stripe Test Secret Key",
    "aws_access_key": "Embedded AWS Access Key",
    "github_token": "Embedded GitHub Token",
    "slack_token": "Embedded Slack Token",
    "openai_api_key": "Embedded OpenAI API Key",
    "azure_credential": "Embedded Azure Credential",
    "google_api_key": "Google client API key",
    "jwt": "Embedded JWT",
    "bearer_token": "Embedded Bearer Token",
    "database_url": "Embedded Database Credential",
    "password": "Hardcoded Password",
    "generic_api_key": "Embedded API Key",
}

RECOMMENDATIONS = {
    "private_key": (
        "Remove the private key from the application and rotate the exposed "
        "credential if it is real."
    ),
    "stripe_key": (
        "Move the credential to a trusted backend and rotate it if it has been "
        "used outside testing."
    ),
    "stripe_test_key": (
        "Move the credential to a trusted backend and rotate it if it has been "
        "used outside testing."
    ),
    "aws_access_key": (
        "Remove cloud credentials from the mobile application and rotate them "
        "in the cloud provider console if they are real."
    ),
    "github_token": (
        "Move the credential to a trusted backend and rotate it if it has been "
        "used outside testing."
    ),
    "slack_token": (
        "Move the credential to a trusted backend and rotate it if it has been "
        "used outside testing."
    ),
    "openai_api_key": (
        "Move the credential to a trusted backend and rotate it if it has been "
        "used outside testing."
    ),
    "azure_credential": (
        "Remove cloud credentials from the mobile application and rotate them "
        "in the cloud provider console if they are real."
    ),
    "password": "Remove hardcoded credentials and use a secure authentication flow.",
    "generic_api_key": (
        "Move the credential to a trusted backend and rotate it if it has been "
        "used outside testing."
    ),
    "bearer_token": (
        "Do not embed long-lived authentication tokens in the application package."
    ),
    "jwt": "Do not embed long-lived authentication tokens in the application package.",
    "database_url": (
        "Remove embedded database credentials from the client and rotate them "
        "if they are real."
    ),
    "google_api_key": (
        "This value is typically a public client identifier, not a server secret. "
        "Confirm it is restricted in the provider console."
    ),
}

IMPACTS = {
    "private_key": (
        "An embedded private key may be extracted from the application package "
        "and used by an unauthorized party."
    ),
    "stripe_key": (
        "An embedded payment API secret may allow unauthorized charges or "
        "account operations if the value is real."
    ),
    "aws_access_key": (
        "An embedded cloud access key may allow unauthorized access to cloud "
        "resources if the value is real."
    ),
    "azure_credential": (
        "An embedded Azure storage credential may allow unauthorized access to "
        "account data if the value is real."
    ),
    "password": (
        "A hardcoded password can be extracted from the package and reused "
        "against the associated service."
    ),
    "bearer_token": (
        "A long-lived bearer token can be replayed to impersonate a client or user."
    ),
    "jwt": (
        "An embedded JWT may grant access to an API until it expires or is revoked."
    ),
    "database_url": (
        "Database credentials in the client can expose the backing datastore."
    ),
    "generic_api_key": (
        "An embedded API credential can be extracted from the application package."
    ),
    "google_api_key": (
        "Google/Firebase client API keys are commonly public configuration, "
        "not server-side secrets."
    ),
}


class SecretScanner(Scanner):
    name = "secret-scanner"
    description = "Deterministic secret and sensitive-string detection"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def supports(self, context: ScanContext) -> bool:
        return context.job.platform is Platform.ANDROID and context.job.artifact_kind in {
            ArtifactKind.APK,
            ArtifactKind.AAB,
        }

    def _limits(self) -> SecretScanLimits:
        return SecretScanLimits(
            max_file_bytes=self.settings.max_secret_file_bytes,
            max_total_bytes=self.settings.max_secret_scan_total_bytes,
            max_files=self.settings.max_secret_scan_files,
            binary_string_limit=self.settings.secret_scan_binary_string_limit,
        )

    async def scan(self, context: ScanContext) -> list[Finding]:
        collector = SecretFileCollector(self._limits())
        findings: list[Finding] = []
        seen: set[tuple[str, int, str, str]] = set()
        try:
            for record in collector.iter_zip(context.artifact_path, source=SOURCE_RAW_APK):
                findings.extend(self._scan_record(record, seen))
            jadx_dir = context.extras.get("jadx_source_dir")
            if jadx_dir:
                for record in collector.iter_tree(Path(jadx_dir), source=SOURCE_JADX):
                    findings.extend(self._scan_record(record, seen))
            apktool_dir = context.extras.get("apktool_decoded_dir")
            if apktool_dir:
                for record in collector.iter_tree(Path(apktool_dir), source=SOURCE_APKTOOL):
                    findings.extend(self._scan_record(record, seen))
        except Exception:
            logger.warning(
                "secret scanner encountered an error; returning partial results",
                exc_info=True,
            )
        coverage = collector.coverage()
        context.extras["secret_scan_coverage"] = coverage
        try:
            out = context.workspace.findings_dir / "secret-scan-coverage.json"
            out.write_text(coverage.model_dump_json(indent=2), encoding="utf-8")
        except OSError:
            logger.debug("could not persist secret-scan coverage", exc_info=True)
        logger.info(
            "secret-scanner coverage files_scanned=%s files_skipped=%s bytes=%s sources=%s",
            coverage.files_scanned,
            coverage.files_skipped,
            coverage.bytes_scanned,
            ",".join(coverage.sources),
        )
        return findings

    def _scan_record(self, record: FileRecord, seen: set[tuple[str, int, str, str]]) -> list[Finding]:
        location = _display_path(record.source, record.path)
        return self._scan_text(
            location=location,
            text=record.text,
            seen=seen,
            source=record.source,
            path=record.path,
        )

    def _scan_text(
        self,
        location: str,
        text: str,
        seen: set[tuple[str, int, str, str]],
        *,
        source: str,
        path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        occupied: list[tuple[int, int]] = []
        firebase_client = _is_firebase_client_config(location, text)
        service_account = _looks_like_service_account(text)

        if firebase_client and not service_account:
            findings.extend(_http_findings(location, text, seen, source, path))
            return findings

        for match in PEM_RE.finditer(text):
            value = match.group(0)
            reason = "PEM private key block"
            if service_account:
                reason = "Google service-account private key material"
            finding = self._secret_finding(
                secret_type="private_key",
                rule_id="private_key",
                value=value,
                location=location,
                text=text,
                start=match.start(),
                confidence=0.99,
                severity=Severity.CRITICAL,
                verification=Verification.CONFIRMED,
                reason=reason,
                source=source,
                path=path,
            )
            if _remember(seen, finding, occupied, match.start(), match.end()):
                findings.append(finding)

        for pattern in PATTERNS:
            if pattern.secret_type == "google_api_key":
                continue
            for match in pattern.regex.finditer(text):
                if _overlaps(occupied, match.start(), match.end()):
                    continue
                value = match.group(0)
                if not _acceptable(value, location, text, pattern):
                    continue
                severity, verification, confidence, reason = _classify(pattern, value, text)
                finding = self._secret_finding(
                    secret_type=pattern.secret_type,
                    rule_id=pattern.rule_id,
                    value=value,
                    location=location,
                    text=text,
                    start=match.start(),
                    confidence=confidence,
                    severity=severity,
                    verification=verification,
                    reason=reason,
                    source=source,
                    path=path,
                )
                if _remember(seen, finding, occupied, match.start(), match.end()):
                    findings.append(finding)

        for match in PASSWORD_ASSIGN_RE.finditer(text):
            if _overlaps(occupied, match.start(), match.end()):
                continue
            label, value = match.group(1), match.group(2)
            if not _assignment_looks_secret(value, kind="password"):
                continue
            line = _line_at(text, match.start())
            if _is_comment_line(line) or _is_generated_path(path):
                continue
            finding = self._secret_finding(
                secret_type="password",
                rule_id="hardcoded_secret",
                value=value,
                location=location,
                text=text,
                start=match.start(),
                confidence=0.72,
                severity=Severity.HIGH,
                verification=Verification.POTENTIAL,
                reason=f"Assignment to '{label}' with a non-placeholder credential-like value",
                source=source,
                path=path,
            )
            if _remember(seen, finding, occupied, match.start(), match.end()):
                findings.append(finding)

        for match in APIKEY_ASSIGN_RE.finditer(text):
            if _overlaps(occupied, match.start(), match.end()):
                continue
            label, value = match.group(1), match.group(2)
            if not _assignment_looks_secret(value, kind="api_key"):
                continue
            line = _line_at(text, match.start())
            if _is_comment_line(line) or _is_generated_path(path):
                continue
            finding = self._secret_finding(
                secret_type="generic_api_key",
                rule_id="hardcoded_secret",
                value=value,
                location=location,
                text=text,
                start=match.start(),
                confidence=0.80,
                severity=Severity.MEDIUM,
                verification=Verification.POTENTIAL,
                reason=f"Assignment to '{label}' with strong credential context",
                source=source,
                path=path,
            )
            if _remember(seen, finding, occupied, match.start(), match.end()):
                findings.append(finding)

        findings.extend(_http_findings(location, text, seen, source, path))
        return findings

    def _secret_finding(
        self,
        *,
        secret_type: str,
        rule_id: str,
        value: str,
        location: str,
        text: str,
        start: int,
        confidence: float,
        severity: Severity,
        verification: Verification,
        reason: str,
        source: str,
        path: str,
    ) -> Finding:
        redacted = _redact_for_type(secret_type, value)
        line_no = _line_number(text, start)
        line = _line_at(text, start)
        evidence_line = _redacted_line(line, value, redacted)
        loc = f"{location}:{line_no}"
        potential = verification is Verification.POTENTIAL
        finding = normalize_finding(
            source=SOURCE,
            rule_id=rule_id,
            title=TITLES.get(secret_type, f"{secret_type.replace('_', ' ').title()} detected"),
            category=FindingCategory.SECRETS,
            severity=severity,
            confidence=confidence,
            description=(
                f"A {secret_type.replace('_', ' ')} candidate was found at `{loc}`. "
                f"Confidence {confidence:.2f}: {reason}. The value is redacted."
            ),
            impact=IMPACTS.get(
                secret_type,
                "Embedded credentials can be extracted from the application package.",
            ),
            recommendation=RECOMMENDATIONS.get(
                secret_type,
                "Remove secrets from the client binary; use a backend or short-lived tokens.",
            ),
            evidence=[
                Evidence(
                    kind="secret",
                    summary=evidence_line,
                    location=loc,
                    data={
                        "secret_type": secret_type,
                        "reason": reason,
                        "confidence_reason": reason,
                        "redacted": True,
                        "line": line_no,
                        "source": source,
                        "path": path,
                        "category": secret_type,
                        "redacted_value": redacted,
                    },
                )
            ],
            affected_component=f"{location}:{line_no}:{secret_type}",
            reproducibility=f"Static match in {loc} ({reason}).",
            potential=potential,
            verification=verification,
        )
        logger.debug(
            "secret-scanner match category=%s path=%s line=%s confidence=%.2f",
            secret_type,
            location,
            line_no,
            confidence,
        )
        return finding


def _display_path(source: str, path: str) -> str:
    if source == SOURCE_RAW_APK:
        return path
    if source == SOURCE_JADX:
        return f"tools/jadx/output/{path}"
    if source == SOURCE_APKTOOL:
        return f"tools/apktool/output/{path}"
    return path


def _remember(
    seen: set[tuple[str, int, str, str]],
    finding: Finding,
    occupied: list[tuple[int, int]],
    start: int,
    end: int,
) -> bool:
    evidence = finding.evidence[0] if finding.evidence else None
    secret_type = (evidence.data.get("secret_type") if evidence else "") or ""
    redacted = (evidence.data.get("redacted_value") if evidence else "") or finding.id
    line = int((evidence.data.get("line") if evidence else 0) or 0)
    location = (evidence.data.get("path") if evidence else "") or finding.affected_component or ""
    key = (str(location), line, str(secret_type), str(redacted))
    if key in seen:
        return False
    seen.add(key)
    occupied.append((start, end))
    return True


def _overlaps(occupied: list[tuple[int, int]], start: int, end: int) -> bool:
    for left, right in occupied:
        if start < right and end > left:
            return True
    return False


def _acceptable(value: str, _location: str, surrounding: str, pattern: SecretPattern) -> bool:
    if len(value) < pattern.min_length:
        return False
    if PLACEHOLDER_RE.search(value):
        return False
    if UUID_RE.match(value) or HEX_HASH_RE.match(value) or PACKAGE_RE.match(value) or VERSION_RE.match(value):
        return False
    if INTERPOLATION_RE.match(value.strip()):
        return False
    if "AKIAIOSFODNN7EXAMPLE" in value:
        return False
    if pattern.secret_type == "jwt" and value.count(".") != 2:
        return False
    if pattern.secret_type in {"bearer_token", "password", "generic_api_key"} and _shannon(value) < 3.3:
        return False
    if pattern.secret_type == "database_url" and not _database_url_has_credentials(value):
        return False
    window = _window(surrounding, value)
    if PLACEHOLDER_RE.search(window) and pattern.confidence < 0.9:
        return False
    return True


def _classify(
    pattern: SecretPattern,
    value: str,
    text: str,
) -> tuple[Severity, Verification, float, str]:
    if pattern.secret_type == "jwt":
        window = _window(text, value, radius=120)
        if AUTH_CONTEXT_RE.search(window):
            return (
                Severity.HIGH,
                Verification.POTENTIAL,
                0.90,
                "JWT with authentication context",
            )
        return (
            Severity.MEDIUM,
            Verification.POTENTIAL,
            0.45,
            "JWT-shaped value without authentication context",
        )
    if pattern.secret_type == "bearer_token":
        token = re.split(r"(?i)bearer\s+", value, maxsplit=1)[-1]
        if _looks_placeholder_value(token) or _shannon(token) < 3.3:
            return (
                Severity.LOW,
                Verification.POTENTIAL,
                0.35,
                "Bearer token with weak or placeholder material",
            )
        return pattern.severity, pattern.verification, pattern.confidence, pattern.reason
    return pattern.severity, pattern.verification, pattern.confidence, pattern.reason


def _assignment_looks_secret(value: str, *, kind: str) -> bool:
    if _looks_placeholder_value(value):
        return False
    if len(value) < 10:
        return False
    if UUID_RE.match(value) or HEX_HASH_RE.match(value) or PACKAGE_RE.match(value):
        return False
    if kind == "password" and value.lower() in WEAK_VALUES:
        return False
    if kind == "password" and value.lower() in {"password", "example", "test"}:
        return False
    return _shannon(value) >= 3.5


def _looks_placeholder_value(value: str) -> bool:
    stripped = value.strip()
    if PLACEHOLDER_RE.search(stripped):
        return True
    if INTERPOLATION_RE.match(stripped):
        return True
    if stripped.lower() in WEAK_VALUES:
        return True
    return False


def _is_firebase_client_config(location: str, text: str) -> bool:
    loc = location.lower()
    if "google-services.json" in loc or loc.endswith("google_app_id.xml"):
        return True
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        if payload.get("type") == "service_account":
            return False
        project = payload.get("project_info")
        client = payload.get("client")
        if isinstance(project, dict) and client is not None:
            return True
    head = text[:2500].lower()
    if any(hint in loc for hint in FIREBASE_PUBLIC_HINTS):
        return True
    if "mobilesdk_app_id" in head or "gcm_defaultsenderid" in head:
        return True
    if '"project_info"' in head and "storage_bucket" in head:
        return True
    return False


def _looks_like_service_account(text: str) -> bool:
    head = text[:4000]
    return "service_account" in head and "private_key" in head


def _database_url_has_credentials(value: str) -> bool:
    if "://" not in value or "@" not in value:
        return False
    rest = value.split("://", 1)[1]
    userinfo, _, hostpart = rest.partition("@")
    if not hostpart or ":" not in userinfo:
        return False
    username, _, password = userinfo.partition(":")
    if not username or not password:
        return False
    if _looks_placeholder_value(password):
        return False
    return True


def _http_findings(
    location: str,
    text: str,
    seen: set[tuple[str, int, str, str]],
    source: str,
    path: str,
) -> list[Finding]:
    findings: list[Finding] = []
    skip_hosts = ("schemas.android.com", "example.com", "localhost", "127.0.0.1")
    for match in HTTP_URL_RE.finditer(text):
        url = match.group(0)
        if not url.lower().startswith("http://"):
            continue
        if any(host in url.lower() for host in skip_hosts):
            continue
        line_no = _line_number(text, match.start())
        key = (path, line_no, "http", url.split("?")[0])
        if key in seen:
            continue
        seen.add(key)
        redacted = url.split("?")[0]
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="http_endpoint",
                title="HTTP (cleartext) URL referenced",
                category=FindingCategory.NETWORK,
                severity=Severity.INFO,
                confidence=0.8,
                description=(
                    f"An HTTP URL was found in `{location}`. This is not automatically a vulnerability; "
                    "it is correlated with cleartext-traffic configuration when present."
                ),
                evidence=[
                    Evidence(
                        kind="url",
                        summary=redacted,
                        location=f"{location}:{line_no}",
                        data={"source": source, "path": path, "line": line_no},
                    )
                ],
                affected_component=location,
                reproducibility=f"Static string in {location}.",
                verification=Verification.INFO,
            )
        )
    return findings


def _shannon(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _window(text: str, value: str, radius: int = 80) -> str:
    idx = text.find(value)
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(value) + radius)
    return text[start:end]


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _line_at(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[start:end]


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "*", "/*", "<!--", ";"))


def _is_generated_path(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    return (
        "/generated/" in lowered
        or lowered.endswith("/r.java")
        or lowered.endswith("buildconfig.java")
    )


def _redacted_line(line: str, value: str, redacted: str) -> str:
    if value and value in line:
        rendered = line.replace(value, redacted, 1).strip()
    else:
        rendered = redacted
    if len(rendered) > 240:
        rendered = rendered[:240] + "…"
    return rendered


def _redact_for_type(secret_type: str, value: str) -> str:
    if secret_type == "private_key":
        return redact_private_key(value) or "-----BEGIN PRIVATE KEY----- [REDACTED]"
    if secret_type == "jwt":
        parts = value.split(".")
        if len(parts) >= 2:
            return f"{parts[0][:8]}{'*' * 12}.{redact_secret(parts[1], keep_prefix=4, keep_suffix=2)}"
    if secret_type == "bearer_token":
        split = re.split(r"(?i)(bearer\s+)", value, maxsplit=1)
        if len(split) >= 3:
            return f"{split[1]}{redact_secret(split[2])}"
        return redact_secret(value)
    if secret_type == "database_url":
        return _redact_database_url(value)
    return redact_secret(value)


def _redact_database_url(value: str) -> str:
    try:
        scheme, rest = value.split("://", 1)
        userinfo, host = rest.split("@", 1)
        username, _, password = userinfo.partition(":")
        return f"{scheme}://{username}:{redact_secret(password, keep_prefix=2, keep_suffix=2)}@{host}"
    except ValueError:
        return redact_secret(value)
