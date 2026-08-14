"""Deterministic secret and sensitive-string detector."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

from app.analyzers.findings import normalize_finding
from app.analyzers.severity import apply_rule_severity
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
    iter_tree_text_files,
    iter_zip_native_libraries,
    iter_zip_text_entries,
)
from app.utils.redact import redact_secret

SOURCE = "secret-scanner"

PLACEHOLDER_RE = re.compile(
    r"(placeholder|changeme|your[-_]?api[-_]?key|example|sample|xxxx+|todo|"
    r"for[_-]?testing|fake[_-]?api[_-]?key|insert[_-]?key|dummy|xxx-xxx)",
    re.I,
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
HEX_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
PACKAGE_RE = re.compile(r"^(com|org|net|io|android)\.[A-Za-z0-9_.]+$")
VERSION_RE = re.compile(r"^v?\d+(\.\d+){1,4}(-[A-Za-z0-9.]+)?$")

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
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.S,
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
        0.95,
        Severity.CRITICAL,
        Verification.CONFIRMED,
        "Stripe live secret/restricted key prefix",
    ),
    SecretPattern(
        "stripe_test_key",
        "hardcoded_secret",
        re.compile(r"(?:sk_test_|rk_test_)[A-Za-z0-9]{16,}"),
        24,
        0.9,
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
        0.9,
        Severity.HIGH,
        Verification.CONFIRMED,
        "Slack token prefix",
    ),
    SecretPattern(
        "google_api_key",
        "hardcoded_secret",
        re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
        24,
        0.5,
        Severity.INFO,
        Verification.INFO,
        "Google API client key prefix; often a public client identifier",
    ),
    SecretPattern(
        "jwt",
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        40,
        0.7,
        Severity.HIGH,
        Verification.POTENTIAL,
        "JWT compact serialization (three base64url segments)",
    ),
    SecretPattern(
        "bearer_token",
        "hardcoded_secret",
        re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
        20,
        0.6,
        Severity.HIGH,
        Verification.POTENTIAL,
        "Bearer token assignment",
    ),
    SecretPattern(
        "database_url",
        "hardcoded_secret",
        re.compile(
            r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^\s\"']{8,}"
        ),
        16,
        0.85,
        Severity.HIGH,
        Verification.CONFIRMED,
        "Database/connection URL with scheme",
    ),
)

ASSIGNMENT_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[=:]\s*[\"']([^\"']{6,})[\"']"
)


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

    async def scan(self, context: ScanContext) -> list[Finding]:
        documents = list(self._collect_documents(context))
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for location, text in documents:
            findings.extend(self._scan_text(location, text, seen))
        return findings

    def _collect_documents(self, context: ScanContext) -> list[tuple[str, str]]:
        max_files = self.settings.max_secret_scan_files
        max_bytes = self.settings.max_secret_file_bytes
        documents: list[tuple[str, str]] = []
        documents.extend(
            (f"apk:{name}", text)
            for name, text in iter_zip_text_entries(
                context.artifact_path, max_files=max_files, max_bytes=max_bytes
            )
        )
        jadx_dir = context.extras.get("jadx_source_dir")
        if jadx_dir:
            documents.extend(
                (f"jadx:{rel}", text)
                for rel, text in iter_tree_text_files(
                    Path(jadx_dir), max_files=max_files, max_bytes=max_bytes
                )
            )
        apktool_dir = context.extras.get("apktool_decoded_dir")
        if apktool_dir:
            documents.extend(
                (f"apktool:{rel}", text)
                for rel, text in iter_tree_text_files(
                    Path(apktool_dir), max_files=max_files, max_bytes=max_bytes
                )
            )
        for name, blob in iter_zip_native_libraries(context.artifact_path, max_bytes=max_bytes):
            extracted = _printable_strings(blob)
            if extracted:
                documents.append((f"native:{name}", extracted))
        return documents[:max_files]

    def _scan_text(self, location: str, text: str, seen: set[tuple[str, str, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for match in PEM_RE.finditer(text):
            value = match.group(0)
            finding = self._secret_finding(
                secret_type="private_key",
                rule_id="private_key",
                value=value,
                location=location,
                confidence=0.99,
                severity=Severity.CRITICAL,
                verification=Verification.CONFIRMED,
                reason="PEM private key block",
            )
            key = ("private_key", location, finding.id)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

        for pattern in PATTERNS:
            for match in pattern.regex.finditer(text):
                value = match.group(0)
                if not _acceptable(value, location, text, pattern):
                    continue
                severity, verification, confidence = _adjust_google_or_firebase(
                    pattern, value, location, text
                )
                finding = self._secret_finding(
                    secret_type=pattern.secret_type,
                    rule_id=pattern.rule_id,
                    value=value,
                    location=location,
                    confidence=confidence,
                    severity=severity,
                    verification=verification,
                    reason=pattern.reason,
                )
                key = (pattern.secret_type, location, value[:16])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

        for match in ASSIGNMENT_RE.finditer(text):
            label, value = match.group(1), match.group(2)
            if not _assignment_looks_secret(value):
                continue
            finding = self._secret_finding(
                secret_type="password",
                rule_id="hardcoded_secret",
                value=value,
                location=location,
                confidence=0.55,
                severity=Severity.HIGH,
                verification=Verification.POTENTIAL,
                reason=f"Assignment to '{label}' with high-entropy value",
            )
            key = ("password", location, value[:16])
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

        findings.extend(_http_findings(location, text, seen))
        return findings

    def _secret_finding(
        self,
        *,
        secret_type: str,
        rule_id: str,
        value: str,
        location: str,
        confidence: float,
        severity: Severity,
        verification: Verification,
        reason: str,
    ) -> Finding:
        redacted = _redact_for_type(secret_type, value)
        potential = verification is Verification.POTENTIAL
        return normalize_finding(
            source=SOURCE,
            rule_id=rule_id,
            title=f"{secret_type.replace('_', ' ').title()} detected",
            category=FindingCategory.SECRETS,
            severity=severity if not potential else apply_rule_severity(rule_id, potential=True),
            confidence=confidence,
            description=(
                f"A {secret_type} candidate was found at `{location}`. "
                f"Reason: {reason}. The value is redacted."
            ),
            impact="Embedded credentials can be extracted from the application package.",
            recommendation="Remove secrets from the client binary; use a backend or short-lived tokens.",
            evidence=[
                Evidence(
                    kind="secret",
                    summary=redacted,
                    location=location,
                    data={"secret_type": secret_type, "reason": reason, "redacted": True},
                )
            ],
            affected_component=location,
            reproducibility=f"Static match in {location} ({reason}).",
            potential=potential,
            verification=verification,
        )


def _acceptable(value: str, location: str, surrounding: str, pattern: SecretPattern) -> bool:
    if len(value) < pattern.min_length:
        return False
    if PLACEHOLDER_RE.search(value) or PLACEHOLDER_RE.search(location):
        return False
    if UUID_RE.match(value) or HEX_HASH_RE.match(value) or PACKAGE_RE.match(value) or VERSION_RE.match(value):
        return False
    if "AKIAIOSFODNN7EXAMPLE" in value:
        return False
    if pattern.secret_type == "jwt" and value.count(".") != 2:
        return False
    if pattern.secret_type in {"bearer_token", "password"} and _shannon(value) < 3.3:
        return False
    window = _window(surrounding, value)
    if PLACEHOLDER_RE.search(window) and pattern.secret_type not in {"stripe_key", "aws_access_key"}:
        # still allow high-confidence prefixes
        if pattern.confidence < 0.9:
            return False
    return True


def _adjust_google_or_firebase(
    pattern: SecretPattern,
    value: str,
    location: str,
    text: str,
) -> tuple[Severity, Verification, float]:
    blob = f"{location} {text[:400]}".lower()
    if pattern.secret_type == "google_api_key":
        if any(hint in blob for hint in FIREBASE_PUBLIC_HINTS) or "google-services.json" in location:
            return Severity.INFO, Verification.INFO, 0.9
        return Severity.INFO, Verification.INFO, pattern.confidence
    if "google-services.json" in location and pattern.secret_type not in {"private_key"}:
        return Severity.INFO, Verification.INFO, 0.8
    return pattern.severity, pattern.verification, pattern.confidence


def _assignment_looks_secret(value: str) -> bool:
    if PLACEHOLDER_RE.search(value) or len(value) < 10:
        return False
    if UUID_RE.match(value) or HEX_HASH_RE.match(value) or PACKAGE_RE.match(value):
        return False
    return _shannon(value) >= 3.5


def _http_findings(location: str, text: str, seen: set[tuple[str, str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    skip_hosts = ("schemas.android.com", "example.com", "localhost", "127.0.0.1")
    for match in HTTP_URL_RE.finditer(text):
        url = match.group(0)
        if not url.lower().startswith("http://"):
            continue
        if any(host in url.lower() for host in skip_hosts):
            continue
        key = ("http", location, url)
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
                        location=location,
                    )
                ],
                affected_component=location,
                reproducibility=f"Static string in {location}.",
                verification=Verification.INFO,
            )
        )
    return findings


def _printable_strings(blob: bytes) -> str:
    chunks: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= 8:
                chunks.append(current.decode("ascii"))
            current = bytearray()
        if len(chunks) >= 400:
            break
    if len(current) >= 8:
        chunks.append(current.decode("ascii"))
    return "\n".join(chunks)


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


def _redact_for_type(secret_type: str, value: str) -> str:
    if secret_type == "private_key":
        return "-----BEGIN PRIVATE KEY-----\\n********\\n-----END PRIVATE KEY-----"
    if secret_type == "jwt":
        parts = value.split(".")
        if len(parts) >= 2:
            return f"{parts[0][:8]}********.{redact_secret(parts[1], keep_prefix=4, keep_suffix=2)}"
    return redact_secret(value)
