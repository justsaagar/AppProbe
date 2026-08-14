"""Secret-scanner tests using synthetic fixtures only.

Provider-shaped values needed to exercise detectors are assembled at runtime
from obviously fake components. Realistic production-style credentials are
never stored in the repository.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import ArtifactKind, Platform, Severity, Verification
from app.models.scan_job import ScanJob
from app.reporters.markdown import MarkdownReporter
from app.scanners.base import ScanContext
from app.scanners.files import SecretFileCollector, SecretScanLimits
from app.scanners.secrets import SecretScanner
from app.storage.workspace import ScanWorkspace
from app.utils.redact import redact_secret
from tests.helpers import write_apk

FAKE_STRIPE_KEY = "FAKE_STRIPE_KEY_FOR_APPPROBE_TEST_ONLY"
FAKE_PASSWORD = "FAKE_PASSWORD_FOR_SECURITY_TEST_ONLY"
FAKE_JWT = "FAKE_JWT_FOR_APPPROBE_TEST_ONLY"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _stripe_live() -> str:
    marker = "APPPROBETESTONLYNOTAREALKEY"
    return "".join(("sk", "_", "live", "_", marker))


def _stripe_publishable() -> str:
    marker = "APPPROBETESTONLYNOTSECRET"
    return "".join(("pk", "_", "live", "_", marker))


def _jwt() -> str:
    header = _b64url(
        json.dumps(
            {"alg": "none", "typ": "JWT", "kid": "APPPROBE-TEST-ONLY"},
            separators=(",", ":"),
        ).encode()
    )
    payload = _b64url(
        json.dumps(
            {"sub": "appprobe-test-user", "iss": "appprobe.example.test"},
            separators=(",", ":"),
        ).encode()
    )
    signature = _b64url(b"APPPROBE-TEST-SIGNATURE-NOT-A-SECRET")
    return ".".join((header, payload, signature))


def _private_key_pem() -> str:
    return "\n".join(
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "APPPROBE_TEST_ONLY_NOT_A_REAL_PRIVATE_KEY_BLOCK",
            "-----END RSA PRIVATE KEY-----",
        )
    )


def _google_api_key() -> str:
    return "".join(("AIza", "Sy", "AppProbeTestPublicClientKey00001"))


def _firebase_json() -> str:
    return json.dumps(
        {
            "project_info": {
                "project_id": "demo-app",
                "storage_bucket": "demo-app.appspot.com",
            },
            "client": [{"api_key": [{"current_key": _google_api_key()}]}],
        }
    )


def _aws_key() -> str:
    return "AKIA" + "APPPROBETESTKEY1"


def _openai_key() -> str:
    return "sk-" + ("b" * 24) + "APPPROBE"


def _github_token() -> str:
    return "ghp_" + "APPPROBETESTONLYTOK1"


def _slack_token() -> str:
    return "xoxb-" + "12345-" + "APPPROBEFAKETOKEN"


def _azure_connection() -> str:
    return (
        "DefaultEndpointsProtocol=https;AccountName=appprobetest;AccountKey="
        + ("B" * 24)
    )


def _db_url() -> str:
    return "postgres://appprobe_user:" + "N0tARealPwd99" + "@db.internal.test:5432/appprobe"


async def _scan(
    tmp_path: Path,
    extra_files: dict[str, bytes],
    *,
    scan_id: str = "sec",
    settings: Settings | None = None,
    extras: dict | None = None,
):
    apk = write_apk(tmp_path / f"{scan_id}.apk", extra_files=extra_files)
    workspace = ScanWorkspace(tmp_path / f"scan-{scan_id}")
    workspace.ensure()
    job = ScanJob(
        id=scan_id,
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    context = ScanContext(
        job=job,
        workspace=workspace,
        artifact_path=apk,
        extras=extras or {},
    )
    scanner = SecretScanner(settings or Settings(workspace_dir=tmp_path / "ws"))
    findings = await scanner.scan(context)
    return findings, context


def _types(findings) -> list[str]:
    return [ev.data.get("secret_type") for item in findings for ev in item.evidence]


def _of_type(findings, secret_type: str):
    return [
        item
        for item in findings
        if any(ev.data.get("secret_type") == secret_type for ev in item.evidence)
    ]


@pytest.mark.asyncio
async def test_synthetic_api_key_detected_and_placeholder_ignored(tmp_path: Path) -> None:
    strong = "api_key=\"" + "Zp7mQ9wL2nX4cH8bR1tY6vK0sD3fJ5aU" + "\"\n"
    weak = 'api_key="FAKE_API_KEY_FOR_TESTING_ONLY"\n'
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/api.properties": strong.encode(),
            "assets/placeholder.properties": weak.encode(),
        },
        scan_id="api-key",
    )
    types = _types(findings)
    assert "generic_api_key" in types
    placeholder = [
        item
        for item in _of_type(findings, "generic_api_key")
        if "placeholder.properties" in (item.evidence[0].location or "")
    ]
    assert placeholder == []


@pytest.mark.asyncio
async def test_stripe_secret_detected_public_key_ignored(tmp_path: Path) -> None:
    live = _stripe_live()
    publishable = _stripe_publishable()
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/stripe.txt": (
                f"secret={live}\n"
                f"publishable={publishable}\n"
                f"fake={FAKE_STRIPE_KEY}\n"
            ).encode()
        },
        scan_id="stripe",
    )
    types = _types(findings)
    assert "stripe_key" in types
    assert not any(publishable in (item.evidence[0].summary or "") for item in findings)
    stripe = _of_type(findings, "stripe_key")[0]
    assert stripe.severity is Severity.CRITICAL
    assert stripe.verification is Verification.CONFIRMED
    assert live not in stripe.evidence[0].summary
    assert "*" in stripe.evidence[0].summary


@pytest.mark.asyncio
async def test_jwt_context_and_non_jwt_dotted_string(tmp_path: Path) -> None:
    token = _jwt()
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/auth.txt": f"Authorization token={token}\n".encode(),
            "assets/random.txt": b"version=aaaa.bbbb.cccc\nnot_a_jwt=foo.bar.baz\n",
        },
        scan_id="jwt",
    )
    jwt_findings = _of_type(findings, "jwt")
    assert jwt_findings
    assert jwt_findings[0].verification is Verification.POTENTIAL
    assert jwt_findings[0].confidence >= 0.8
    assert token not in jwt_findings[0].evidence[0].summary
    random_hits = [
        item
        for item in jwt_findings
        if "random.txt" in (item.evidence[0].location or "")
    ]
    assert random_hits == []
    placeholder, _ = await _scan(
        tmp_path,
        {"assets/docs.txt": b'token="YOUR_JWT_HERE"\n'},
        scan_id="jwt-ph",
    )
    assert "jwt" not in _types(placeholder)


@pytest.mark.asyncio
async def test_password_assignment_and_weak_values(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/passwords.txt": (
                f'password="{FAKE_PASSWORD}"\n'
                'password="password"\n'
                'password="example"\n'
                'password="test_password"\n'
                'pwd="YOUR_PASSWORD"\n'
            ).encode()
        },
        scan_id="pwd",
    )
    passwords = _of_type(findings, "password")
    assert passwords
    summaries = " ".join(item.evidence[0].summary for item in passwords)
    assert FAKE_PASSWORD not in summaries
    assert passwords[0].severity is Severity.HIGH
    weak_only, _ = await _scan(
        tmp_path,
        {"assets/weak.txt": b'password="password"\npasswd="example"\n'},
        scan_id="pwd-weak",
    )
    assert _of_type(weak_only, "password") == []


@pytest.mark.asyncio
async def test_private_key_is_critical_and_redacted(tmp_path: Path) -> None:
    pem = _private_key_pem()
    findings, _ = await _scan(
        tmp_path,
        {"assets/key.pem": pem.encode()},
        scan_id="pem",
    )
    private = _of_type(findings, "private_key")
    assert private
    assert private[0].severity is Severity.CRITICAL
    assert private[0].verification is Verification.CONFIRMED
    assert private[0].confidence >= 0.99
    summary = private[0].evidence[0].summary
    assert "-----BEGIN PRIVATE KEY----- [REDACTED]" in summary
    assert "APPPROBE_TEST_ONLY" not in summary
    assert pem not in summary


@pytest.mark.asyncio
async def test_bearer_token_detected_and_redacted(tmp_path: Path) -> None:
    token = "APPPROBE" + "BearerTok3nValueNotReal0099"
    header = "Authorization: Bearer " + token
    findings, _ = await _scan(
        tmp_path,
        {"assets/http.txt": header.encode()},
        scan_id="bearer",
    )
    bearer = _of_type(findings, "bearer_token")
    assert bearer
    assert token not in bearer[0].evidence[0].summary
    assert "Bearer" in bearer[0].evidence[0].summary
    assert "*" in bearer[0].evidence[0].summary


@pytest.mark.asyncio
async def test_cloud_credentials_aws_google_azure(tmp_path: Path) -> None:
    aws = _aws_key()
    azure = _azure_connection()
    pem = _private_key_pem()
    service_account = json.dumps(
        {
            "type": "service_account",
            "project_id": "appprobe-test",
            "private_key": pem,
            "client_email": "appprobe@example.test",
        }
    )
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/aws.properties": f"accessKey={aws}\n".encode(),
            "assets/azure.txt": azure.encode(),
            "assets/sa.json": service_account.encode(),
        },
        scan_id="cloud",
    )
    types = set(_types(findings))
    assert "aws_access_key" in types
    assert "azure_credential" in types
    assert "private_key" in types
    aws_finding = _of_type(findings, "aws_access_key")[0]
    assert aws_finding.severity is Severity.CRITICAL
    assert aws not in aws_finding.evidence[0].summary


@pytest.mark.asyncio
async def test_openai_and_github_and_slack_assembled_at_runtime(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/keys.txt": (
                f"openai={_openai_key()}\n"
                f"github={_github_token()}\n"
                f"slack={_slack_token()}\n"
            ).encode()
        },
        scan_id="providers",
    )
    types = set(_types(findings))
    assert "openai_api_key" in types
    assert "github_token" in types
    assert "slack_token" in types


@pytest.mark.asyncio
async def test_firebase_client_config_is_not_a_secret(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {"google-services.json": _firebase_json().encode()},
        scan_id="firebase",
    )
    secretish = [
        item
        for item in findings
        if item.category == "secrets" and item.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
    ]
    assert secretish == []
    assert "google_api_key" not in _types(findings)
    assert "private_key" not in _types(findings)


@pytest.mark.asyncio
async def test_database_url_requires_credentials(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/db.txt": (
                f"prod={_db_url()}\n"
                "plain=postgres://db.internal.test:5432/appprobe\n"
            ).encode()
        },
        scan_id="db",
    )
    db = _of_type(findings, "database_url")
    assert db
    assert db[0].severity is Severity.HIGH
    assert "N0tARealPwd99" not in db[0].evidence[0].summary
    assert not any("postgres://db.internal.test:5432/appprobe" == ev.summary for item in db for ev in item.evidence)


@pytest.mark.asyncio
async def test_false_positives_uuid_hash_version_package_placeholders(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/noise.txt": (
                b"uuid=550e8400-e29b-41d4-a716-446655440000\n"
                b"hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                b"ver=1.2.3\n"
                b"pkg=com.example.vulnerable\n"
                b"api_key=YOUR_API_KEY_HERE\n"
                b"api_key=${API_KEY}\n"
                b'api_key="<API_KEY>"\n'
                b"api_key=process.env.API_KEY\n"
                b"password=example_password\n"
            )
        },
        scan_id="fp",
    )
    types = set(_types(findings))
    assert "generic_api_key" not in types
    assert "password" not in types
    assert "jwt" not in types


@pytest.mark.asyncio
async def test_file_traversal_nested_malformed_large_binary_symlink(tmp_path: Path) -> None:
    settings = Settings(
        workspace_dir=tmp_path / "ws",
        max_secret_file_bytes=512,
        max_secret_scan_total_bytes=1024 * 1024,
    )
    outside = tmp_path / "outside.txt"
    outside.write_text("password=\"" + FAKE_PASSWORD + "\"\n", encoding="utf-8")
    tree = tmp_path / "jadx-out"
    nested = tree / "sources" / "com" / "example"
    nested.mkdir(parents=True)
    (nested / "ApiClient.java").write_text(
        f'public class ApiClient {{ String key = "{_stripe_live()}"; }}\n',
        encoding="utf-8",
    )
    (tree / "huge.txt").write_text("A" * 4096, encoding="utf-8")
    (tree / "blob.bin").write_bytes(_stripe_live().encode() + b"\x00\xff" * 20)
    (tree / "broken.xml").symlink_to(tmp_path / "missing-target")
    (tree / "escape.txt").symlink_to(outside)
    findings, context = await _scan(
        tmp_path,
        {"assets/nested/dir/ok.txt": b"hello=world\n"},
        scan_id="traverse",
        settings=settings,
        extras={"jadx_source_dir": str(tree)},
    )
    assert "stripe_key" in _types(findings)
    stripe_paths = [item.evidence[0].location or "" for item in _of_type(findings, "stripe_key")]
    assert any("tools/jadx/output" in path for path in stripe_paths)
    coverage = context.extras["secret_scan_coverage"]
    reasons = {item.reason for item in coverage.skipped_files}
    assert "file size exceeds scanner limit" in reasons
    assert "symlink skipped" in reasons
    escaped = [item for item in _of_type(findings, "password") if "outside" in (item.evidence[0].location or "")]
    assert escaped == []
    blob_hits = [item for item in findings if "blob.bin" in (item.evidence[0].location or "")]
    assert blob_hits == []


@pytest.mark.asyncio
async def test_limits_and_skipped_file_reporting(tmp_path: Path) -> None:
    settings = Settings(
        workspace_dir=tmp_path / "ws",
        max_secret_file_bytes=64,
        max_secret_scan_total_bytes=80,
        max_secret_scan_files=10,
    )
    findings, context = await _scan(
        tmp_path,
        {
            "assets/a.txt": b"alpha-file-contents-ok\n",
            "assets/b.txt": b"bravo-file-contents-ok\n",
            "assets/large.txt": b"X" * 200,
        },
        scan_id="limits",
        settings=settings,
    )
    coverage = context.extras["secret_scan_coverage"]
    assert coverage.files_skipped >= 1
    assert any("file size exceeds scanner limit" in item.reason for item in coverage.skipped_files) or any(
        "maximum total bytes exceeded" in item.reason for item in coverage.skipped_files
    )
    assert coverage.bytes_scanned <= settings.max_secret_scan_total_bytes
    assert findings is not None


def test_binary_string_limit() -> None:
    blob = b"\x00".join(f"string{i:04d}XXXX".encode() for i in range(50))
    collector = SecretFileCollector(
        SecretScanLimits(
            max_file_bytes=10_000,
            max_total_bytes=10_000,
            max_files=10,
            binary_string_limit=5,
        )
    )
    from app.scanners.files import extract_printable_strings

    text = extract_printable_strings(blob, max_strings=5)
    assert text.count("\n") <= 4
    assert collector.limits.binary_string_limit == 5


@pytest.mark.asyncio
async def test_evidence_contains_path_line_redaction_confidence(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {"assets/config.properties": f"key={_stripe_live()}\n".encode()},
        scan_id="evidence",
    )
    stripe = _of_type(findings, "stripe_key")[0]
    data = stripe.evidence[0].data
    assert data["path"] == "assets/config.properties"
    assert data["line"] == 1
    assert data["redacted"] is True
    assert stripe.confidence > 0.9
    assert "Stripe" in data["confidence_reason"]
    assert stripe.evidence[0].location.endswith(":1")


@pytest.mark.asyncio
async def test_severity_mapping_is_deterministic(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "assets/mix.txt": (
                f"{_private_key_pem()}\n"
                f"stripe={_stripe_live()}\n"
                f"token={_jwt()}\n"
                f'password="{FAKE_PASSWORD}"\n'
            ).encode()
        },
        scan_id="sev",
    )
    assert _of_type(findings, "private_key")[0].severity is Severity.CRITICAL
    assert _of_type(findings, "stripe_key")[0].severity is Severity.CRITICAL
    assert _of_type(findings, "password")[0].severity is Severity.HIGH
    jwt = _of_type(findings, "jwt")[0]
    assert jwt.severity in {Severity.HIGH, Severity.MEDIUM}
    assert jwt.verification is Verification.POTENTIAL


@pytest.mark.asyncio
async def test_local_deduplication(tmp_path: Path) -> None:
    live = _stripe_live()
    findings, _ = await _scan(
        tmp_path,
        {"assets/dup.txt": f"a={live} b={live}\n".encode()},
        scan_id="dedup",
    )
    assert len(_of_type(findings, "stripe_key")) == 1


@pytest.mark.asyncio
async def test_apktool_tree_is_scanned_when_present(tmp_path: Path) -> None:
    tree = tmp_path / "apktool-out"
    (tree / "res" / "raw").mkdir(parents=True)
    (tree / "res" / "raw" / "config.txt").write_text(
        _private_key_pem() + "\n",
        encoding="utf-8",
    )
    findings, context = await _scan(
        tmp_path,
        {},
        scan_id="apktool",
        extras={"apktool_decoded_dir": str(tree)},
    )
    private = _of_type(findings, "private_key")
    assert private
    assert "tools/apktool/output" in (private[0].evidence[0].location or "")
    assert "apktool output" in context.extras["secret_scan_coverage"].sources


def test_scanner_module_has_no_network_client_imports() -> None:
    import app.scanners.secrets as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("urllib", "requests", "httpx", "aiohttp", "socket.create_connection"):
        assert banned not in source


@pytest.mark.asyncio
async def test_manual_synthetic_apk_report_redacts_values(tmp_path: Path) -> None:
    stripe = _stripe_live()
    token = _jwt()
    pem = _private_key_pem()
    findings, context = await _scan(
        tmp_path,
        {
            "assets/secrets.txt": (
                f"api={stripe}\n"
                f'token="{token}"\n'
                f"{pem}\n"
                f'password="{FAKE_PASSWORD}"\n'
            ).encode(),
            "google-services.json": _firebase_json().encode(),
        },
        scan_id="manual",
    )
    job = context.job
    job.findings = findings
    job.secret_scan_coverage = context.extras["secret_scan_coverage"]
    markdown = MarkdownReporter().render(job)
    assert "## Secrets & Sensitive Data" in markdown
    assert "## Secret Scan Coverage" in markdown
    assert "SEC-SECRET-001" in markdown
    assert "Files scanned:" in markdown
    assert "raw APK" in markdown
    assert stripe not in markdown
    assert token not in markdown
    assert "APPPROBE_TEST_ONLY_NOT_A_REAL_PRIVATE_KEY_BLOCK" not in markdown
    assert FAKE_PASSWORD not in markdown
    assert "-----BEGIN PRIVATE KEY----- [REDACTED]" in markdown
    firebase_critical = [
        item
        for item in findings
        if "google-services.json" in (item.affected_component or "")
        and item.severity in {Severity.CRITICAL, Severity.HIGH}
    ]
    assert firebase_critical == []
    assert os.environ.get("NO_NETWORK", "1")


def test_redaction_helper_masks_provider_prefix() -> None:
    value = _stripe_live()
    redacted = redact_secret(value)
    assert value not in redacted
    assert redacted.startswith("".join(("sk", "_", "live", "_")))
    assert "*" in redacted
