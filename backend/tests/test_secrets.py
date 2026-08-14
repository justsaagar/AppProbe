from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import ArtifactKind, Platform, Severity, Verification
from app.models.scan_job import ScanJob
from app.scanners.base import ScanContext
from app.scanners.secrets import SecretScanner
from app.storage.workspace import ScanWorkspace
from app.utils.redact import redact_secret
from tests.helpers import write_apk

STRIPE_LIVE = "sk_live_abcdefghijklmnopqrstuvwx1234"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepartneedslength"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIFakePrivateKeyDataForUnitTestsNotRealABCDEFGHIJKLMNOPQRSTUVWX\n"
    "-----END RSA PRIVATE KEY-----"
)
FIREBASE_JSON = """{
  "project_info": {"project_id": "demo-app", "storage_bucket": "demo-app.appspot.com"},
  "client": [{"api_key": [{"current_key": "AIzaSyFakePublicClientKeyForTests1234567"}]}]
}
"""


@pytest.mark.asyncio
async def test_detects_stripe_jwt_private_key_and_password(tmp_path: Path) -> None:
    assets = (
        f"key={STRIPE_LIVE}\n"
        f"token={JWT}\n"
        f"{PRIVATE_KEY}\n"
        'password="N7v9Qx2Lm8Zp4Hd1Rc6"\n'
    ).encode()
    apk = write_apk(tmp_path / "app.apk", extra_files={"res/values/secrets.xml": assets})
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="s1",
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    findings = await SecretScanner(Settings(workspace_dir=tmp_path / "ws")).scan(
        ScanContext(job=job, workspace=workspace, artifact_path=apk)
    )
    types = [ev.data.get("secret_type") for item in findings for ev in item.evidence]
    assert "stripe_key" in types
    assert "jwt" in types
    assert "private_key" in types
    assert "password" in types
    stripe = next(item for item in findings if any(ev.data.get("secret_type") == "stripe_key" for ev in item.evidence))
    assert stripe.severity is Severity.CRITICAL
    assert stripe.verification is Verification.CONFIRMED
    assert STRIPE_LIVE not in stripe.evidence[0].summary
    assert "****" in stripe.evidence[0].summary or "*" in stripe.evidence[0].summary
    private = next(item for item in findings if any(ev.data.get("secret_type") == "private_key" for ev in item.evidence))
    assert private.severity is Severity.CRITICAL
    assert "BEGIN PRIVATE KEY" in private.evidence[0].summary
    assert "MIIFake" not in private.evidence[0].summary


@pytest.mark.asyncio
async def test_skips_placeholder_and_firebase_public_config(tmp_path: Path) -> None:
    files = {
        "res/values/strings.xml": b"key=FAKE_API_KEY_FOR_TESTING_ONLY\napi=sk_live_YOUR_API_KEY_HERE_xxxxxxxxxx",
        "google-services.json": FIREBASE_JSON.encode(),
        "res/values/ids.xml": b"uuid=550e8400-e29b-41d4-a716-446655440000\nver=1.2.3",
    }
    apk = write_apk(tmp_path / "app.apk", extra_files=files)
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="s2",
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    findings = await SecretScanner(Settings(workspace_dir=tmp_path / "ws")).scan(
        ScanContext(job=job, workspace=workspace, artifact_path=apk)
    )
    secret_types = [ev.data.get("secret_type") for item in findings for ev in item.evidence]
    assert "stripe_key" not in secret_types
    google = [item for item in findings if any(ev.data.get("secret_type") == "google_api_key" for ev in item.evidence)]
    for item in google:
        assert item.severity is Severity.INFO
        assert item.verification is Verification.INFO
    assert not any(item.severity is Severity.CRITICAL for item in findings)


@pytest.mark.asyncio
async def test_http_endpoint_is_informational(tmp_path: Path) -> None:
    apk = write_apk(
        tmp_path / "app.apk",
        extra_files={"assets/config.json": b'{"api":"http://api.testhost.invalid/v1/login"}'},
    )
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="s3",
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    findings = await SecretScanner(Settings(workspace_dir=tmp_path / "ws")).scan(
        ScanContext(job=job, workspace=workspace, artifact_path=apk)
    )
    http = [item for item in findings if item.rule_id == "http_endpoint"]
    assert http
    assert http[0].severity is Severity.INFO


def test_redaction_helper() -> None:
    redacted = redact_secret(STRIPE_LIVE)
    assert STRIPE_LIVE not in redacted
    assert redacted.startswith("sk_live_")
    assert redacted.endswith("1234")
