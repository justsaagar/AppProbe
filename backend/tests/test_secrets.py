"""Secret-scanner tests using synthetic fixtures only.

Provider-shaped values needed to exercise detectors are assembled at runtime
from obviously fake components. Realistic production-style credentials are
never stored in the repository.
"""

from __future__ import annotations

import base64
import json
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

FAKE_STRIPE_KEY = "FAKE_STRIPE_KEY_FOR_APPPROBE_TEST_ONLY"
FAKE_PASSWORD = "FAKE_PASSWORD_FOR_SECURITY_TEST_ONLY"
FAKE_JWT = "FAKE_JWT_FOR_APPPROBE_TEST_ONLY"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _stripe_live() -> str:
    """Stripe-shaped detector input, assembled only at runtime."""
    marker = "APPPROBETESTONLYNOTAREALKEY"
    return "".join(("sk", "_", "live", "_", marker))


def _jwt() -> str:
    """Compact JWT built from synthetic JSON claims at test runtime."""
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


async def _scan(tmp_path: Path, extra_files: dict[str, bytes], scan_id: str = "s1"):
    apk = write_apk(tmp_path / "app.apk", extra_files=extra_files)
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id=scan_id,
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    return await SecretScanner(Settings(workspace_dir=tmp_path / "ws")).scan(
        ScanContext(job=job, workspace=workspace, artifact_path=apk)
    )


def _secret_types(findings) -> list[str]:
    return [ev.data.get("secret_type") for item in findings for ev in item.evidence]


@pytest.mark.asyncio
async def test_detects_stripe_jwt_private_key_and_password(tmp_path: Path) -> None:
    stripe = _stripe_live()
    token = _jwt()
    pem = _private_key_pem()
    assets = (
        f"key={stripe}\n"
        f"token={token}\n"
        f"{pem}\n"
        f'password="{FAKE_PASSWORD}"\n'
    ).encode()
    findings = await _scan(tmp_path, {"res/values/secrets.xml": assets})
    types = _secret_types(findings)
    assert "stripe_key" in types
    assert "jwt" in types
    assert "private_key" in types
    assert "password" in types
    stripe_finding = next(
        item for item in findings if any(ev.data.get("secret_type") == "stripe_key" for ev in item.evidence)
    )
    assert stripe_finding.severity is Severity.CRITICAL
    assert stripe_finding.verification is Verification.CONFIRMED
    assert stripe not in stripe_finding.evidence[0].summary
    assert "****" in stripe_finding.evidence[0].summary or "*" in stripe_finding.evidence[0].summary
    private = next(
        item for item in findings if any(ev.data.get("secret_type") == "private_key" for ev in item.evidence)
    )
    assert private.severity is Severity.CRITICAL
    assert "BEGIN PRIVATE KEY" in private.evidence[0].summary
    assert "APPPROBE_TEST_ONLY" not in private.evidence[0].summary


@pytest.mark.asyncio
async def test_skips_placeholder_and_firebase_public_config(tmp_path: Path) -> None:
    files = {
        "res/values/strings.xml": (
            f"key=FAKE_API_KEY_FOR_TESTING_ONLY\napi={FAKE_STRIPE_KEY}\n"
        ).encode(),
        "google-services.json": _firebase_json().encode(),
        "res/values/ids.xml": b"uuid=550e8400-e29b-41d4-a716-446655440000\nver=1.2.3",
    }
    findings = await _scan(tmp_path, files, scan_id="s2")
    secret_types = _secret_types(findings)
    assert "stripe_key" not in secret_types
    google = [item for item in findings if any(ev.data.get("secret_type") == "google_api_key" for ev in item.evidence)]
    for item in google:
        assert item.severity is Severity.INFO
        assert item.verification is Verification.INFO
    assert not any(item.severity is Severity.CRITICAL for item in findings)


@pytest.mark.asyncio
async def test_explicit_fake_literals_are_not_provider_secrets(tmp_path: Path) -> None:
    blob = (
        f"stripe={FAKE_STRIPE_KEY}\n"
        f"token={FAKE_JWT}\n"
        f"secret={FAKE_PASSWORD}\n"
    ).encode()
    findings = await _scan(tmp_path, {"assets/fakes.txt": blob}, scan_id="s4")
    types = set(_secret_types(findings))
    assert "stripe_key" not in types
    assert "jwt" not in types


@pytest.mark.asyncio
async def test_http_endpoint_is_informational(tmp_path: Path) -> None:
    findings = await _scan(
        tmp_path,
        {"assets/config.json": b'{"api":"http://api.testhost.invalid/v1/login"}'},
        scan_id="s3",
    )
    http = [item for item in findings if item.rule_id == "http_endpoint"]
    assert http
    assert http[0].severity is Severity.INFO


def test_redaction_helper() -> None:
    value = _stripe_live()
    redacted = redact_secret(value)
    assert value not in redacted
    assert redacted.startswith("".join(("sk", "_", "live", "_")))
    assert "*" in redacted
