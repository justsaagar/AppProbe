"""Dependency/SDK scanner tests. Fixtures use harmless package paths only."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.enums import ArtifactKind, Platform, Severity, Verification
from app.models.scan_job import ScanJob
from app.reporters.markdown import MarkdownReporter
from app.scanners.base import ScanContext
from app.scanners.dependencies import DependencyScanner
from app.storage.workspace import ScanWorkspace
from tests.helpers import write_apk


async def _scan(
    tmp_path: Path,
    extra_files: dict[str, bytes],
    *,
    scan_id: str = "dep",
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
    context = ScanContext(job=job, workspace=workspace, artifact_path=apk, extras=extras or {})
    findings = await DependencyScanner().scan(context)
    return findings, context


def _names(findings) -> set[str]:
    return {
        item.affected_component
        for item in findings
        if item.affected_component and item.affected_component != "dependencies"
    }


def _record(context: ScanContext, name: str):
    inventory = context.extras.get("technology_inventory") or []
    return next((item for item in inventory if item.name == name), None)


@pytest.mark.asyncio
async def test_flutter_artifacts_detected_and_version_unknown(tmp_path: Path) -> None:
    findings, context = await _scan(
        tmp_path,
        {
            "lib/arm64-v8a/libflutter.so": b"\x7fELF",
            "assets/flutter_assets/AssetManifest.json": b"{}",
        },
        scan_id="flutter",
    )
    assert "Flutter" in _names(findings)
    record = _record(context, "Flutter")
    assert record is not None
    assert record.version is None
    assert record.version_label == "Unknown"
    assert record.confidence >= 0.99
    assert record.category == "FRAMEWORK"
    flutter = next(item for item in findings if item.affected_component == "Flutter")
    assert flutter.severity is Severity.INFO
    assert "framework detected" in flutter.title.lower()


@pytest.mark.asyncio
async def test_flutter_false_positive_string_not_detected(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {"assets/readme.txt": b"This app mentions flutter maps stripe dio react firebase\n"},
        scan_id="flutter-fp",
    )
    names = _names(findings)
    assert "Flutter" not in names
    assert "Stripe SDK" not in names
    assert "Dio" not in names
    assert "React Native" not in names
    assert "Firebase" not in names
    assert "Google Maps" not in names


@pytest.mark.asyncio
async def test_firebase_components_and_generic(tmp_path: Path) -> None:
    findings, context = await _scan(
        tmp_path,
        {
            "com/google/firebase/FirebaseApp.class": b"dummy",
            "com/google/firebase/auth/FirebaseAuth.class": b"dummy",
            "com/google/firebase/messaging/FirebaseMessaging.class": b"dummy",
            "com/google/firebase/analytics/FirebaseAnalytics.class": b"dummy",
            "com/google/firebase/firestore/FirebaseFirestore.class": b"dummy",
            "google-services.json": b'{"project_info":{"project_id":"demo"}}',
        },
        scan_id="firebase",
    )
    names = _names(findings)
    assert "Firebase" in names
    assert "Firebase Auth" in names
    assert "Firebase Messaging" in names
    assert "Firebase Analytics" in names
    assert "Firebase Firestore" in names
    assert "Google Play Services" not in names


@pytest.mark.asyncio
async def test_duplicate_firebase_evidence_is_merged(tmp_path: Path) -> None:
    jadx = tmp_path / "jadx"
    (jadx / "sources/com/google/firebase/messaging").mkdir(parents=True)
    (jadx / "sources/com/google/firebase/messaging/FirebaseMessaging.java").write_text(
        "package com.google.firebase.messaging;\n", encoding="utf-8"
    )
    apktool = tmp_path / "apktool"
    (apktool / "smali/com/google/firebase/messaging").mkdir(parents=True)
    (apktool / "smali/com/google/firebase/messaging/FirebaseMessaging.smali").write_text(
        ".class Lcom/google/firebase/messaging/FirebaseMessaging;\n", encoding="utf-8"
    )
    findings, context = await _scan(
        tmp_path,
        {"com/google/firebase/messaging/FirebaseMessaging.class": b"dummy"},
        scan_id="merge",
        extras={"jadx_source_dir": str(jadx), "apktool_decoded_dir": str(apktool)},
    )
    messaging = [item for item in findings if item.affected_component == "Firebase Messaging"]
    assert len(messaging) == 1
    record = _record(context, "Firebase Messaging")
    assert record is not None
    assert {"APK entries", "JADX", "apktool"} <= set(record.sources)
    coverage = context.extras["dependency_scan_coverage"]
    assert "APK entries" in coverage.sources
    assert "JADX output" in coverage.sources
    assert "apktool output" in coverage.sources


@pytest.mark.asyncio
async def test_google_maps_places_billing_signin(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "com/google/android/gms/maps/GoogleMap.class": b"dummy",
            "com/google/android/libraries/places/Places.class": b"dummy",
            "com/android/billingclient/api/BillingClient.class": b"dummy",
            "com/google/android/gms/auth/api/signin/GoogleSignIn.class": b"dummy",
        },
        scan_id="google",
    )
    names = _names(findings)
    assert "Google Maps" in names
    assert "Google Places" in names
    assert "Google Play Billing" in names
    assert "Google Sign-In" in names


@pytest.mark.asyncio
async def test_payments_stripe_and_revenuecat(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "com/stripe/android/Stripe.class": b"dummy",
            "com/revenuecat/purchases/Purchases.class": b"dummy",
        },
        scan_id="pay",
    )
    names = _names(findings)
    assert "Stripe SDK" in names
    assert "RevenueCat" in names


@pytest.mark.asyncio
async def test_networking_okhttp_retrofit_dio(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "okhttp3/OkHttpClient.class": b"dummy",
            "retrofit2/Retrofit.class": b"dummy",
            "assets/flutter_assets/packages/dio/lib/dio.dart": b"// dio package marker\n",
        },
        scan_id="net",
    )
    names = _names(findings)
    assert "OkHttp" in names
    assert "Retrofit" in names
    assert "Dio" in names


@pytest.mark.asyncio
async def test_analytics_sdks(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "com/appsflyer/AppsFlyerLib.class": b"dummy",
            "com/mixpanel/android/mpmetrics/MixpanelAPI.class": b"dummy",
            "com/onesignal/OneSignal.class": b"dummy",
            "com/amplitude/api/Amplitude.class": b"dummy",
        },
        scan_id="analytics",
    )
    names = _names(findings)
    assert "AppsFlyer" in names
    assert "Mixpanel" in names
    assert "OneSignal" in names
    assert "Amplitude" in names


@pytest.mark.asyncio
async def test_mapbox_detected(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {
            "com/mapbox/maps/MapView.class": b"dummy",
            "lib/arm64-v8a/libmapbox-gl.so": b"\x7fELF",
        },
        scan_id="mapbox",
    )
    assert "Mapbox" in _names(findings)


@pytest.mark.asyncio
async def test_native_library_detection_and_platform_exclusion(tmp_path: Path) -> None:
    findings, context = await _scan(
        tmp_path,
        {
            "lib/arm64-v8a/libssl.so": b"\x7fELF",
            "lib/arm64-v8a/libcrypto.so": b"\x7fELF",
            "lib/arm64-v8a/libc.so": b"\x7fELF",
            "lib/arm64-v8a/liblog.so": b"\x7fELF",
        },
        scan_id="native",
    )
    names = _names(findings)
    assert "OpenSSL" in names
    inventory_names = {item.name for item in context.extras["technology_inventory"]}
    assert "libc.so" not in inventory_names
    assert not any("liblog" in (item.name.lower()) for item in context.extras["technology_inventory"])


@pytest.mark.asyncio
async def test_version_detected_unknown_and_invalid_ignored(tmp_path: Path) -> None:
    pom = "groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.12.0\n"
    bad = "groupId=com.squareup.retrofit2\nartifactId=retrofit\nversion=latest\n"
    findings, context = await _scan(
        tmp_path,
        {
            "okhttp3/OkHttpClient.class": b"dummy",
            "retrofit2/Retrofit.class": b"dummy",
            "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties": pom.encode(),
            "META-INF/maven/com.squareup.retrofit2/retrofit/pom.properties": bad.encode(),
        },
        scan_id="ver",
    )
    okhttp = _record(context, "OkHttp")
    retrofit = _record(context, "Retrofit")
    assert okhttp is not None and okhttp.version == "4.12.0"
    assert okhttp.version_confidence >= 0.98
    assert retrofit is not None and retrofit.version is None
    assert "4.12.0" in " ".join(item.description for item in findings if item.affected_component == "OkHttp")
    assert "CVE-" not in "".join(item.title for item in findings)


@pytest.mark.asyncio
async def test_evidence_source_path_and_confidence(tmp_path: Path) -> None:
    findings, context = await _scan(
        tmp_path,
        {"okhttp3/OkHttpClient.class": b"dummy"},
        scan_id="ev",
    )
    record = _record(context, "OkHttp")
    assert record is not None
    assert record.evidence
    assert record.evidence[0].location
    assert record.confidence >= 0.9
    finding = next(item for item in findings if item.affected_component == "OkHttp")
    assert finding.evidence
    assert finding.verification is Verification.INFO
    assert finding.severity is Severity.INFO


@pytest.mark.asyncio
async def test_works_with_only_raw_apk(tmp_path: Path) -> None:
    findings, context = await _scan(
        tmp_path,
        {"okhttp3/OkHttpClient.class": b"dummy"},
        scan_id="raw-only",
    )
    assert "OkHttp" in _names(findings)
    assert context.extras["dependency_scan_coverage"].sources == ["APK entries", "DEX"]


@pytest.mark.asyncio
async def test_no_cve_lookup_language_and_info_severity(tmp_path: Path) -> None:
    findings, _ = await _scan(
        tmp_path,
        {"okhttp3/OkHttpClient.class": b"dummy"},
        scan_id="cve",
    )
    assert all(item.severity is Severity.INFO for item in findings)
    assert all(item.verification is Verification.INFO for item in findings)
    assert any("NOT EXECUTED" in item.title for item in findings)
    assert any("vulnerability version verification not available" in item.description.lower() for item in findings)
    blob = "\n".join(item.title + item.description for item in findings)
    assert "CVE-202" not in blob


def test_scanner_module_has_no_network_client_imports() -> None:
    import app.scanners.dependencies as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("urllib", "requests", "httpx", "aiohttp", "socket.create_connection"):
        assert banned not in source
    sig_source = Path(mod.__file__).with_name("tech_signatures.py").read_text(encoding="utf-8")
    for banned in ("nvd.nist", "osv.dev", "snyk.io"):
        assert banned not in sig_source


@pytest.mark.asyncio
async def test_manual_inventory_report_section(tmp_path: Path) -> None:
    findings, context = await _scan(
        tmp_path,
        {
            "lib/arm64-v8a/libflutter.so": b"\x7fELF",
            "assets/flutter_assets/AssetManifest.json": b"{}",
            "com/google/firebase/auth/FirebaseAuth.class": b"dummy",
            "okhttp3/OkHttpClient.class": b"dummy",
            "com/stripe/android/Stripe.class": b"dummy",
            "com/appsflyer/AppsFlyerLib.class": b"dummy",
            "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties": (
                b"groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.12.0\n"
            ),
        },
        scan_id="manual",
    )
    job = context.job
    job.findings = findings
    job.technology_inventory = context.extras["technology_inventory"]
    job.dependency_scan_coverage = context.extras["dependency_scan_coverage"]
    markdown = MarkdownReporter().render(job)
    assert "## Technology & Dependency Inventory" in markdown
    assert "Flutter" in markdown
    assert "Firebase Auth" in markdown
    assert "OkHttp" in markdown
    assert "4.12.0" in markdown
    assert "Stripe SDK" in markdown
    assert "NOT EXECUTED" in markdown
    assert "CVE-202" not in markdown
    assert "Unknown" in markdown
