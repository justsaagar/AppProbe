"""Third-party SDK / library detection. Does not invent CVEs."""

from __future__ import annotations

import zipfile
from pathlib import Path

from app.analyzers.findings import normalize_finding
from app.models.enums import (
    ArtifactKind,
    FindingCategory,
    Platform,
    Severity,
    Verification,
)
from app.models.finding import Evidence, Finding
from app.scanners.base import ScanContext, Scanner
from app.utils.paths import UnsafePathError, assert_relative_zip_entry

SOURCE = "dependency-scanner"

# Path/package signatures that identify well-known SDKs. Informational only.
SDK_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Firebase", ("com/google/firebase", "com.google.firebase", "google-services.json", "firebase-")),
    ("Google Play services", ("com/google/android/gms", "com.google.android.gms")),
    ("Google Maps", ("com/google/android/gms/maps", "com.google.android.gms.maps")),
    ("Stripe", ("com/stripe", "com.stripe", "stripe-android")),
    ("RevenueCat", ("com/revenuecat", "com.revenuecat", "purchases-android")),
    ("OkHttp", ("okhttp3/", "okhttp3.", "/okhttp/")),
    ("Retrofit", ("retrofit2/", "retrofit2.")),
    ("Gson", ("com/google/gson", "com.google.gson")),
    ("Glide", ("com/bumptech/glide", "com.bumptech.glide")),
    ("Picasso", ("com/squareup/picasso", "com.squareup.picasso")),
    ("Coil", ("coil/", "io.coil-kt")),
    ("Facebook SDK", ("com/facebook", "com.facebook.FacebookSdk")),
    ("Crashlytics", ("com/google/firebase/crashlytics", "firebase-crashlytics")),
    ("Sentry", ("io/sentry", "io.sentry")),
    ("Branch", ("io/branch", "io.branch.referral")),
    ("Adjust", ("com/adjust/sdk", "com.adjust.sdk")),
    ("Amplitude", ("com/amplitude", "com.amplitude")),
    ("Mixpanel", ("com/mixpanel", "com.mixpanel.android")),
    ("WebView / Chromium bits", ("android/webkit", "android.webkit.WebView")),
    ("Kotlin stdlib", ("kotlin/", "kotlin.jvm")),
    ("AndroidX", ("androidx/", "androidx.")),
)


class DependencyScanner(Scanner):
    name = "dependency-scanner"
    description = "Detect embedded SDKs and libraries from package paths"

    def supports(self, context: ScanContext) -> bool:
        return context.job.platform is Platform.ANDROID

    async def scan(self, context: ScanContext) -> list[Finding]:
        haystack = self._haystack(context)
        detected: list[tuple[str, str]] = []
        for name, signatures in SDK_SIGNATURES:
            hit = next((sig for sig in signatures if sig.lower() in haystack), None)
            if hit:
                detected.append((name, hit))
        findings = [_sdk_finding(name, evidence, context) for name, evidence in detected]
        if context.job.artifact_kind in {ArtifactKind.APK, ArtifactKind.AAB}:
            findings.append(_no_cve_notice())
        return findings


    def _haystack(self, context: ScanContext) -> str:
        parts: list[str] = []
        parts.extend(self._zip_names(context.artifact_path))
        for key in ("jadx_source_dir", "apktool_decoded_dir"):
            raw = context.extras.get(key)
            if not raw:
                continue
            root = Path(raw)
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    rel = path.relative_to(root).as_posix()
                except ValueError:
                    continue
                parts.append(rel)
                if len(parts) > 20000:
                    break
        if context.metadata:
            parts.extend(context.metadata.native_libraries)
            parts.extend(context.metadata.permissions)
        return "\n".join(parts).lower()

    def _zip_names(self, path: Path) -> list[str]:
        names: list[str] = []
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    try:
                        names.append(assert_relative_zip_entry(info.filename))
                    except UnsafePathError:
                        continue
                    if len(names) > 20000:
                        break
        except zipfile.BadZipFile:
            return names
        return names


def _sdk_finding(name: str, evidence: str, context: ScanContext) -> Finding:
    return normalize_finding(
        source=SOURCE,
        rule_id="sdk_detected",
        title=f"{name} SDK detected",
        category=FindingCategory.DEPENDENCY,
        severity=Severity.INFO,
        confidence=0.9,
        description=(
            f"{name} appears to be embedded in the application (matched `{evidence}`). "
            "Dependency detected; vulnerability version verification not available in this milestone."
        ),
        impact="Third-party code expands attack surface; this finding is informational only.",
        recommendation="Inventory SDKs, keep them updated, and remove unused vendors.",
        evidence=[
            Evidence(
                kind="sdk",
                summary=f"signature `{evidence}`",
                location=context.job.filename,
                data={"sdk": name, "signature": evidence},
            )
        ],
        affected_component=name,
        reproducibility="Static path/package signature match.",
        verification=Verification.INFO,
    )


def _no_cve_notice() -> Finding:
    return normalize_finding(
        source=SOURCE,
        rule_id="sdk_detected",
        title="Dependency vulnerability version verification not available",
        category=FindingCategory.PROCESS,
        severity=Severity.INFO,
        confidence=1.0,
        description=(
            "No vulnerability database is integrated in Milestone 2. Detected SDKs are not "
            "classified as vulnerable merely because they are present or appear old. CVEs are not invented."
        ),
        evidence=[
            Evidence(
                kind="process",
                summary="No CVE/version database configured",
            )
        ],
        affected_component="dependencies",
        reproducibility="N/A — pipeline limitation.",
        verification=Verification.INFO,
    )
