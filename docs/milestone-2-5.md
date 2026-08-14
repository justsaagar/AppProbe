# Milestone 2.5 — Dependency & SDK scanner

## Status

Dependency and SDK detection is informational in Milestone 2.5.

A detected dependency is NOT automatically considered vulnerable.

CVE/advisory database integration is intentionally deferred.

## Pipeline position

```text
Artifact validation
        ↓
Metadata
        ↓
Manifest scanner
        ↓
JADX
        ↓
apktool
        ↓
Secret scanner
        ↓
Dependency / SDK scanner
        ↓
Report
```

The scanner inspects whichever local artifacts are available:

- APK entries (always, for Android APK/AAB)
- DEX strings (bounded extraction from `classes*.dex`)
- JADX output under `tools/jadx/output/` when JADX executed
- apktool output under `tools/apktool/output/` when apktool executed

If JADX and/or apktool are unavailable, the scan continues using the raw APK.

## What is detected

High-confidence package, native-library, APK-entry, Maven coordinate, and
Flutter-package evidence is used. Free-text keywords in README or application
strings are not treated as dependencies.

| Category | Examples |
| --- | --- |
| FRAMEWORK | Flutter, React Native |
| AUTHENTICATION | Firebase Auth, Google Sign-In |
| MESSAGING | Firebase Messaging, OneSignal |
| ANALYTICS | Firebase Analytics, AppsFlyer, Mixpanel, Amplitude, Adjust, Facebook SDK |
| PAYMENT | Stripe SDK, RevenueCat, Google Play Billing |
| NETWORKING | OkHttp, Retrofit, Volley, Ktor, Dio, Dart http, Chopper |
| MAPS | Google Maps, Google Places, Mapbox |
| SDK | Firebase, Google Play Services, ML Kit, Firebase Crashlytics/Storage/Remote Config |
| DATABASE | Firebase Firestore, SQLite |
| CRYPTOGRAPHY | OpenSSL (bundled native libs) |
| OTHER | Android WebView (platform), Flutter WebView, React Native WebView |

Firebase components are reported individually when package evidence identifies
them. They are not collapsed into a generic Google Play Services row.

## Version detection

Versions are recorded only from evidence such as Maven `pom.properties` or a
library `BuildConfig` constant.

- Known version → stored with a version confidence (for example 0.98 for Maven metadata)
- Unknown version → `Unknown`
- Invalid values (`latest`, `unknown`, `null`, …) are ignored

The scanner does not guess the current/latest version and does not invent
versions from dates.

## Confidence

Each inventory record has a detection confidence in `[0.0, 1.0]`. Multiple
independent sources (APK path + JADX + apktool) slightly increase confidence.
Version confidence is tracked separately when a version is present.

## Evidence

Evidence is concise: a package path, native library name, or metadata file.
Large source excerpts are not stored.

## False-positive strategy

- Require package prefixes, native library names, Maven coordinates, Flutter
  `assets/flutter_assets/packages/<pkg>/` paths, or known resource files
- Do not match `stripe` / `firebase` / `dio` / `react` in arbitrary text
- `com/facebook/react` is React Native, not Facebook SDK
- Standard Android system libraries (`libc.so`, `liblog.so`, …) are not reported
  as third-party dependencies
- Flutter requires `libflutter.so`, `assets/flutter_assets/`, or `io/flutter`
  artifacts — not `libapp.so` alone

## Deduplication

Local to this scanner: the same technology found in the APK, JADX tree, and
apktool tree becomes **one** inventory entry with merged evidence. Cross-scanner
correlation is out of scope (Milestone 2.7).

## Security assessment

```text
Dependency vulnerability assessment:
NOT EXECUTED
```

No NVD, OSV, Snyk, or GitHub Advisory calls are made. Detected versions are
recorded only. Security status is `NOT EVALUATED`.

## Report

The Markdown report includes:

- Dependency / SDK Scanner in the static analysis tool table
- **Dependency Scan Coverage** (counts and sources actually used)
- **Technology & Dependency Inventory** table
- The existing Dependencies / Technology Detection sections, with an explicit
  NOT EXECUTED CVE statement

## Limitations

- No CVE/advisory lookup
- No claim that an old library is vulnerable
- No attempt to reverse-engineer the entire Dart AOT snapshot
- Platform/system libraries are excluded from third-party inventory
- Detection is only as good as package/native/metadata evidence in the artifact
