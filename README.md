# AppProbe

Local-first AI-powered mobile application testing and security analysis platform.

Milestone 1 provides Android-first static analysis: upload an APK (or AAB/IPA), validate it, extract metadata from the Android manifest, produce normalized findings, and generate `security-report.md`.

The LLM is **not** used in Milestone 1. Deterministic scanners perform the analysis. Runtime/emulator, MobSF, JADX, apktool, bundletool, network interception, and AI reasoning are scaffolded but explicitly reported as **not executed**.

## Layout

```
backend/                 FastAPI application (independent of any UI)
frontend/                Dashboard placeholder (Milestone 7)
workspace/               Isolated per-scan uploads, artifacts, reports
scripts/
docker/
docs/
```

## Requirements

- Python 3.12+
- pip

No Android SDK, emulator, or MobSF installation is required for Milestone 1.

## Setup

```bash
make setup
```

This installs `backend/requirements.txt`. Copy `.env.example` to `.env` if you want to override workspace paths or size limits. Do not put real API keys in the repository.

## Run the API

```bash
make run
```

The server listens on `http://127.0.0.1:8000`.

- `POST /api/scans` — upload APK/AAB/IPA, returns a scan ID immediately (`202`)
- `GET  /api/scans`
- `GET  /api/scans/{scan_id}` — status and progress
- `GET  /api/scans/{scan_id}/findings`
- `GET  /api/scans/{scan_id}/report`
- `GET  /api/scans/{scan_id}/artifacts`
- `POST /api/scans/{scan_id}/cancel`
- `GET  /health`

Long-running analysis does not block the upload response.

## CLI

```bash
make scan FILE=./example.apk
```

or, from the repo root:

```bash
PYTHONPATH=backend python -m app.cli scan ./example.apk
```

Expected progress:

```
[1/8] Validating artifact
[2/8] Extracting metadata
[3/8] Running static analysis
[4/8] Preparing Android runtime
[5/8] Running dynamic analysis
[6/8] Correlating findings
[7/8] Running AI analysis
[8/8] Generating report
Scan completed.
Report:
workspace/reports/<scan-id>/security-report.md
```

Stages 4, 5, and 7 are recorded as skipped. The report states `Runtime Testing: NOT EXECUTED` with the reason `Android Emulator unavailable`. AI analysis is not implemented and does not invent findings.

## Tests

```bash
make test
make lint
```

Tests build synthetic APK/AAB/IPA fixtures. They do not use production applications or real credentials.

## What Milestone 1 actually does

For **APK**:

- ZIP/APK structure validation (magic bytes, zip-slip rejection, size limits)
- `AndroidManifest.xml` extraction (binary AXML or text XML)
- Package name, version, versionCode, minSdk, targetSdk
- Permissions, activities, services, receivers, providers
- Deterministic findings for debuggable builds, cleartext traffic, backup, exported components, dangerous permissions (informational), native library presence, Firebase config presence

For **AAB**:

- Bundle structure inspection
- Metadata from `base/manifest/AndroidManifest.xml` when present
- Explicit note that bundletool was **not** used and the AAB is **not** an installable APK

For **IPA**:

- Payload validation and Info.plist metadata when present
- Explicit status: dynamic iOS testing requires a supported macOS/device environment

## What Milestone 1 does not do

- MobSF, JADX, apktool, secret scanning of decompiled code, dependency CVE matching
- Android emulator, ADB install/launch, UI exploration, logcat, screenshots
- Network interception / mitmproxy
- LLM severity or report generation
- Frontend dashboard

See `docs/milestones.md` for the remaining roadmap.

## Security notes

Uploaded binaries are treated as untrusted:

- isolated workspace per scan
- extension and ZIP validation
- path traversal protection
- subprocess helper uses argument arrays only (`shell=False`)
- secrets in reports are redacted
- emulator/runtime isolation is deferred until Milestone 3
