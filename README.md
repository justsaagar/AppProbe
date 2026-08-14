# AppProbe

Local-first AI-powered mobile application testing and security analysis platform.

The LLM is a reasoning and reporting layer. Deterministic scanners perform the
actual analysis. This repository is at **Milestone 1**: APK upload, manifest
metadata, normalized findings, and a Markdown security report.

Later milestones add MobSF/JADX, emulator runtime, UI exploration, network
analysis, AI correlation, and a dashboard. Those stages are **not faked**.

## Milestone 1 capabilities

- Upload APK (primary), AAB, or IPA
- Create a scan job and run analysis asynchronously
- Validate ZIP structure (including zip-slip protection)
- Extract Android package metadata from `AndroidManifest.xml`
- Static manifest checks (exported components, cleartext, debuggable, backup, dangerous permissions)
- Write `workspace/reports/<scan-id>/security-report.md`

AAB files are inspected as bundles. They are **not** silently treated as
installable APKs. iOS IPA files are accepted and validated; dynamic iOS testing
requires a supported macOS/device environment and is not executed.

## Requirements

- Python 3.12+

Optional later: Android SDK/emulator, bundletool, JADX, apktool, MobSF, an LLM API key.

## Setup

```bash
cp .env.example .env
make setup
```

## Run the API

```bash
make run
```

- `POST /api/scans` — upload an artifact (returns a scan ID immediately)
- `GET  /api/scans`
- `GET  /api/scans/{scan_id}`
- `GET  /api/scans/{scan_id}/findings`
- `GET  /api/scans/{scan_id}/report`
- `GET  /api/scans/{scan_id}/artifacts`
- `POST /api/scans/{scan_id}/cancel`

## CLI scan

```bash
python scripts/generate_sample_apk.py
make scan FILE=workspace/samples/vulnerable-demo.apk
```

Expected:

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

Stages 4–7 are skipped in Milestone 1 and recorded as NOT EXECUTED in the report.

Equivalent:

```bash
cd backend && PYTHONPATH=. python -m app.cli scan ../workspace/samples/vulnerable-demo.apk
```

## Tests and lint

```bash
make test
make lint
```

## Security notes

Uploaded binaries are untrusted:

- Isolated workspace per scan
- File size and extension checks
- ZIP path-traversal rejection
- Subprocess calls use argument arrays (no shell interpolation)
- API keys belong in `.env`, never in source
- Report generation redacts common credential patterns

Do not run untrusted apps on the host. Runtime execution (Milestone 3+) belongs
in an emulator.

## Layout

See [docs/architecture.md](docs/architecture.md) and [docs/milestone-1.md](docs/milestone-1.md).
