# AppProbe

Local-first AI-powered mobile application testing and security analysis platform.

The LLM is a reasoning and reporting layer. Deterministic scanners perform the
actual analysis. This repository is at **Milestone 2.9**: premium web dashboard
on top of the existing static-analysis backend.

Runtime testing, network interception, LLM analysis, emulator/ADB, and dynamic
security testing are **not** implemented and are **not faked**.

## Milestone 2.9 — web dashboard

- Dark-first React + TypeScript + Vite + Tailwind UI
- Upload an APK, watch live scanner progress, and inspect findings
- Correlation summary, technology inventory, scanner coverage, Markdown download
- Backend remains the source of truth; the UI does not recalculate severity

See [docs/milestone-2-9.md](docs/milestone-2-9.md).

## Milestone 2.8 — MobSF static analysis adapter

- Optional REST integration (`MOBSF_ENABLED=false` by default)
- Upload / scan / bounded poll / JSON report / cleanup
- Normalizes MobSF issues into AppProbe `Finding` records
- Distinguishes NOT ENABLED, NOT AVAILABLE, AUTH FAILED, TIMEOUT, FAILED
- Does **not** replace AppProbe scanners and does **not** run dynamic analysis

See [docs/milestone-2-8.md](docs/milestone-2-8.md).

## Milestone 2.7 — cross-scanner finding correlation

- Detects exact duplicate findings across scanners using structured keys
- Groups related issues (cleartext + HTTP, inventory + advisory) without
  hiding distinct vulnerabilities
- Merges evidence, reconciles severity/confidence, and assigns `CORR-NNN` IDs
- Correlation is deterministic and does not use AI
- When evidence is insufficient, findings remain separate

See [docs/milestone-2-7.md](docs/milestone-2-7.md).

## Milestone 2.6 — vulnerability / advisory scanner

- Consumes the Milestone 2.5 technology inventory
- Maps known technologies to Maven (and, when reliable, Pub) coordinates
- Queries the official OSV API for known package/version pairs only
- Creates findings only when the installed version is in an affected range
- Records COMPLETE / INCOMPLETE / NOT_AVAILABLE — a failed lookup is not “safe”
- Does **not** exploit vulnerabilities or validate exploitability

See [docs/milestone-2-6.md](docs/milestone-2-6.md).

## Milestone 2.5 — dependency and SDK scanner

- Detects recognizable frameworks, SDKs, and libraries from package paths,
  native libraries, Maven metadata, and Flutter package assets
- Records versions only when evidence exists; otherwise Version is Unknown
- Emits informational technology findings — **not** vulnerabilities
- Does **not** call NVD/OSV/Snyk or assign CVEs
- Merges duplicate evidence from APK / JADX / apktool into one inventory row

See [docs/milestone-2-5.md](docs/milestone-2-5.md).

## Milestone 2.4 — deterministic secret scanner

- Scans the raw APK and, when present, JADX and apktool output
- Detects private keys, cloud/API credentials, JWTs, bearer tokens, passwords,
  and credential-bearing database URLs
- Applies validation, confidence, severity, and redaction without an LLM
- Does **not** validate or exploit credentials and does **not** call the network
- Records secret-scan coverage (files scanned/skipped, bytes, sources)

See [docs/milestone-2-4.md](docs/milestone-2-4.md).

## Milestone 2.3 — apktool adapter

- Detects `apktool` (or `APKTOOL_BIN`) without hardcoded `/usr/bin` paths
- Runs through `ExternalToolExecutor` with timeouts and isolated output
- Writes decoded output to `workspace/scans/<scan-id>/tools/apktool/output/`
- Records EXECUTED / NOT AVAILABLE / FAILED / TIMEOUT / NOT EXECUTED in the report
- Does **not** emit security findings

See [docs/milestone-2-3.md](docs/milestone-2-3.md).

## Milestone 2.2 — JADX adapter

- Detects `jadx` / `jadx-cli` (or `JADX_BIN`) without hardcoded `/usr/bin` paths
- Runs through `ExternalToolExecutor` with timeouts and isolated output
- Writes decompiled output to `workspace/scans/<scan-id>/tools/jadx/output/`
- Records EXECUTED / NOT AVAILABLE / FAILED / TIMEOUT / NOT EXECUTED in the report
- Does **not** emit security findings (downstream scanners will consume the output)

See [docs/milestone-2-2.md](docs/milestone-2-2.md).

## Milestone 2.1 — external tool execution

- Safe executable discovery (`shutil.which`, configurable names, no hardcoded `/usr/bin`)
- Structured results: `AVAILABLE` / `NOT_AVAILABLE` / `EXECUTED` / `FAILED` / `TIMEOUT`
- Timeouts, stdout/stderr size limits, workspace-local working directories
- Argument arrays only (`shell=True` is never used)

See [docs/milestone-2-1.md](docs/milestone-2-1.md).

## Earlier capabilities

- Milestone 1: upload, validation, AXML metadata, manifest findings, `security-report.md`
- Optional scan-level tool coverage records when a binary is absent (`NOT_AVAILABLE`)

AAB files are inspected as bundles. They are **not** silently treated as
installable APKs. iOS IPA files are accepted and validated; dynamic iOS testing
requires a supported macOS/device environment and is not executed.

## Requirements

- Python 3.12+

Optional: JADX, apktool (Java), local MobSF REST (`MOBSF_ENABLED`, `MOBSF_URL`).
See [docs/milestone-2.md](docs/milestone-2.md) and
[docs/milestone-2-8.md](docs/milestone-2-8.md).

## Setup

```bash
cp .env.example .env
make setup
```

## Run the dashboard

1. Start the API: `make run` (http://127.0.0.1:8000)
2. Start the UI: `make web` or `cd frontend && npm install && npm run dev`
3. Open http://127.0.0.1:5173
4. Upload an APK and start a scan
5. Inspect findings, technologies, correlation, and the Markdown report

The Vite dev server proxies `/api` and `/health` to the FastAPI backend.

## Run the API

```bash
make run
```

- `POST /api/scans` — upload an artifact (returns a scan ID immediately)
- `GET  /api/config` — public upload limits and tool configuration flags
- `GET  /api/scans`
- `GET  /api/scans/{scan_id}`
- `GET  /api/scans/{scan_id}/findings`
- `GET  /api/scans/{scan_id}/technologies`
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
[1/11] Validating artifact
[2/11] Extracting metadata
[3/11] Running manifest analysis
[4/11] MobSF - NOT ENABLED
[5/11] JADX - NOT AVAILABLE
[6/11] apktool - NOT AVAILABLE
[7/11] Running secret detection
[8/11] Running dependency analysis
[9/11] Running vulnerability assessment
[10/11] Correlating findings
[11/11] Generating report
Scan completed.
Report:
workspace/reports/<scan-id>/security-report.md
```

If JADX/apktool are installed, those lines show EXECUTED instead of NOT AVAILABLE.
If a local MobSF instance is enabled and reachable, MobSF shows EXECUTED instead
of NOT ENABLED / NOT AVAILABLE.
Runtime/AI stages are omitted from the CLI counter and recorded as NOT EXECUTED in the report.

Equivalent:

```bash
cd backend && PYTHONPATH=. python -m app.cli scan ../workspace/samples/vulnerable-demo.apk
```

## Tests and lint

```bash
make test
make lint
make secrets-check
```

## Security notes

Uploaded binaries are untrusted:

- Isolated workspace per scan
- File size and extension checks
- ZIP path-traversal rejection
- Subprocess calls use argument arrays (no shell interpolation)
- Copy `.env.example` to `.env`; never commit `.env` or real credentials
- Test fixtures and the sample APK generator must use synthetic values only
- Generated APK/AAB artifacts, scan workspaces, and reports stay local
- Report generation redacts common credential patterns

See [docs/security.md](docs/security.md). Run `make secrets-check` before committing.

Do not run untrusted apps on the host. Runtime execution (Milestone 3+) belongs
in an emulator.

## Layout

See [docs/architecture.md](docs/architecture.md), [docs/milestone-1.md](docs/milestone-1.md),
[docs/milestone-2.md](docs/milestone-2.md), [docs/milestone-2-1.md](docs/milestone-2-1.md),
[docs/milestone-2-2.md](docs/milestone-2-2.md), [docs/milestone-2-3.md](docs/milestone-2-3.md),
and [docs/milestone-2-4.md](docs/milestone-2-4.md),
[docs/milestone-2-5.md](docs/milestone-2-5.md),
[docs/milestone-2-6.md](docs/milestone-2-6.md),
[docs/milestone-2-7.md](docs/milestone-2-7.md),
[docs/milestone-2-8.md](docs/milestone-2-8.md), and
[docs/milestone-2-9.md](docs/milestone-2-9.md).
