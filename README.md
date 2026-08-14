# AppProbe

Local-first AI-powered mobile application testing and security analysis platform.

The LLM is a reasoning and reporting layer. Deterministic scanners perform the
actual analysis. This repository is at **Milestone 2.2**: JADX decompilation
adapter on the reusable external-tool executor.

Runtime testing, network interception, LLM analysis, and the dashboard are
**not** implemented and are **not faked**.

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

Optional: JADX, apktool (Java), MobSF REST (`MOBSF_URL`) or `mobsfscan`. See
[docs/milestone-2.md](docs/milestone-2.md).

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
[1/10] Validating artifact
[2/10] Extracting metadata
[3/10] Running manifest analysis
[4/10] MobSF - NOT AVAILABLE
[5/10] JADX - NOT AVAILABLE
[6/10] apktool - NOT AVAILABLE
[7/10] Running secret detection
[8/10] Running dependency analysis
[9/10] Correlating findings
[10/10] Generating report
Scan completed.
Report:
workspace/reports/<scan-id>/security-report.md
```

If JADX/apktool/MobSF are installed, those lines show EXECUTED instead of NOT AVAILABLE.
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
and [docs/milestone-2-2.md](docs/milestone-2-2.md).
