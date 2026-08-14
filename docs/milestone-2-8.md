# Milestone 2.8 — MobSF Static Analysis Adapter

## Status

MobSF is an optional static-analysis provider.

AppProbe does not depend on MobSF being available.

MobSF findings are normalized into AppProbe's Finding model.

MobSF does not replace AppProbe's deterministic scanners.

Dynamic analysis is NOT part of Milestone 2.8.

## Pipeline position

```text
AppProbe
   |
   +-- Manifest Scanner
   +-- JADX
   +-- apktool
   +-- Secret Scanner
   +-- Dependency Scanner
   +-- Vulnerability Scanner
   +-- MobSF
   |
   v
Correlation
   |
   v
Final Report
```

MobSF is another evidence-producing scanner. It is not the source of truth
for the AppProbe report.

## Architecture

```text
MobsfTool
    |
    v
MobSFClient
    |
    +-- health  GET  /api/v1/scans
    +-- upload  POST /api/v1/upload
    +-- scan    POST /api/v1/scan
    +-- status  POST /api/v1/scan_logs
    +-- report  POST /api/v1/report_json
    +-- cleanup POST /api/v1/delete_scan
```

The scanner depends on `MobSFClient`, not scattered HTTP calls. The HTTP
implementation talks only to the configured MobSF origin using the REST API.
It does not scrape the web UI or automate a browser.

If `/api/v1/scan` returns a structured report immediately, AppProbe uses it.
Otherwise it polls `/api/v1/report_json` until completion, failure, or
`MOBSF_MAX_WAIT_SECONDS`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MOBSF_ENABLED` | `false` | Master switch. AppProbe works when this is false. |
| `MOBSF_URL` | empty | Trusted base URL, for example `http://127.0.0.1:8000` |
| `MOBSF_API_KEY` | empty | REST API key (credential) |
| `MOBSF_TIMEOUT_SECONDS` | `30` | Per-request HTTP timeout |
| `MOBSF_POLL_INTERVAL_SECONDS` | `2` | Polling interval |
| `MOBSF_MAX_WAIT_SECONDS` | `180` | Bounded wait for scan completion |
| `MOBSF_MAX_RESPONSE_BYTES` | `8 MiB` | Response size cap |

The URL must come from application configuration. Per-scan URLs from uploaded
content are rejected. Redirects are not followed to other hosts. There is no
hardcoded public MobSF service.

## API key handling

`MOBSF_API_KEY` is a credential. It is never committed, logged, placed in
findings, included in exceptions, printed as HTTP headers, or written into
Markdown. `.env.example` may contain `MOBSF_API_KEY=` with an empty value.

## Availability states

| State | Meaning |
| --- | --- |
| `NOT ENABLED` | `MOBSF_ENABLED=false` |
| `NOT AVAILABLE` | Enabled, but the server is unreachable or unconfigured |
| `AUTH FAILED` | The configured API key was rejected |
| `NOT EXECUTED` | Artifact is not an APK (AAB/IPA in this milestone) |
| `EXECUTED` | Static analysis completed and findings were imported |
| `FAILED` | Upload, scan, or report failed |
| `TIMEOUT` | Bounded wait expired |

Disabled is not the same as unavailable. A MobSF failure never fails the
overall AppProbe scan.

An unavailable or malformed report is **not** treated as zero vulnerabilities.

## Upload, scan, polling, cleanup

1. Upload the original APK unchanged.
2. Start static analysis (`/api/v1/scan`). Dynamic MobSF endpoints are not used.
3. Poll until a JSON report is available, the scan fails, or the wait expires.
4. Normalize findings. Do not keep the complete MobSF JSON.
5. Delete the remote scan if the API supports it. Cleanup failure is a warning
   and does not mark a successful analysis as failed.

Only `scan_id` and status are logged. APK contents are not logged.

## Normalization

MobSF issues become AppProbe `Finding` records with `source=mobsf`. Severity
maps onto `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`. MobSF `WARNING`
maps to `MEDIUM`. Unknown high-severity items are capped at `MEDIUM` so every
MobSF observation is not automatically HIGH.

Confidence is taken from MobSF when present and otherwise assigned
conservatively by finding type (for example 0.7 for manifest, 0.55 for code,
0.4 for secrets). Values of `0.99` are not invented.

CVE, CWE, MASVS, and rule identifiers are preserved on the Finding and in
verification evidence when MobSF supplies them. Secret-like strings are
redacted.

## Correlation

Imported MobSF findings enter `job.raw_findings` with every other scanner and
pass through the existing correlation engine. There is no MobSF-specific
deduplicator. Unrelated findings stay separate.

## Report

The Markdown report includes `## MobSF Analysis` with status, version,
findings imported, correlated findings, duration, availability, and
limitations. The tool table records MobSF coverage. The API key, raw HTTP
headers, complete MobSF JSON, and complete secrets are never included.

If MobSF does not expose a version through a supported JSON field, the report
records `Version: Unknown`.

## Limitations

- APK only. AAB and IPA are `NOT EXECUTED`.
- Static REST integration only.
- No Android emulator, ADB, Frida, runtime instrumentation, or traffic
  interception.
- No UI scraping.
- AppProbe scanners remain authoritative for deterministic checks.
