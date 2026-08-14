# Architecture (Milestone 2)

AppProbe is a local-first mobile application QA and security analysis platform.
The LLM is a later reasoning layer. Deterministic tools own analysis.

## Repository layout

```
backend/app/
  api/          HTTP routes (FastAPI)
  models/       ScanJob, Finding, enumerations, state machine
  schemas/      API response models
  services/     ScanService + ScanOrchestrator
  scanners/     Manifest, secret, dependency scanners + tools/ adapters
  tools/        External executable discovery + safe process execution
  analyzers/    AXML parser, validator, metadata, severity, correlation
  reporters/    Markdown report generator
  runners/      RuntimeRunner interface (unused until Milestone 3)
  agents/       Reserved for UI exploration (Milestone 4)
  storage/      Isolated workspaces + JSON job store
  utils/        Safe paths, subprocess wrapper, redaction
```

## Scan pipeline (Milestone 2)

1. Validate ZIP/APK/AAB/IPA structure
2. Extract metadata (Milestone 1 AXML parser remains authoritative)
3. Manifest scanner
4. MobSF adapter (skipped if unavailable)
5. JADX adapter (skipped if unavailable)
6. apktool adapter (skipped if unavailable)
7. Secret detector (APK entries, JADX/apktool output when present)
8. Dependency / SDK detector
9. Deterministic correlation
10. Record runtime / dynamic / AI as **NOT EXECUTED**
11. Write `workspace/reports/<scan-id>/security-report.md`

Raw tool output is stored under `workspace/scans/<id>/tools/` and
`workspace/scans/<id>/findings/raw-findings.json`.

## External tool execution (Milestone 2.1)

`app.tools` is the reusable process layer: `ToolDefinition`,
`resolve_executable`, `ExternalToolExecutor`, and `ToolExecutionResult`.

Statuses: `AVAILABLE`, `NOT_AVAILABLE`, `EXECUTED`, `FAILED`, `TIMEOUT`.

External tool execution infrastructure is implemented. See
[docs/milestone-2-1.md](milestone-2-1.md).

## JADX adapter (Milestone 2.2)

`JadxTool` uses `ToolDefinition` + `ExternalToolExecutor`. It decompiles APKs
into `workspace/scans/<id>/tools/jadx/output/`.

JADX output is generated for downstream analysis. No security findings are
generated directly by the JADX adapter. See
[docs/milestone-2-2.md](milestone-2-2.md).

## apktool adapter (Milestone 2.3)

`ApktoolTool` uses `ToolDefinition` + `ExternalToolExecutor`. It decodes APKs
into `workspace/scans/<id>/tools/apktool/output/`.

apktool provides decoded application artifacts for downstream analysis.
The apktool adapter itself does not generate security findings. See
[docs/milestone-2-3.md](milestone-2-3.md).

## Finding model

Normalized `Finding` records include `source`, `sources` (after merge),
`rule_id`, `verification` (`CONFIRMED` / `POTENTIAL` / `INFO`), evidence, and
optional CWE/OWASP/MASVS mappings that are only set when known.

## What is intentionally not implemented

| Area | Status |
| --- | --- |
| Android emulator, ADB, logcat | Milestone 3 |
| UI exploration / functional tests | Milestone 4 |
| Network interception | Milestone 5 |
| LLM analysis | Milestone 6 |
| Dashboard UI, full AAB install path | Milestone 7 |
