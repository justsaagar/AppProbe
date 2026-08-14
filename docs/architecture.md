# Architecture (Milestone 1)

AppProbe is a local-first mobile application QA and security analysis platform.
The LLM is a later reasoning layer. Deterministic tools own analysis.

## Repository layout

```
backend/app/
  api/          HTTP routes (FastAPI)
  models/       ScanJob, Finding, enumerations, state machine
  schemas/      API response models
  services/     ScanService + ScanOrchestrator
  scanners/     Pluggable Scanner interface + ManifestScanner
  analyzers/    AXML parser, validator, metadata, severity, AI stub
  reporters/    Markdown report generator
  runners/      RuntimeRunner interface (unused until Milestone 3)
  agents/       Reserved for UI exploration (Milestone 4)
  storage/      Isolated workspaces + JSON job store
  utils/        Safe paths, subprocess wrapper, redaction
```

## Scan pipeline (Milestone 1)

1. Validate ZIP/APK/AAB/IPA structure (size, magic, zip-slip, required entries)
2. Extract metadata from AndroidManifest.xml (AXML) or IPA Info.plist
3. Run the custom manifest scanner (permissions, exported components, flags)
4. Record runtime / dynamic / correlation / AI stages as **NOT EXECUTED**
5. Write `workspace/reports/<scan-id>/security-report.md`

## What is intentionally not implemented

| Area | Status |
| --- | --- |
| MobSF, JADX, apktool, bundletool | Milestone 2 |
| Secret / dependency scanners | Milestone 2 |
| Finding correlation | Milestone 2 |
| Android emulator, ADB, logcat | Milestone 3 |
| UI exploration / functional tests | Milestone 4 |
| Network interception | Milestone 5 |
| LLM analysis | Milestone 6 |
| Dashboard UI, full AAB install path | Milestone 7 |

Do not interpret skipped stages as passing tests.
