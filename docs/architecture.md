# Architecture (Milestone 1)

AppProbe is a modular local-first scanner. The LLM is a future reasoning layer, not the analyzer.

```
upload → ScanJob → validate → metadata → scanners → correlate → (AI stub) → markdown report
```

## Backend packages

| Package | Role in Milestone 1 |
| --- | --- |
| `app.api` | FastAPI routes for scan jobs |
| `app.models` | `ScanJob`, `Finding`, enums, state transitions |
| `app.schemas` | API response models |
| `app.analyzers` | APK/AAB/IPA validation, AXML/manifest parsing, severity, correlation |
| `app.scanners` | Pluggable `Scanner` interface; `ManifestScanner` is implemented |
| `app.runners` | `RuntimeRunner` stubs that report emulator/iOS as unavailable |
| `app.agents` | `AIAnalyzer` stub that does not invent evidence |
| `app.reporters` | Deterministic `security-report.md` generator |
| `app.storage` | Isolated workspaces and JSON job persistence |
| `app.services` | Async scan pipeline |
| `app.utils` | Path sanitization, subprocess wrapper, redaction |

## Finding schema

Every scanner emits `Finding` objects with evidence. Severity is assigned by deterministic rules (`app.analyzers.severity`). Milestone 1 never assigns `CRITICAL` because exploitability is not confirmed at runtime.

## Adding a scanner later

Implement `Scanner.scan(artifact, context) -> list[Finding]` and register it in `default_scanners()`. Do not call an LLM from the scanner.
