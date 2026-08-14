# Milestone 1

## Goal

Accept an APK, analyze Android metadata and the manifest, emit normalized
findings, and generate a valid `security-report.md`.

## Delivered

- Project structure matching the planned modular layout
- FastAPI upload API that returns a scan ID immediately
- Background scan job with status/progress
- APK validation (ZIP, zip-slip, required entries)
- Binary AXML parser + encoder (used for fixtures)
- Metadata: package, version, versionCode, minSdk, targetSdk, permissions, components
- Manifest findings: dangerous permissions (INFO), exported components, cleartext, debuggable, backup
- Markdown report with all required sections
- CLI: `python -m app.cli scan ./app.apk`
- Unit and integration tests with a synthetic vulnerable APK

## Explicit non-goals (this milestone)

No MobSF, JADX, apktool, emulator, network, or LLM results are generated.
Reports state `Runtime Testing: NOT EXECUTED` when those stages are skipped.

AAB uploads are inspected as bundles (not converted to APK).
IPA uploads are structurally validated; dynamic iOS testing is not claimed.
