# Milestone 2

## Goal

Expand AppProbe from a custom manifest scanner into a modular static-analysis
platform without pretending optional tools ran.

## Added

- External tool adapters: MobSF (REST or `mobsfscan` CLI), JADX, apktool
- Availability detection and structured statuses:
  `AVAILABLE_AND_EXECUTED`, `AVAILABLE_BUT_FAILED`, `NOT_AVAILABLE`, `NOT_EXECUTED`
- Deterministic secret detector with redaction and false-positive guards
- SDK/dependency detector (informational inventory)
- Vulnerability / advisory matching via OSV (affected versions only)
- Finding correlation: duplicates, related groups, evidence merge, CORR-NNN report IDs
- Report sections for tool coverage, secrets, and correlated groups
- Isolated tool output under `workspace/scans/<id>/tools/`

## Optional tools

AppProbe Milestone 1 behavior remains if none of these are installed.

### JADX

```bash
# example
# https://github.com/skylot/jadx/releases
jadx --version
```

Override with `JADX_BIN=/path/to/jadx`.

### apktool

```bash
apktool --version
```

Override with `APKTOOL_BIN=/path/to/apktool`. Requires Java.

### MobSF

Either:

- REST: set `MOBSF_URL=http://127.0.0.1:8000` and optional `MOBSF_API_KEY`
- CLI: install `mobsfscan` on `PATH`

If neither is present, the report records **MobSF: NOT_AVAILABLE** and the scan continues.

## What is still not implemented

- Android emulator / ADB / UI exploration
- Network interception
- LLM analysis
- Dashboard
- bundletool APK-set generation
