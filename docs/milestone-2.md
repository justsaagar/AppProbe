# Milestone 2

## Goal

Expand AppProbe from a custom manifest scanner into a modular static-analysis
platform without pretending optional tools ran.

## Added

- External tool adapters: JADX, apktool, optional MobSF REST
- Availability detection and structured statuses:
  `AVAILABLE_AND_EXECUTED`, `AVAILABLE_BUT_FAILED`, `NOT_AVAILABLE`,
  `NOT_EXECUTED`, `TIMEOUT`, `NOT_ENABLED`, `AUTH_FAILED`
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

MobSF is an optional static-analysis provider. Leave it disabled unless a
**local** MobSF instance is running.

```bash
MOBSF_ENABLED=true
MOBSF_URL=http://127.0.0.1:8000
MOBSF_API_KEY=
```

If `MOBSF_ENABLED=false`, the report records **MobSF: NOT ENABLED** and the
scan continues. If enabled but unreachable, the report records
**MobSF: NOT AVAILABLE**. Authentication failure is **AUTH FAILED**.

See [docs/milestone-2-8.md](milestone-2-8.md).

Dynamic analysis is NOT part of Milestone 2.8.

## What is still not implemented

- Android emulator / ADB / UI exploration
- Network interception
- LLM analysis
- Dashboard
- bundletool APK-set generation
