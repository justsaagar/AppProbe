# Milestone 2.2 — JADX static analysis adapter

## Status

JADX is integrated as an extraction/decompilation adapter on top of the
Milestone 2.1 executor.

JADX output is generated for downstream analysis.

No security findings are generated directly by the JADX adapter.

## Prerequisites

Optional. Install `jadx` (or `jadx-cli`) and ensure it is on `PATH`, or set:

```
JADX_BIN=/path/to/jadx
```

AppProbe does not require JADX. If it is missing, the scan continues.

## Availability

Discovery uses `shutil.which` / an explicit `JADX_BIN` path. It never hardcodes
`/usr/bin/jadx`.

| Situation | Status |
| --- | --- |
| Executable not found | `NOT AVAILABLE` |
| Non-APK input (AAB, IPA, other) | `NOT EXECUTED` |
| Process exits 0 and writes output | `EXECUTED` |
| Non-zero exit or empty output | `FAILED` |
| Deadline exceeded | `TIMEOUT` |

Reason example when missing:

```
JADX executable was not found in PATH.
```

The scan is not failed solely because JADX is absent.

## Version

Version is read with `jadx --version` through `ExternalToolExecutor.get_version`.
If version detection fails, `version` is empty and execution may still proceed.

## Input

Supported: Android **APK**.

Not supported in this milestone:

- AAB (no silent conversion to APK)
- IPA
- arbitrary ZIP/files

## Output location

```
workspace/scans/<scan-id>/tools/jadx/output/
```

Metadata (status, version, exit code, file counts) is stored as
`tools/jadx/jadx-meta.json`. Decompiled source is not copied into logs or the
Markdown report.

A later secret/security scanner may read the output directory. That analysis
is **not** part of Milestone 2.2.

## Limitations

- No vulnerability or secret findings from JADX itself
- No apktool / MobSF work in this milestone
- No emulator, network, or LLM stages
