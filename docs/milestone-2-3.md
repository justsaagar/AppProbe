# Milestone 2.3 — apktool static analysis adapter

## Status

apktool provides decoded application artifacts for downstream analysis.

The apktool adapter itself does not generate security findings.

## Prerequisites

Optional. Install `apktool` (requires Java) and ensure it is on `PATH`, or set:

```
APKTOOL_BIN=/path/to/apktool
```

AppProbe does not require apktool. If it is missing, the scan continues.

## Availability

Discovery uses `shutil.which` / an explicit `APKTOOL_BIN` path. It never hardcodes
`/usr/bin/apktool`.

| Situation | Status |
| --- | --- |
| Executable not found | `NOT AVAILABLE` |
| Non-APK input (AAB, IPA, other) | `NOT EXECUTED` |
| Process exits 0 and writes a decoded project | `EXECUTED` |
| Non-zero exit, empty output, or missing artifacts | `FAILED` |
| Deadline exceeded | `TIMEOUT` |

The scan is not failed solely because apktool is absent.

## Version

Version is read with `apktool --version` through `ExternalToolExecutor`.
If version detection fails, `version` is empty and decoding may still proceed.

## Input

Supported: Android **APK**.

Not supported in this milestone:

- AAB (no silent conversion)
- IPA
- arbitrary files

The original APK is not modified.

## Output location

```
workspace/scans/<scan-id>/tools/apktool/output/
```

Metadata is stored as `tools/apktool/apktool-meta.json` (status, version, exit
code, duration, whether manifest/res/smali were observed). Decoded XML, smali,
and resources are not copied into logs or the Markdown report.

Success requires more than exit code 0: the output directory must contain a
decoded project (typically `AndroidManifest.xml` and/or `apktool.yml` plus
resources or smali when present).

## Limitations

- No vulnerability or secret findings from apktool itself
- No MobSF work in this milestone
- No emulator, network, or LLM stages
- Decoded files are data for later scanners and are never executed
