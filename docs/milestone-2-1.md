# Milestone 2.1 — External tool execution abstraction

## Status

External tool execution infrastructure is implemented.
Specific tool adapters are not yet implemented.

This milestone does **not** add JADX, apktool, MobSF, or bundletool integrations.

## Goal

Provide a reusable, testable layer for running external analysis binaries so
future scanners are not coupled to raw subprocess calls.

Separation of concerns:

1. **Tool definition** — `ToolDefinition` (name, executable, version args)
2. **Tool discovery** — `resolve_executable` via `shutil.which` / path check
3. **Tool execution** — `ExternalToolExecutor.run`
4. **Tool result** — `ToolExecutionResult` (no exceptions for normal failures)
5. **Scan orchestration** — unchanged; future scanners call the executor

## Execution statuses

| Status | Meaning |
| --- | --- |
| `AVAILABLE` | Executable was found (`probe`) |
| `NOT_AVAILABLE` | Executable was not found |
| `EXECUTED` | Process ran and exited 0 |
| `FAILED` | Non-zero exit, permission error, or spawn error |
| `TIMEOUT` | Deadline exceeded; process was terminated |

Unavailable, failed, timed out, and crashed-before-run are distinct states.
None of them raise into the API layer by themselves.

## Behavior

- Timeouts are per invocation (`timeout=` or `TOOL_TIMEOUT_SECONDS`, default 180s)
- stdout/stderr are capped (`TOOL_MAX_OUTPUT_BYTES`, default 1 MiB each) with
  `stdout_truncated` / `stderr_truncated`
- Working directory is caller-supplied (typically `workspace/scans/<id>/tools/<name>/`)
- Environment overrides are merged onto an allowlisted process env
- Version detection is generic: `get_version(executable, version_args)` with
  timeout; failure returns `None`

## Security model

APK/AAB/IPA files are untrusted. The executor:

- never uses `shell=True`
- always passes an argument array
- never interpolates user input into a shell
- does not log full argument lists, environment variables, or raw tool output
- logs tool name, executable basename, status, exit code, duration, timeout,
  truncation flags, and scan-local cwd name only

## How future scanners will use it

A later adapter (for example JADX) will hold a `ToolDefinition` and call
`ExternalToolExecutor.run(...)`, then map `ToolExecutionResult.status` onto
scan-level coverage. Those adapters are **not** part of Milestone 2.1.

## Configuration

Works with no extra environment variables.

```
TOOL_TIMEOUT_SECONDS=180
TOOL_MAX_OUTPUT_BYTES=1048576
```
