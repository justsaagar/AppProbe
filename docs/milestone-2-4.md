# Milestone 2.4 — Deterministic secret scanner

## Status

The secret scanner performs deterministic local analysis.

It does not validate credentials against external services.

It does not attempt to use or exploit discovered credentials.

AI-assisted analysis is not part of this milestone.

## Pipeline position

```text
Artifact validation
        ↓
Metadata
        ↓
Manifest scanner
        ↓
JADX
        ↓
apktool
        ↓
Secret scanner
        ↓
Report
```

The scanner inspects whichever local artifacts are available:

- raw APK (always, for Android APK/AAB)
- JADX output under `tools/jadx/output/` when JADX executed
- apktool output under `tools/apktool/output/` when apktool executed

If JADX and/or apktool are unavailable, the scan continues using the raw APK.
Missing optional tool output is not a scan failure.

## Architecture

`SecretScanner` (`name="secret-scanner"`) implements the existing `Scanner`
interface and returns normalized `Finding` records. It does not introduce a
parallel finding model.

File traversal is file-type-aware:

- Text-like files (XML, JSON, properties, Java/Kotlin, smali, HTML, YAML, …)
  are scanned as UTF-8 text.
- `.so` and `.dex` use bounded printable-string extraction.
- Other binaries are not converted to text and regex-scanned.
- Oversized, malformed, symlink, and path-escaping files are skipped with a
  recorded reason.

## Secret categories

| Category | Typical classification | Notes |
| --- | --- | --- |
| Private keys (PEM) | CONFIRMED / CRITICAL | Header-only redaction |
| Stripe secret keys (`sk_live_` / `rk_live_`) | CONFIRMED / CRITICAL | Publishable `pk_` keys are ignored |
| AWS access key IDs (`AKIA…`) | CONFIRMED / CRITICAL | Not validated remotely |
| Azure connection strings with AccountKey | CONFIRMED / CRITICAL | |
| GitHub / Slack / OpenAI prefixes | CONFIRMED / HIGH | |
| Database URLs | CONFIRMED / HIGH | Only when username **and** password are present |
| Bearer tokens | POTENTIAL / HIGH | Token body redacted |
| JWT compact tokens | POTENTIAL | High confidence only with auth context |
| Password / pwd assignments | POTENTIAL / HIGH | Weak and placeholder values ignored |
| Generic API key assignments | POTENTIAL / MEDIUM | Requires assignment context + entropy |

## False-positive strategy

Matches are candidates, not automatic vulnerabilities. Validation uses multiple
signals:

- placeholder / documentation strings (`YOUR_API_KEY_HERE`, `${API_KEY}`, …)
- interpolation (`process.env.…`, `<API_KEY>`)
- weak dictionary passwords (`password`, `example`, `test_password`, …)
- UUIDs, hex hashes, package names, version strings
- AWS documentation example key IDs
- comment lines and generated sources (`R.java`, `BuildConfig.java`) for generic matches
- JWT-shaped values without authentication context stay POTENTIAL at lower confidence
- local deduplication of the same file, line, category, and redacted match

The scanner does not ignore every value that contains the word `test`, because a
real credential could include that substring.

## Firebase handling

Firebase client configuration commonly shipped in mobile apps is **not** treated
as a secret:

- project ID, app ID, sender ID, storage bucket
- client API keys (`AIza…`) used as public configuration
- `google-services.json`

These are ignored (not reported as vulnerabilities).

Google **service-account** material that includes a PEM private key is reported
as a CRITICAL private-key finding.

## Confidence and severity

Every secret finding has a deterministic confidence in `[0.0, 1.0]` and a
reason string (for example “PEM private key block” or “JWT with authentication
context”).

Severity reflects likely impact, not a blanket CRITICAL:

- CRITICAL — private keys, live cloud/payment secrets with broad scope
- HIGH — embedded passwords, bearer tokens, database credentials, test Stripe secrets
- MEDIUM — generic API keys or JWT-shaped values with weaker context
- LOW — weak bearer-like values
- INFO — cleartext HTTP URL references (not credentials)

Classification uses the existing `verification` field: `CONFIRMED`, `POTENTIAL`,
or `INFO`. Weak heuristics are not promoted to confirmed vulnerabilities.

## Redaction

Complete secrets are never written to findings, Markdown, logs, or exceptions.

- Typical tokens keep a short prefix/suffix and mask the middle.
- Private keys become `-----BEGIN PRIVATE KEY----- [REDACTED]` with no key body.

## File limits and coverage

Defaults (override with environment variables if needed; none are required):

| Setting | Default | Env |
| --- | --- | --- |
| Max file size | 2 MiB | `SECRET_SCAN_MAX_FILE_BYTES` |
| Max total bytes | 32 MiB | `SECRET_SCAN_MAX_TOTAL_BYTES` |
| Binary string cap | 2000 strings | `SECRET_SCAN_BINARY_STRING_LIMIT` |
| Max files | 4000 | `MAX_SECRET_SCAN_FILES` |

Coverage is recorded on the job and rendered as **Secret Scan Coverage**:

- files scanned / skipped
- bytes scanned
- sources (raw APK, JADX output, apktool output)
- skip reasons (size, total budget, malformed, symlink, traversal)

## Report

The Markdown report includes:

- Secret Scanner in the static analysis tool table
- `# Secrets & Sensitive Data` grouped by severity with `SEC-SECRET-NNN` headings
- ID, title, severity, confidence, classification, source, location, redacted
  evidence, impact, and a category-specific recommendation

## Limitations

- No credential validation, rotation checks, or network calls
- No exploit attempts
- No MobSF, CVE lookup, dependency correlation, or LLM ranking in this milestone
- Cross-scanner finding correlation remains the existing deterministic merge;
  full secret correlation is out of scope (later milestone)
- Intra-scanner dedup only (same file / line / category / redacted match)
