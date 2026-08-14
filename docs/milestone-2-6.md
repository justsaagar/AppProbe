# Milestone 2.6 — Vulnerability / Advisory Scanner

## Status

The scanner matches detected dependency versions against published
advisories. It does not exploit vulnerabilities or validate exploitability.

Vulnerability assessment depends on advisory-provider availability.

A failed advisory lookup does NOT mean that the dependency is safe.

## Pipeline position

```text
Dependency / SDK scanner
        ↓
Vulnerability / advisory scanner
        ↓
Correlation
        ↓
Report
```

The scanner consumes the normalized technology inventory from Milestone 2.5.

## Architecture

```text
VulnerabilityScanner
        ↓
AdvisoryProvider
        ↓
OSVProvider  (OSV.dev)
```

`VulnerabilityScanner` contains no OSV-specific HTTP logic. Additional
providers (GitHub Advisory Database, NVD, vendor feeds) can be added later
without rewriting the scanner.

The first provider is **OSV.dev**, using the official API:

- `POST /v1/querybatch` for package/version lookups
- `GET /v1/vulns/{id}` for normalized advisory details

Queries send only:

- package ecosystem
- package name
- installed version

They never send APKs, decompiled source, secrets, or user data. No API token
is required for the public OSV API.

## Package mapping

Technologies are mapped to canonical package identifiers only when the
coordinate is known from a signature or Maven `pom.properties` evidence.

| Technology | Ecosystem | Package |
| --- | --- | --- |
| OkHttp | Maven | `com.squareup.okhttp3:okhttp` |
| Retrofit | Maven | `com.squareup.retrofit2:retrofit` |
| Firebase Auth | Maven | `com.google.firebase:firebase-auth` |
| Firebase Messaging | Maven | `com.google.firebase:firebase-messaging` |

Coordinates are not invented. If identity cannot be determined:

```text
Status: NOT_EVALUATED
Reason: Package identity unavailable.
```

Flutter/Dart packages are mapped to Pub only when the signature has a single
known pub.dev name. If the version is unknown (for example Dio), OSV is not
queried.

## Version requirements

An advisory lookup runs only when both are known:

- package identity
- installed version

Unknown, invalid, or guessed values (`latest`, `Unknown`, `snapshot`) are not
queried. The scanner never substitutes a current/latest version.

## Affected-range matching

Version comparison uses the range semantics supplied by the advisory:

- Maven `ECOSYSTEM` ranges use Maven version order (`1.9.0` < `1.10.0`)
- `SEMVER` ranges use semantic versions
- `GIT` ranges are not matched against APK versions

A vulnerability finding is created only when the installed version is
**affected**. Unknown ranges produce `NOT_EVALUATED`, not a finding.
Unaffected versions produce no finding and are counted as “no matching
advisories”.

## Confidence and severity

Exact package identity + exact version + deterministic range match →
confidence `0.99`.

Severity is taken from advisory CVSS or qualitative severity when present
and mapped to CRITICAL / HIGH / MEDIUM / LOW / INFO. Missing severity is
`UNKNOWN` internally and mapped conservatively to INFO on findings. A CVE
identifier alone is not treated as HIGH.

## Caching and rate limits

Lookups are cached for the duration of one scan keyed by
`ecosystem:package:version`. Duplicate technology records share one provider
request. Batches are bounded. Concurrent HTTP is limited. HTTP 429 is not
retried aggressively; the assessment is `INCOMPLETE`.

There is no persistent global cache.

## Network and offline behavior

| Condition | Assessment status |
| --- | --- |
| Lookups finished | `COMPLETE` |
| Timeout, HTTP 5xx, malformed JSON, rate limit | `INCOMPLETE` |
| Connection failure / unreachable provider | `NOT_AVAILABLE` |
| Network disabled | `NOT_AVAILABLE` |
| Scanner did not run | `NOT_EXECUTED` |

The overall AppProbe scan still finishes. Failed lookups are **not** reported
as “0 vulnerabilities”. The report states:

```text
Vulnerability status: NOT DETERMINED
```

A failed advisory lookup does NOT mean that the dependency is safe.

## Report

The Markdown report includes **Dependency Vulnerability Assessment** with
status, advisory source, packages evaluated, vulnerable package count, and
packages with no matching advisories. Individual `VULN-NNN` findings include
OSV id, CVE/GHSA aliases, package, installed version, affected range,
evidence, and a deterministic upgrade recommendation.

Clean packages do not get individual findings; they appear in statistics.

## Limitations

- Advisory matching only — no exploit validation
- Maven is the primary ecosystem; Pub is used only with a known name+version
- No NVD/GitHub provider yet
- No claim of exploitability
- Assessment quality depends on inventory versions and OSV coverage
