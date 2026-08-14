# Milestone 2.7 — Cross-scanner finding correlation

## Status

Correlation is deterministic and does not use AI.

When evidence is insufficient to establish a relationship,
findings remain separate.

Original scanner findings are preserved as `raw_findings`. Correlation never
silently discards security evidence.

## Architecture

```text
Scanner Findings
      │
      ▼
Correlation Normalizer
      │
      ▼
Correlation Keys / fingerprints
      │
      ▼
Duplicate Detection
      │
      ▼
Related Finding Grouping
      │
      ▼
Evidence Merge
      │
      ▼
Severity / Confidence Reconciliation
      │
      ▼
Correlated Findings + CORR-NNN groups
```

The engine lives in `app.analyzers.correlation` (the existing correlator,
extended — not a second `FindingCorrelator`).

## Duplicate detection

Exact duplicates share a structured key, for example:

- secrets: category + normalized scan-relative path + line
- manifest cleartext: issue type + application/component
- advisories: advisory id + package
- exported components: component name

Titles and scanners may differ. Secret values, tokens, and private key
material are **never** part of a fingerprint.

Path variants such as `./tools/jadx/output/...` and
`tools/jadx/output/...` normalize to the same location. Absolute
machine-specific prefixes are stripped.

The same class in JADX vs apktool smali is **not** merged automatically.
If path/class equivalence cannot be established reliably, findings stay
separate.

## Related findings

Related groups keep distinct findings and record the relationship:

| Relationship | Example |
| --- | --- |
| `DUPLICATE` | Secret scanner + MobSF, same Stripe secret location |
| `RELATED` | Manifest `usesCleartextTraffic` + HTTP endpoint evidence |
| `SUPPORTING_EVIDENCE` | OkHttp inventory + OSV advisory for that package |

Inventory rows are not a second vulnerability. The advisory finding is
primary; the technology record is supporting evidence.

Do not merge merely because findings share a file, severity, category,
title keyword, or CVE family.

## Severity reconciliation

For merged duplicates:

1. If any finding is `CONFIRMED`, use the highest severity among CONFIRMED items.
2. Otherwise use the highest severity among `POTENTIAL` items.
3. INFO-only observations cannot raise a CONFIRMED group's severity.

Example: CONFIRMED MEDIUM + CONFIRMED HIGH → HIGH.
CONFIRMED MEDIUM + POTENTIAL HIGH → MEDIUM.

## Confidence reconciliation

A single-source finding keeps its original confidence.

When independent scanners report the same duplicate issue, confidence
increases using `1 - Π(1 - c_i)` and is capped at `1.0`. Unrelated
findings are never averaged.

## Primary finding selection

Deterministic order:

1. CONFIRMED vulnerability / advisory match
2. CONFIRMED secret
3. CONFIRMED over POTENTIAL over INFO
4. Higher severity
5. Higher confidence
6. Inventory INFO last

## Group IDs

Groups are sorted by relationship, fingerprint, then title, and numbered
`CORR-001`, `CORR-002`, … Fingerprints are hashes of structured keys.

## Report

The Markdown report includes:

- **Correlation Summary** (raw count, duplicates merged, related groups, independents)
- **Correlated Findings** with `CORR-NNN`, primary finding, corroborating sources, evidence
- **Correlation: EXECUTED** in the static analysis tool table

Scanner coverage (JADX unavailable, OSV incomplete, and so on) is unchanged.

## Limitations

- No LLM / semantic embedding comparison
- No automatic JADX↔smali class equivalence
- No MobSF-specific parsers (synthetic MobSF findings still correlate when evidence agrees)
- False-positive correlation is treated as worse than leaving duplicates
