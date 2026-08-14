# Security fixtures and credentials

AppProbe analyzes untrusted mobile artifacts. The repository itself must not
contain real credentials.

## Rules

- Never commit `.env`. Copy `.env.example` and keep real values local.
- Never put live API keys, passwords, JWTs, or cloud credentials in tests,
  sample generators, docs, or committed fixtures.
- Security-scanner tests must use **synthetic** values such as
  `FAKE_STRIPE_KEY_FOR_APPPROBE_TEST_ONLY`.
- When a detector must see a provider-shaped value (for example a Stripe
  `sk_live_` prefix), assemble that value **at test runtime** from obviously
  fake components. Do not store a contiguous production-style credential.
- Generated APK/AAB/IPA files, scan workspaces, reports, and tool output stay
  local unless they are intentionally versioned. They are gitignored.

## Secret scanner (Milestone 2.4)

The secret scanner performs deterministic local analysis.

It does not validate credentials against external services.

It does not attempt to use or exploit discovered credentials.

AI-assisted analysis is not part of this milestone.

Findings never include the complete secret. Private keys are rendered as
`-----BEGIN PRIVATE KEY----- [REDACTED]`. Firebase client configuration
(`google-services.json`, project IDs, client API keys) is not classified as a
vulnerability; service-account private keys are.

## Dependency and SDK scanner (Milestone 2.5)

Dependency and SDK detection is informational in Milestone 2.5.

A detected dependency is NOT automatically considered vulnerable.

CVE/advisory database integration is intentionally deferred.

The scanner does not call NVD, OSV, Snyk, or GitHub Advisory. Test fixtures may
use harmless package names such as `com.stripe.android` without credentials.

## Vulnerability / advisory scanner (Milestone 2.6)

OSV public API access does not require a secret. Do not add API tokens, GitHub
tokens, or passwords for this scanner.

Vulnerability assessment depends on advisory-provider availability.

A failed advisory lookup does NOT mean that the dependency is safe.

The scanner does not exploit vulnerabilities or validate exploitability.

Queries include only package ecosystem, name, and version. Advisory responses
are untrusted external data.

## Cross-scanner correlation (Milestone 2.7)

Correlation fingerprints never include secret values, tokens, or private key
material. Original findings remain available as `raw_findings`.

Correlation is deterministic and does not use AI.

When evidence is insufficient to establish a relationship,
findings remain separate.

## MobSF adapter (Milestone 2.8)

MobSF is an optional static-analysis provider. The API key is a credential:
never commit it, log it, put it in findings, or print HTTP headers that carry
it. `.env.example` may contain `MOBSF_API_KEY=` with no value.

AppProbe does not depend on MobSF being available. Disabled (`NOT ENABLED`) is
distinct from an unreachable server (`NOT AVAILABLE`) and from authentication
failure (`AUTH FAILED`).

The adapter uploads the original APK only to the configured MobSF URL. It does
not follow redirects to other hosts, does not scrape the UI, and does not
enable MobSF dynamic analysis.

See [docs/milestone-2-8.md](milestone-2-8.md).

## Historical GitGuardian incidents

GitGuardian reported three findings in commit `9f26f4c` (file
`backend/tests/test_secrets.py`):

| Category | Classification | Notes |
| --- | --- | --- |
| Stripe Keys | TEST_SECRET | Alphabet-suffix unit-test fixture, not a live Stripe key |
| JSON Web Token | TEST_SECRET | jwt.io-style demo header/payload with a fake signature |
| Generic Password | TEST_SECRET | Random-looking assignment used only in a unit test |

Those values were never production credentials. No rotation/revocation is
required.

That commit is already reachable from the default branch `dev`. Deleting the
strings in a later commit does **not** remove them from Git history. Rewriting
`dev` is a separate, explicitly reviewed operation and was not performed as
part of this cleanup.

## Local check

```bash
make secrets-check
```

This scans tracked files for realistic credential literals. It does not replace
GitGuardian's server-side scan.
