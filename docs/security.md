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
