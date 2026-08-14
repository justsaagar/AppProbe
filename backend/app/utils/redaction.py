"""Secret redaction helpers used by reports and logs."""

from __future__ import annotations

import re

_REDACT_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s\"']+)"),
    re.compile(r"(?i)(secret\s*[=:]\s*)([^\s\"']+)"),
    re.compile(r"(?i)(password\s*[=:]\s*)([^\s\"']+)"),
    re.compile(r"(?i)(token\s*[=:]\s*)([^\s\"']+)"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-+=/]+)"),
    re.compile(r"(sk_live_|sk_test_|rk_live_|rk_test_)([A-Za-z0-9]+)"),
    re.compile(
        r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)(.*?)(-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        re.DOTALL,
    ),
]


_KNOWN_PREFIXES = ("sk_live_", "sk_test_", "rk_live_", "rk_test_")


def redact_secret(value: str, *, keep_start: int = 4, keep_end: int = 4) -> str:
    """Redact a credential, keeping short prefix/suffix for identification."""
    if value is None:
        return ""
    text = value.strip()
    if not text:
        return text
    if "\n" in text or "BEGIN " in text:
        return "[REDACTED PRIVATE KEY]"
    for prefix in _KNOWN_PREFIXES:
        if text.startswith(prefix):
            rest = text[len(prefix) :]
            tail = rest[-keep_end:] if rest else ""
            return f"{prefix}{'*' * 16}{tail}"
    if len(text) <= keep_start + keep_end + 4:
        return text[:2] + "*" * max(len(text) - 2, 4)
    return f"{text[:keep_start]}{'*' * 16}{text[-keep_end:]}"


def redact_text(text: str) -> str:
    """Redact common credential patterns in free-form text."""
    if not text:
        return text
    redacted = text
    for pattern in _REDACT_PATTERNS:
        if pattern.groups >= 3 and "PRIVATE KEY" in pattern.pattern:
            redacted = pattern.sub(r"\1 [REDACTED] \3", redacted)
        elif pattern.groups >= 2:
            redacted = pattern.sub(
                lambda m: f"{m.group(1)}{redact_secret(m.group(2))}",
                redacted,
            )
    return redacted
