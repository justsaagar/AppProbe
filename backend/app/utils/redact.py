"""Redact likely secrets from logs and generated reports."""

from __future__ import annotations

import re

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(sk_live_|sk_test_|rk_live_|rk_test_)([A-Za-z0-9]{4,})([A-Za-z0-9]{4})"),
    re.compile(r"(AKIA)([A-Z0-9]{12})([A-Z0-9]{4})"),
    re.compile(r"(ghp_)([A-Za-z0-9]{4,})([A-Za-z0-9]{4})"),
    re.compile(r"(AIza)([A-Za-z0-9_\-]{4,})([A-Za-z0-9_\-]{4})"),
    re.compile(
        r"(eyJ[A-Za-z0-9_\-]{8,}\.)([A-Za-z0-9_\-]{8,}\.)([A-Za-z0-9_\-]{4,})"
    ),
]


def redact_secret(value: str, *, keep_prefix: int = 8, keep_suffix: int = 4) -> str:
    """Mask a credential for display. Never emit the full secret."""
    if not value:
        return value
    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)
    return f"{value[:keep_prefix]}{'*' * max(8, len(value) - keep_prefix - keep_suffix)}{value[-keep_suffix:]}"


def redact_text(text: str) -> str:
    """Best-effort redaction of common credential patterns in free text."""

    def _jwt(match: re.Match[str]) -> str:
        return f"{match.group(1)}{'*' * 12}.{redact_secret(match.group(3), keep_prefix=0, keep_suffix=4)}"

    redacted = text
    for pattern in _PATTERNS:
        if pattern.pattern.startswith("(eyJ"):
            redacted = pattern.sub(_jwt, redacted)
        else:
            redacted = pattern.sub(
                lambda m: f"{m.group(1)}{'*' * max(8, len(m.group(2)))}{m.group(3)}",
                redacted,
            )
    return redacted
