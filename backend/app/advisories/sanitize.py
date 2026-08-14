"""Treat advisory-provider JSON as untrusted external data."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

MAX_ID_LEN = 128
MAX_TEXT_LEN = 500
MAX_DETAILS_LEN = 2000
MAX_URL_LEN = 500
MAX_ALIASES = 20
MAX_RANGES = 20
MAX_VERSIONS = 50
MAX_REFERENCES = 8

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-:]{0,190}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)


def as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def sanitize_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_ID_LEN:
        return None
    if not _ID_RE.match(text):
        return None
    return text


def sanitize_package(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 191:
        return None
    if not _PACKAGE_RE.match(text):
        return None
    return text


def sanitize_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _VERSION_RE.match(text):
        return None
    return text


def sanitize_text(value: Any, *, limit: int = MAX_TEXT_LEN) -> str:
    if not isinstance(value, str):
        return ""
    collapsed = " ".join(value.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed


def sanitize_alias(value: Any) -> str | None:
    ident = sanitize_id(value)
    if ident is None:
        return None
    upper = ident.upper()
    if upper.startswith("CVE-") and not _CVE_RE.match(ident):
        return None
    if upper.startswith("GHSA-") and not _GHSA_RE.match(ident):
        return None
    return ident


def sanitize_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_URL_LEN:
        return None
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc or parsed.netloc.startswith("."):
        return None
    if parsed.username or parsed.password:
        return None
    if any(ch.isspace() for ch in text):
        return None
    return text


def is_cve(value: str) -> bool:
    return bool(_CVE_RE.match(value))


def is_ghsa(value: str) -> bool:
    return bool(_GHSA_RE.match(value))
