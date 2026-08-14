"""Validate the configured MobSF base URL.

The URL must come from trusted application configuration, never from
user-uploaded content or MobSF finding payloads.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse, urlunparse

from app.utils.http import JsonHttpError

ALLOWED_SCHEMES = {"http", "https"}


def validate_mobsf_url(raw: str) -> str:
    """Return a normalized origin+path base URL, or raise JsonHttpError."""

    text = (raw or "").strip()
    if not text:
        raise JsonHttpError("unavailable", "MobSF URL is not configured")
    parsed = urlparse(text)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise JsonHttpError("invalid_url", "MobSF URL must be http or https")
    if not parsed.hostname:
        raise JsonHttpError("invalid_url", "MobSF URL is missing a host")
    if parsed.username or parsed.password:
        raise JsonHttpError("invalid_url", "MobSF URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise JsonHttpError("invalid_url", "MobSF URL must not contain query or fragment")
    path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def same_origin(base: str, candidate: str) -> bool:
    left = urlparse(base)
    right = urlparse(candidate)
    return (
        left.scheme == right.scheme
        and left.hostname == right.hostname
        and (left.port or _default_port(left.scheme)) == (right.port or _default_port(right.scheme))
    )


def join_mobsf(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None
