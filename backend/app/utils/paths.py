"""Path sanitization for untrusted upload names and ZIP entries."""

from __future__ import annotations

import os
import re
from pathlib import Path

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


class UnsafePathError(ValueError):
    """Raised when a path would escape an allowed root or is otherwise unsafe."""


def sanitize_filename(name: str, *, default: str = "upload.bin") -> str:
    """Return a basename safe to store on disk.

    Drops directory components, rejects empty/reserved names, and replaces
    remaining unsafe characters. The original user-supplied name is never
    interpolated into shell commands.
    """
    if not name or not name.strip():
        return default
    base = Path(name.replace("\\", "/")).name
    if not base or base in {".", ".."}:
        return default
    if "\x00" in base:
        raise UnsafePathError("NUL byte in filename")
    cleaned = _UNSAFE_CHARS.sub("_", base).strip("._")
    if not cleaned:
        return default
    if len(cleaned) > 200:
        stem, suffix = os.path.splitext(cleaned)
        cleaned = stem[: 200 - len(suffix)] + suffix
    return cleaned


def assert_relative_zip_entry(entry: str) -> str:
    """Reject ZIP entries that would escape the extraction root (zip slip)."""
    if not entry or "\x00" in entry:
        raise UnsafePathError("invalid ZIP entry name")
    normalized = entry.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        raise UnsafePathError(f"absolute ZIP entry rejected: {entry}")
    parts = []
    for part in normalized.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise UnsafePathError(f"path traversal in ZIP entry: {entry}")
        parts.append(part)
    if not parts:
        raise UnsafePathError("empty ZIP entry path")
    return "/".join(parts)


def safe_join(root: Path, *parts: str) -> Path:
    """Join path parts and ensure the result stays inside root."""
    root = root.resolve()
    candidate = root.joinpath(*parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise UnsafePathError(f"path escapes workspace: {candidate}") from exc
    return candidate
