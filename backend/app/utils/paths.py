"""Path sanitization helpers for untrusted upload names and zip entries."""

from __future__ import annotations

from pathlib import Path, PurePosixPath


class PathTraversalError(ValueError):
    """Raised when a path would escape its intended workspace."""


_FORBIDDEN_NAME_CHARS = set('<>:"|?*\x00')


def sanitize_filename(name: str, *, default: str = "upload.bin") -> str:
    """Return a basename-only filename safe to store on disk."""
    if not name or not name.strip():
        return default
    candidate = Path(name.replace("\\", "/")).name.strip()
    if not candidate or candidate in {".", ".."}:
        return default
    cleaned = "".join("_" if ch in _FORBIDDEN_NAME_CHARS else ch for ch in candidate)
    cleaned = cleaned.strip(" .")
    if not cleaned:
        return default
    return cleaned[:255]


def assert_relative_entry(entry: str) -> PurePosixPath:
    """Reject zip/path entries that are absolute or contain parent traversal."""
    if not entry or entry.startswith("\x00"):
        raise PathTraversalError("Empty or invalid archive entry")
    normalized = entry.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("\\"):
        raise PathTraversalError(f"Absolute archive entry rejected: {entry}")
    posix = PurePosixPath(normalized)
    if posix.is_absolute() or posix.anchor:
        raise PathTraversalError(f"Absolute archive entry rejected: {entry}")
    if ".." in posix.parts:
        raise PathTraversalError(f"Parent traversal rejected: {entry}")
    return posix


def safe_join(base: Path, *parts: str) -> Path:
    """Join path parts under base and reject escapes."""
    base_resolved = base.resolve()
    filtered: list[str] = []
    for part in parts:
        if part is None:
            continue
        text = str(part)
        if "\x00" in text:
            raise PathTraversalError("Null byte in path component")
        assert_relative_entry(text)
        filtered.append(text.replace("\\", "/"))
    joined = base_resolved.joinpath(*filtered).resolve()
    if not joined.is_relative_to(base_resolved):
        raise PathTraversalError(f"Path escapes workspace: {joined}")
    return joined
