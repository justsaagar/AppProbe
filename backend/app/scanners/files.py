"""Bounded, path-safe file iteration over APKs and tool output trees."""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from pathlib import Path

from app.utils.paths import UnsafePathError, assert_relative_zip_entry

TEXT_SUFFIXES = {
    ".xml",
    ".json",
    ".properties",
    ".txt",
    ".html",
    ".htm",
    ".js",
    ".java",
    ".kt",
    ".kts",
    ".smali",
    ".plist",
    ".gradle",
    ".pro",
    ".cfg",
    ".ini",
    ".yml",
    ".yaml",
    ".csv",
    ".conf",
}

TEXT_NAMES = {
    "google-services.json",
    "androidmanifest.xml",
    "strings.xml",
    "network_security_config.xml",
    "firebase-config.json",
}


def is_probably_text(name: str) -> bool:
    lowered = name.lower().replace("\\", "/")
    base = Path(lowered).name
    if base in TEXT_NAMES:
        return True
    return Path(lowered).suffix in TEXT_SUFFIXES


def iter_zip_text_entries(
    archive_path: Path,
    *,
    max_files: int,
    max_bytes: int,
) -> Iterator[tuple[str, str]]:
    count = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir() or info.file_size <= 0 or info.file_size > max_bytes:
                    continue
                try:
                    name = assert_relative_zip_entry(info.filename)
                except UnsafePathError:
                    continue
                if not is_probably_text(name):
                    continue
                try:
                    data = archive.read(info)
                except Exception:
                    continue
                count += 1
                if count > max_files:
                    return
                yield name, data.decode("utf-8", errors="replace")
    except zipfile.BadZipFile:
        return


def iter_zip_native_libraries(
    archive_path: Path,
    *,
    max_bytes: int,
) -> Iterator[tuple[str, bytes]]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.endswith(".so"):
                    continue
                if info.file_size <= 0 or info.file_size > max_bytes:
                    continue
                try:
                    name = assert_relative_zip_entry(info.filename)
                    yield name, archive.read(info)
                except (UnsafePathError, Exception):
                    continue
    except zipfile.BadZipFile:
        return


def iter_tree_text_files(
    root: Path,
    *,
    max_files: int,
    max_bytes: int,
    confine_to: Path | None = None,
) -> Iterator[tuple[str, str]]:
    if not root.is_dir():
        return
    confine = (confine_to or root).resolve()
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            return
        if path.is_symlink() or not path.is_file():
            continue
        try:
            resolved = path.resolve()
            resolved.relative_to(confine)
        except (ValueError, OSError):
            continue
        if path.stat().st_size > max_bytes:
            continue
        rel = path.relative_to(root).as_posix()
        if not is_probably_text(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count += 1
        yield rel, text
