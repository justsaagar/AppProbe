"""Bounded, path-safe file iteration over APKs and tool output trees."""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from app.models.scan_job import SecretScanCoverage, SkippedScanFile
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
    ".env",
    ".pem",
}

TEXT_NAMES = {
    "google-services.json",
    "androidmanifest.xml",
    "strings.xml",
    "network_security_config.xml",
    "firebase-config.json",
}

BINARY_STRING_SUFFIXES = {".so", ".dex"}
SKIP_DIR_NAMES = {".git", "__macosx", "node_modules", ".svn", ".hg"}
SOURCE_RAW_APK = "raw APK"
SOURCE_JADX = "JADX output"
SOURCE_APKTOOL = "apktool output"
MAX_RECORDED_SKIPS = 100


@dataclass
class FileRecord:
    source: str
    path: str
    text: str
    size: int


@dataclass
class SecretScanLimits:
    max_file_bytes: int
    max_total_bytes: int
    max_files: int
    binary_string_limit: int


@dataclass
class SecretFileCollector:
    """Incrementally visit artifact files without loading the whole tree."""

    limits: SecretScanLimits
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped: list[SkippedScanFile] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def coverage(self) -> SecretScanCoverage:
        return SecretScanCoverage(
            files_scanned=self.files_scanned,
            files_skipped=len(self.skipped),
            bytes_scanned=self.bytes_scanned,
            sources=list(self.sources),
            skipped_files=self.skipped[:MAX_RECORDED_SKIPS],
        )

    def _note_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def _skip(self, path: str, reason: str) -> None:
        if len(self.skipped) < MAX_RECORDED_SKIPS:
            self.skipped.append(SkippedScanFile(path=path, reason=reason))

    def _budget_allows(self, size: int) -> str | None:
        if self.files_scanned >= self.limits.max_files:
            return "scan file limit reached"
        if self.bytes_scanned + size > self.limits.max_total_bytes:
            return "maximum total bytes exceeded"
        return None

    def accept(self, source: str, path: str, data: bytes) -> FileRecord | None:
        size = len(data)
        reason = self._budget_allows(size)
        if reason:
            self._skip(path, reason)
            return None
        text = decode_for_scan(data, self.limits.binary_string_limit)
        self.files_scanned += 1
        self.bytes_scanned += size
        return FileRecord(source=source, path=path, text=text, size=size)

    def iter_zip(self, archive_path: Path, *, source: str = SOURCE_RAW_APK) -> Iterator[FileRecord]:
        self._note_source(source)
        try:
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    try:
                        name = assert_relative_zip_entry(info.filename)
                    except UnsafePathError:
                        self._skip(info.filename, "path traversal rejected")
                        continue
                    lowered = name.lower().replace("\\", "/")
                    if any(part in SKIP_DIR_NAMES for part in lowered.split("/")):
                        continue
                    kind = classify_scan_file(name)
                    if kind == "ignore":
                        continue
                    if info.file_size <= 0:
                        continue
                    if info.file_size > self.limits.max_file_bytes:
                        self._skip(name, "file size exceeds scanner limit")
                        continue
                    try:
                        data = archive.read(info)
                    except Exception:
                        self._skip(name, "malformed file")
                        continue
                    if kind == "binary":
                        text = extract_printable_strings(
                            data, max_strings=self.limits.binary_string_limit
                        )
                        reason = self._budget_allows(len(data))
                        if reason:
                            self._skip(name, reason)
                            continue
                        self.files_scanned += 1
                        self.bytes_scanned += len(data)
                        yield FileRecord(source=source, path=name, text=text, size=len(data))
                        continue
                    record = self.accept(source, name, data)
                    if record is not None:
                        yield record
        except zipfile.BadZipFile:
            self._skip(str(archive_path), "malformed file")

    def iter_tree(self, root: Path, *, source: str) -> Iterator[FileRecord]:
        if not root.is_dir():
            return
        self._note_source(source)
        confine = root.resolve()
        for path in root.rglob("*"):
            try:
                if any(part.lower() in SKIP_DIR_NAMES for part in path.parts):
                    continue
                if path.is_symlink():
                    self._skip(_rel(root, path), "symlink skipped")
                    continue
                if not path.is_file():
                    continue
                resolved = path.resolve()
                resolved.relative_to(confine)
            except (ValueError, OSError):
                self._skip(_rel(root, path), "path escapes scan workspace")
                continue
            rel = path.relative_to(root).as_posix()
            kind = classify_scan_file(rel)
            if kind == "ignore":
                continue
            try:
                size = path.stat().st_size
            except OSError:
                self._skip(rel, "malformed file")
                continue
            if size <= 0:
                continue
            if size > self.limits.max_file_bytes:
                self._skip(rel, "file size exceeds scanner limit")
                continue
            try:
                data = path.read_bytes()
            except OSError:
                self._skip(rel, "malformed file")
                continue
            if kind == "binary":
                reason = self._budget_allows(len(data))
                if reason:
                    self._skip(rel, reason)
                    continue
                text = extract_printable_strings(
                    data, max_strings=self.limits.binary_string_limit
                )
                self.files_scanned += 1
                self.bytes_scanned += len(data)
                yield FileRecord(source=source, path=rel, text=text, size=len(data))
                continue
            record = self.accept(source, rel, data)
            if record is not None:
                yield record


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def is_probably_text(name: str) -> bool:
    lowered = name.lower().replace("\\", "/")
    base = Path(lowered).name
    if base in TEXT_NAMES:
        return True
    return Path(lowered).suffix in TEXT_SUFFIXES


def classify_scan_file(name: str) -> str:
    """Return 'text', 'binary', or 'ignore'."""
    lowered = name.lower().replace("\\", "/")
    suffix = Path(lowered).suffix
    if is_probably_text(name):
        return "text"
    if suffix in BINARY_STRING_SUFFIXES:
        return "binary"
    return "ignore"


def decode_for_scan(data: bytes, binary_string_limit: int) -> str:
    text = data.decode("utf-8", errors="replace")
    if not text:
        return ""
    replacements = text.count("\ufffd")
    if replacements > max(8, int(len(text) * 0.1)):
        return extract_printable_strings(data, max_strings=binary_string_limit)
    return text


def extract_printable_strings(blob: bytes, *, min_len: int = 6, max_strings: int = 2000) -> str:
    """Extract printable ASCII strings from a binary blob without regex-on-bytes."""
    chunks: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_len:
            chunks.append(current.decode("ascii"))
            if len(chunks) >= max_strings:
                break
        current = bytearray()
    if len(chunks) < max_strings and len(current) >= min_len:
        chunks.append(current.decode("ascii"))
    return "\n".join(chunks)


def iter_zip_text_entries(
    archive_path: Path,
    *,
    max_files: int,
    max_bytes: int,
) -> Iterator[tuple[str, str]]:
    collector = SecretFileCollector(
        SecretScanLimits(
            max_file_bytes=max_bytes,
            max_total_bytes=max_bytes * max(1, max_files),
            max_files=max_files,
            binary_string_limit=400,
        )
    )
    for record in collector.iter_zip(archive_path):
        if classify_scan_file(record.path) == "text":
            yield record.path, record.text


def iter_zip_native_libraries(
    archive_path: Path,
    *,
    max_bytes: int,
) -> Iterator[tuple[str, bytes]]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".so"):
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
    collector = SecretFileCollector(
        SecretScanLimits(
            max_file_bytes=max_bytes,
            max_total_bytes=max_bytes * max(1, max_files),
            max_files=max_files,
            binary_string_limit=400,
        )
    )
    source = str(confine_to or root)
    yield from ((record.path, record.text) for record in collector.iter_tree(root, source=source))
