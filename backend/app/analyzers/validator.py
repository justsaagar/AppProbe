"""Validate untrusted APK / AAB / IPA uploads before analysis."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.models.enums import ArtifactKind, Platform
from app.utils.paths import (
    UnsafePathError,
    assert_relative_zip_entry,
    sanitize_filename,
)

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ALLOWED_EXTENSIONS = {".apk", ".aab", ".ipa"}
ALLOWED_CONTENT_TYPES = {
    "application/vnd.android.package-archive",
    "application/java-archive",
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
    "application/x-authorware-bin",  # some browsers map .aab oddly
    "application/iphone",
}


class ArtifactValidationError(ValueError):
    """The uploaded file is not a usable mobile artifact."""


@dataclass
class ValidationResult:
    kind: ArtifactKind
    platform: Platform
    filename: str
    size: int
    zip_entries: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def detect_kind(filename: str) -> ArtifactKind:
    suffix = Path(filename).suffix.lower()
    mapping = {
        ".apk": ArtifactKind.APK,
        ".aab": ArtifactKind.AAB,
        ".ipa": ArtifactKind.IPA,
    }
    return mapping.get(suffix, ArtifactKind.UNKNOWN)


def validate_upload_name(filename: str) -> str:
    cleaned = sanitize_filename(filename)
    suffix = Path(cleaned).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ArtifactValidationError(
            f"unsupported extension {suffix or '(none)'}; allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )
    return cleaned


def validate_content_type(content_type: str | None) -> None:
    if not content_type:
        return
    mime = content_type.split(";")[0].strip().lower()
    if mime not in ALLOWED_CONTENT_TYPES:
        raise ArtifactValidationError(f"unsupported content type: {content_type}")


def validate_size(size: int, max_bytes: int) -> None:
    if size <= 0:
        raise ArtifactValidationError("empty upload")
    if size > max_bytes:
        raise ArtifactValidationError(f"file exceeds size limit of {max_bytes} bytes")


def validate_magic(path: Path) -> None:
    header = path.read_bytes()[:8]
    if not any(header.startswith(magic) for magic in ZIP_MAGICS):
        raise ArtifactValidationError("file is not a ZIP-based APK/AAB/IPA (missing PK magic)")


def _iter_zip_entries(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise ArtifactValidationError("corrupt ZIP archive")
            names: list[str] = []
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.header_offset < 0:
                    raise ArtifactValidationError("invalid ZIP entry metadata")
                # Zip bomb / compression ratio guard
                if info.compress_size and info.file_size / max(info.compress_size, 1) > 200:
                    raise ArtifactValidationError(f"suspicious compression ratio for {info.filename}")
                names.append(assert_relative_zip_entry(info.filename))
            return names
    except zipfile.BadZipFile as exc:
        raise ArtifactValidationError("file is not a valid ZIP archive") from exc
    except UnsafePathError as exc:
        raise ArtifactValidationError(str(exc)) from exc


def validate_artifact(path: Path, *, original_filename: str) -> ValidationResult:
    kind = detect_kind(original_filename)
    if kind is ArtifactKind.UNKNOWN:
        raise ArtifactValidationError("unable to detect artifact type from filename")
    validate_magic(path)
    entries = _iter_zip_entries(path)
    notes: list[str] = []
    if kind is ArtifactKind.APK:
        _validate_apk(entries, notes)
        platform = Platform.ANDROID
    elif kind is ArtifactKind.AAB:
        _validate_aab(entries, notes)
        platform = Platform.ANDROID
    else:
        _validate_ipa(entries, notes)
        platform = Platform.IOS
    return ValidationResult(
        kind=kind,
        platform=platform,
        filename=Path(original_filename).name,
        size=path.stat().st_size,
        zip_entries=entries,
        notes=notes,
    )


def _validate_apk(entries: list[str], notes: list[str]) -> None:
    names = set(entries)
    if "AndroidManifest.xml" not in names:
        raise ArtifactValidationError("APK is missing AndroidManifest.xml")
    if not any(name == "classes.dex" or name.startswith("classes") and name.endswith(".dex") for name in names):
        notes.append("APK does not contain a classes*.dex file; bytecode analysis will be limited")
    if "resources.arsc" not in names:
        notes.append("APK does not contain resources.arsc")


def _validate_aab(entries: list[str], notes: list[str]) -> None:
    names = set(entries)
    if "BundleConfig.pb" not in names:
        raise ArtifactValidationError("AAB is missing BundleConfig.pb")
    if "base/manifest/AndroidManifest.xml" not in names:
        raise ArtifactValidationError("AAB is missing base/manifest/AndroidManifest.xml")
    notes.append(
        "AAB is an Android App Bundle, not an installable APK. "
        "Milestone 1 inspects bundle metadata only; bundletool APK-set generation is not implemented."
    )


def _validate_ipa(entries: list[str], notes: list[str]) -> None:
    has_payload = any(name.startswith("Payload/") for name in entries)
    has_app = any(name.startswith("Payload/") and ".app/" in name for name in entries)
    if not has_payload or not has_app:
        raise ArtifactValidationError("IPA is missing Payload/*.app/")
    notes.append(
        "Dynamic iOS testing requires a supported macOS/device environment. "
        "Milestone 1 performs structural validation and limited metadata extraction only."
    )
