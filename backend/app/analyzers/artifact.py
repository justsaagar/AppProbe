"""Validate untrusted APK/AAB/IPA uploads without executing them."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings
from app.models.enums import ArtifactKind, Platform
from app.utils.paths import PathTraversalError, assert_relative_entry, sanitize_filename

ZIP_MAGIC = b"PK\x03\x04"
ALLOWED_MIMES = {
    "application/vnd.android.package-archive",
    "application/java-archive",
    "application/zip",
    "application/octet-stream",
    "application/x-zip-compressed",
    "application/iphone",
    "application/x-itunes-ipa",
}


class ArtifactValidationError(ValueError):
    """Raised when an uploaded artifact is rejected."""


@dataclass
class ZipInventory:
    entries: list[str] = field(default_factory=list)
    uncompressed_total: int = 0
    has_android_manifest: bool = False
    has_bundle_config: bool = False
    has_base_manifest: bool = False
    has_payload_app: bool = False
    native_libraries: list[str] = field(default_factory=list)
    google_services_path: str | None = None


@dataclass
class ValidationResult:
    kind: ArtifactKind
    platform: Platform
    stored_filename: str
    size_bytes: int
    zip_ok: bool
    notes: list[str] = field(default_factory=list)
    inventory: ZipInventory = field(default_factory=ZipInventory)


def detect_kind(filename: str) -> ArtifactKind:
    suffix = Path(sanitize_filename(filename)).suffix.lower()
    if suffix == ".apk":
        return ArtifactKind.APK
    if suffix == ".aab":
        return ArtifactKind.AAB
    if suffix == ".ipa":
        return ArtifactKind.IPA
    return ArtifactKind.UNKNOWN


def validate_filename(filename: str, settings: Settings) -> str:
    cleaned = sanitize_filename(filename)
    suffix = Path(cleaned).suffix.lower()
    if suffix not in settings.allowed_extensions:
        raise ArtifactValidationError(
            f"Unsupported extension '{suffix or '<none>'}'. Allowed: {', '.join(settings.allowed_extensions)}"
        )
    return cleaned


def validate_size(size: int, settings: Settings) -> None:
    if size <= 0:
        raise ArtifactValidationError("Empty upload rejected")
    if size > settings.max_upload_bytes:
        raise ArtifactValidationError(
            f"Upload exceeds size limit of {settings.max_upload_bytes} bytes"
        )


def validate_content_type(content_type: str | None) -> None:
    if not content_type:
        return
    mime = content_type.split(";")[0].strip().lower()
    if mime and mime not in ALLOWED_MIMES:
        raise ArtifactValidationError(f"Unsupported content type: {mime}")


def inspect_zip(path: Path, settings: Settings) -> ZipInventory:
    inventory = ZipInventory()
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > settings.max_zip_entries:
                raise ArtifactValidationError("Archive contains too many entries")
            for info in infos:
                assert_relative_entry(info.filename)
                if info.file_size < 0:
                    raise ArtifactValidationError("Negative file size in archive")
                inventory.uncompressed_total += info.file_size
                if inventory.uncompressed_total > settings.max_uncompressed_bytes:
                    raise ArtifactValidationError("Uncompressed archive size exceeds limit")
                name = info.filename.replace("\\", "/")
                inventory.entries.append(name)
                lowered = name.lower()
                if name == "AndroidManifest.xml" or lowered == "androidmanifest.xml":
                    inventory.has_android_manifest = True
                if name == "BundleConfig.pb" or name.endswith("/BundleConfig.pb"):
                    inventory.has_bundle_config = True
                if name == "base/manifest/AndroidManifest.xml":
                    inventory.has_base_manifest = True
                if name.startswith("Payload/") and name.endswith(".app/") or "/Payload/" in f"/{name}":
                    if ".app" in name:
                        inventory.has_payload_app = True
                if lowered.startswith("lib/") and lowered.endswith(".so"):
                    inventory.native_libraries.append(name)
                if lowered.endswith("google-services.json"):
                    inventory.google_services_path = name
            if any(entry.startswith("Payload/") and ".app" in entry for entry in inventory.entries):
                inventory.has_payload_app = True
    except zipfile.BadZipFile as exc:
        raise ArtifactValidationError("File is not a valid ZIP/APK/AAB/IPA archive") from exc
    except PathTraversalError as exc:
        raise ArtifactValidationError(str(exc)) from exc
    return inventory


def validate_artifact_file(
    path: Path,
    *,
    original_filename: str,
    content_type: str | None,
    settings: Settings,
) -> ValidationResult:
    stored = validate_filename(original_filename, settings)
    validate_content_type(content_type)
    size = path.stat().st_size
    validate_size(size, settings)
    header = path.read_bytes()[:4]
    if header != ZIP_MAGIC:
        raise ArtifactValidationError("File does not start with ZIP magic bytes")

    kind = detect_kind(stored)
    inventory = inspect_zip(path, settings)
    notes: list[str] = []
    platform = Platform.UNKNOWN

    if kind == ArtifactKind.APK:
        platform = Platform.ANDROID
        if not inventory.has_android_manifest:
            raise ArtifactValidationError("APK is missing AndroidManifest.xml")
    elif kind == ArtifactKind.AAB:
        platform = Platform.ANDROID
        if not (inventory.has_bundle_config or inventory.has_base_manifest):
            raise ArtifactValidationError(
                "AAB is missing BundleConfig.pb and base/manifest/AndroidManifest.xml"
            )
        notes.append(
            "AAB detected. Milestone 1 does not convert the bundle to an installable APK via bundletool."
        )
    elif kind == ArtifactKind.IPA:
        platform = Platform.IOS
        if not inventory.has_payload_app:
            raise ArtifactValidationError("IPA is missing Payload/*.app")
        notes.append(
            "iOS IPA accepted for static metadata only. Dynamic iOS testing requires a supported macOS/device environment."
        )
    else:
        raise ArtifactValidationError("Unable to determine artifact type")

    return ValidationResult(
        kind=kind,
        platform=platform,
        stored_filename=stored,
        size_bytes=size,
        zip_ok=True,
        notes=notes,
        inventory=inventory,
    )
