"""Read AndroidManifest.xml (and related metadata) from APK/AAB archives."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from app.analyzers.artifact import ZipInventory
from app.analyzers.axml import AxmlError, parse_manifest_bytes
from app.analyzers.manifest_parser import AndroidMetadata, parse_android_metadata
from app.config import Settings
from app.models.enums import ArtifactKind
from app.utils.paths import assert_relative_entry
from app.utils.redaction import redact_text


class MetadataError(ValueError):
    pass


def read_zip_member(path: Path, member: str, max_bytes: int) -> bytes:
    assert_relative_entry(member)
    with zipfile.ZipFile(path) as zf:
        try:
            info = zf.getinfo(member)
        except KeyError as exc:
            raise MetadataError(f"Archive member not found: {member}") from exc
        if info.file_size > max_bytes:
            raise MetadataError(f"Archive member too large: {member}")
        with zf.open(info, "r") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise MetadataError(f"Archive member too large: {member}")
        return data


def extract_android_metadata(
    path: Path,
    kind: ArtifactKind,
    inventory: ZipInventory,
    settings: Settings,
) -> AndroidMetadata:
    manifest_member = _manifest_member(kind, inventory)
    if not manifest_member:
        raise MetadataError("No AndroidManifest.xml found")
    try:
        raw = read_zip_member(path, manifest_member, settings.max_manifest_bytes)
        root = parse_manifest_bytes(raw)
        metadata = parse_android_metadata(root)
    except AxmlError as exc:
        raise MetadataError(str(exc)) from exc
    metadata.native_libraries = list(inventory.native_libraries)
    metadata.firebase_config_present = inventory.google_services_path is not None
    metadata.extra["manifest_member"] = manifest_member
    metadata.extra["manifest_format"] = (
        "text-xml" if raw.lstrip().startswith(b"<") else "binary-axml"
    )
    if inventory.google_services_path:
        metadata.extra["google_services_json"] = inventory.google_services_path
        try:
            gs = read_zip_member(path, inventory.google_services_path, 256_000)
            parsed = json.loads(gs.decode("utf-8"))
            project_id = parsed.get("project_info", {}).get("project_id")
            metadata.extra["firebase_project_id"] = redact_text(str(project_id)) if project_id else None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, MetadataError):
            metadata.extra["firebase_project_id"] = None
    return metadata


def _manifest_member(kind: ArtifactKind, inventory: ZipInventory) -> str | None:
    if kind == ArtifactKind.APK and inventory.has_android_manifest:
        for entry in inventory.entries:
            if entry == "AndroidManifest.xml":
                return entry
        return "AndroidManifest.xml"
    if kind == ArtifactKind.AAB:
        if inventory.has_base_manifest:
            return "base/manifest/AndroidManifest.xml"
        for entry in inventory.entries:
            if entry.endswith("manifest/AndroidManifest.xml"):
                return entry
    return None
