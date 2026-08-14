"""Android App Bundle inspection for Milestone 1.

Does not convert the bundle into an installable APK. bundletool belongs to a later milestone.
"""

from __future__ import annotations

from pathlib import Path

from app.analyzers.apk import extract_android_metadata
from app.analyzers.artifact import ZipInventory
from app.analyzers.manifest_parser import AndroidMetadata
from app.config import Settings
from app.models.enums import ArtifactKind


def inspect_aab(
    path: Path,
    inventory: ZipInventory,
    settings: Settings,
) -> tuple[AndroidMetadata, list[str]]:
    notes = [
        "AAB structure inspected. An installable APK set was not generated because bundletool is not integrated in Milestone 1.",
        "Do not treat this AAB as an already-installable APK.",
    ]
    metadata = extract_android_metadata(path, ArtifactKind.AAB, inventory, settings)
    modules = sorted(
        {
            entry.split("/")[0]
            for entry in inventory.entries
            if "/" in entry and not entry.startswith("BundleConfig")
        }
    )
    metadata.extra["bundle_modules"] = modules
    metadata.extra["bundletool_used"] = False
    metadata.extra["apk_generation"] = "not_attempted"
    return metadata, notes
