"""iOS IPA static inspection.

Dynamic testing is explicitly out of scope until a macOS/device runner exists.
"""

from __future__ import annotations

import plistlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analyzers.artifact import ZipInventory
from app.config import Settings
from app.utils.paths import assert_relative_entry


@dataclass
class IosMetadata:
    bundle_id: str | None = None
    version: str | None = None
    build: str | None = None
    display_name: str | None = None
    minimum_os_version: str | None = None
    permissions: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "version": self.version,
            "build": self.build,
            "display_name": self.display_name,
            "minimum_os_version": self.minimum_os_version,
            "permissions": self.permissions,
            "extra": self.extra,
        }


IOS_DYNAMIC_UNAVAILABLE = (
    "Dynamic iOS testing requires a supported macOS/device environment. "
    "Runtime testing was not executed."
)


def inspect_ipa(path: Path, inventory: ZipInventory, settings: Settings) -> IosMetadata:
    info_path = next(
        (
            entry
            for entry in inventory.entries
            if entry.startswith("Payload/") and entry.endswith(".app/Info.plist")
        ),
        None,
    )
    meta = IosMetadata()
    meta.extra["dynamic_testing"] = "not_executed"
    meta.extra["dynamic_testing_reason"] = IOS_DYNAMIC_UNAVAILABLE
    if not info_path:
        return meta
    assert_relative_entry(info_path)
    with zipfile.ZipFile(path) as zf:
        info = zf.getinfo(info_path)
        if info.file_size > settings.max_manifest_bytes:
            return meta
        raw = zf.read(info_path)
    try:
        plist = plistlib.loads(raw)
    except Exception:
        meta.extra["info_plist_parse"] = "failed"
        return meta
    meta.bundle_id = plist.get("CFBundleIdentifier")
    meta.version = plist.get("CFBundleShortVersionString")
    meta.build = str(plist.get("CFBundleVersion")) if plist.get("CFBundleVersion") is not None else None
    meta.display_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName")
    meta.minimum_os_version = plist.get("MinimumOSVersion")
    usage_keys = [key for key in plist if str(key).endswith("UsageDescription")]
    meta.permissions = sorted(usage_keys)
    meta.extra["info_plist"] = info_path
    return meta
