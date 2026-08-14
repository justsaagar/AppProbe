"""Extract application metadata from APK, AAB, or IPA artifacts."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

from app.analyzers.axml import XmlNode, parse_manifest_bytes
from app.analyzers.validator import ValidationResult
from app.models.enums import ArtifactKind, Platform
from app.models.scan_job import ApplicationMetadata
from app.utils.paths import assert_relative_zip_entry


class MetadataError(ValueError):
    pass


def extract_metadata(path: Path, validation: ValidationResult) -> ApplicationMetadata:
    if validation.kind is ArtifactKind.APK:
        return _from_apk(path, validation)
    if validation.kind is ArtifactKind.AAB:
        return _from_aab(path, validation)
    if validation.kind is ArtifactKind.IPA:
        return _from_ipa(path, validation)
    raise MetadataError("unsupported artifact kind")


def load_manifest_from_apk(path: Path) -> XmlNode:
    data = _zip_read(path, "AndroidManifest.xml")
    return parse_manifest_bytes(data)


def load_manifest_from_aab(path: Path) -> XmlNode:
    data = _zip_read(path, "base/manifest/AndroidManifest.xml")
    return parse_manifest_bytes(data)


def metadata_from_manifest(manifest: XmlNode, *, kind: ArtifactKind) -> ApplicationMetadata:
    application = manifest.find("application")
    uses_sdk = manifest.find("uses-sdk")

    package = manifest.get("package")
    version_name = manifest.get("android:versionName") or manifest.get("versionName")
    version_code = _maybe_int(manifest.get("android:versionCode") or manifest.get("versionCode"))
    min_sdk = _maybe_int(uses_sdk.get("android:minSdkVersion") if uses_sdk else None)
    target_sdk = _maybe_int(uses_sdk.get("android:targetSdkVersion") if uses_sdk else None)
    if min_sdk is None:
        min_sdk = _maybe_int(manifest.get("android:minSdkVersion"))
    if target_sdk is None:
        target_sdk = _maybe_int(manifest.get("android:targetSdkVersion"))

    permissions = [
        perm.get("android:name") or perm.get("name") or ""
        for perm in manifest.findall("uses-permission")
    ]
    permissions = [item for item in permissions if item]

    activities = _component_names(application, "activity") if application else []
    services = _component_names(application, "service") if application else []
    receivers = _component_names(application, "receiver") if application else []
    providers = _component_names(application, "provider") if application else []
    main_activity = _find_launcher_activity(application, package) if application else None

    return ApplicationMetadata(
        platform=Platform.ANDROID,
        artifact_kind=kind,
        package_name=package,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=permissions,
        activities=activities,
        services=services,
        receivers=receivers,
        providers=providers,
        application_label=(application.get("android:label") if application else None),
        main_activity=main_activity,
        extra={"manifest_tag": manifest.name},
    )


def _from_apk(path: Path, validation: ValidationResult) -> ApplicationMetadata:
    manifest = load_manifest_from_apk(path)
    metadata = metadata_from_manifest(manifest, kind=ArtifactKind.APK)
    metadata.native_libraries = sorted(
        {entry for entry in validation.zip_entries if entry.startswith("lib/") and entry.endswith(".so")}
    )
    metadata.extra["zip_entry_count"] = len(validation.zip_entries)
    metadata.extra["has_dex"] = any(
        name == "classes.dex" or (name.startswith("classes") and name.endswith(".dex"))
        for name in validation.zip_entries
    )
    metadata.extra["has_resources_arsc"] = "resources.arsc" in validation.zip_entries
    return metadata


def _from_aab(path: Path, validation: ValidationResult) -> ApplicationMetadata:
    manifest = load_manifest_from_aab(path)
    metadata = metadata_from_manifest(manifest, kind=ArtifactKind.AAB)
    metadata.extra["bundletool_used"] = False
    metadata.extra["apk_generation"] = (
        "not_performed: AAB was not converted to an installable APK set. "
        "bundletool integration is planned for a later milestone."
    )
    metadata.extra["zip_entry_count"] = len(validation.zip_entries)
    native = [
        entry
        for entry in validation.zip_entries
        if "/lib/" in entry and entry.endswith(".so")
    ]
    metadata.native_libraries = sorted(native)
    return metadata


def _from_ipa(path: Path, validation: ValidationResult) -> ApplicationMetadata:
    info = _read_ipa_info_plist(path)
    metadata = ApplicationMetadata(
        platform=Platform.IOS,
        artifact_kind=ArtifactKind.IPA,
        package_name=info.get("CFBundleIdentifier"),
        version_name=info.get("CFBundleShortVersionString") or info.get("CFBundleVersion"),
        extra={
            "bundle_name": info.get("CFBundleName"),
            "display_name": info.get("CFBundleDisplayName"),
            "dynamic_testing": (
                "Dynamic iOS testing requires a supported macOS/device environment. "
                "It was not executed."
            ),
            "zip_entry_count": len(validation.zip_entries),
        },
    )
    return metadata


def _read_ipa_info_plist(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        candidates = [
            name
            for name in archive.namelist()
            if name.startswith("Payload/") and name.endswith(".app/Info.plist")
        ]
        if not candidates:
            return {}
        data = archive.read(candidates[0])
    try:
        loaded = plistlib.loads(data)
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _zip_read(path: Path, name: str) -> bytes:
    assert_relative_zip_entry(name)
    with zipfile.ZipFile(path) as archive:
        try:
            return archive.read(name)
        except KeyError as exc:
            raise MetadataError(f"missing ZIP entry: {name}") from exc


def _maybe_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        if value.startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def _component_names(application: XmlNode, tag: str) -> list[str]:
    names: list[str] = []
    for node in application.children:
        if node.name != tag:
            continue
        name = node.get("android:name") or node.get("name")
        if name:
            names.append(name)
    return names


def _find_launcher_activity(application: XmlNode, package: str | None) -> str | None:
    for activity in application.children:
        if activity.name not in {"activity", "activity-alias"}:
            continue
        for intent_filter in activity.children:
            if intent_filter.name != "intent-filter":
                continue
            actions = {
                child.get("android:name") or child.get("name")
                for child in intent_filter.children
                if child.name == "action"
            }
            categories = {
                child.get("android:name") or child.get("name")
                for child in intent_filter.children
                if child.name == "category"
            }
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                name = activity.get("android:name") or activity.get("name")
                if name and package and name.startswith("."):
                    return package + name
                return name
    return None
