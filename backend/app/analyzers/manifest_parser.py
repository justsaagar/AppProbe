"""Extract structured application metadata from a parsed Android manifest."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.analyzers.axml import AxmlNode


@dataclass
class ComponentInfo:
    kind: str
    name: str
    exported: bool | None
    permission: str | None = None
    intent_filters: list[dict[str, Any]] = field(default_factory=list)
    authorities: str | None = None
    grant_uri_permissions: bool | None = None


@dataclass
class AndroidMetadata:
    package_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    activities: list[ComponentInfo] = field(default_factory=list)
    services: list[ComponentInfo] = field(default_factory=list)
    receivers: list[ComponentInfo] = field(default_factory=list)
    providers: list[ComponentInfo] = field(default_factory=list)
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    application_name: str | None = None
    custom_permissions: list[dict[str, Any]] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    firebase_config_present: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "permissions": self.permissions,
            "activities": [c.__dict__ for c in self.activities],
            "services": [c.__dict__ for c in self.services],
            "receivers": [c.__dict__ for c in self.receivers],
            "providers": [c.__dict__ for c in self.providers],
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "application_name": self.application_name,
            "custom_permissions": self.custom_permissions,
            "native_libraries": self.native_libraries,
            "firebase_config_present": self.firebase_config_present,
            "extra": self.extra,
        }


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in {"true", "1"}:
            return True
        if lowered in {"false", "0"}:
            return False
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    return None


def _collect_intent_filters(node: AxmlNode) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = []
    for intent in node.findall("intent-filter"):
        filters.append(
            {
                "actions": [child.attr("name") for child in intent.findall("action") if child.attr("name")],
                "categories": [
                    child.attr("name") for child in intent.findall("category") if child.attr("name")
                ],
                "data": [
                    {
                        "scheme": child.attr("scheme"),
                        "host": child.attr("host"),
                        "path": child.attr("path"),
                        "mimeType": child.attr("mimeType"),
                    }
                    for child in intent.findall("data")
                ],
            }
        )
    return filters


def _exported_default(component: AxmlNode, target_sdk: int | None, kind: str) -> bool | None:
    explicit = _bool(component.attr("exported"))
    if explicit is not None:
        return explicit
    has_filters = bool(component.findall("intent-filter"))
    if kind == "provider":
        if target_sdk is not None and target_sdk >= 17:
            return False
        return True if target_sdk is None else False
    if has_filters:
        if target_sdk is not None and target_sdk >= 31:
            return None
        return True
    return False


def _component(node: AxmlNode, kind: str, target_sdk: int | None) -> ComponentInfo | None:
    name = node.attr("name")
    if not name:
        return None
    return ComponentInfo(
        kind=kind,
        name=str(name),
        exported=_exported_default(node, target_sdk, kind),
        permission=str(node.attr("permission")) if node.attr("permission") is not None else None,
        intent_filters=_collect_intent_filters(node),
        authorities=str(node.attr("authorities")) if node.attr("authorities") is not None else None,
        grant_uri_permissions=_bool(node.attr("grantUriPermissions")),
    )


def parse_android_metadata(root: AxmlNode) -> AndroidMetadata:
    meta = AndroidMetadata()
    meta.package_name = _stringify(root.attr("package"))
    meta.version_name = _stringify(root.attr("versionName"))
    meta.version_code = _int(root.attr("versionCode"))
    meta.compile_sdk = _int(root.attr("compileSdkVersion"))

    for uses_sdk in root.findall("uses-sdk"):
        meta.min_sdk = _int(uses_sdk.attr("minSdkVersion")) or meta.min_sdk
        meta.target_sdk = _int(uses_sdk.attr("targetSdkVersion")) or meta.target_sdk

    permissions: list[str] = []
    for perm in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
        name = perm.attr("name")
        if name:
            permissions.append(str(name))
    meta.permissions = sorted(set(permissions))

    for perm in root.findall("permission"):
        meta.custom_permissions.append(
            {
                "name": perm.attr("name"),
                "protectionLevel": perm.attr("protectionLevel"),
            }
        )

    applications = root.findall("application")
    if applications:
        app = applications[0]
        meta.application_name = _stringify(app.attr("name"))
        meta.debuggable = _bool(app.attr("debuggable"))
        meta.allow_backup = _bool(app.attr("allowBackup"))
        meta.uses_cleartext_traffic = _bool(app.attr("usesCleartextTraffic"))
        meta.network_security_config = _stringify(app.attr("networkSecurityConfig"))
        target = meta.target_sdk
        for kind, tag in (
            ("activity", "activity"),
            ("activity", "activity-alias"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider"),
        ):
            bucket = {
                "activity": meta.activities,
                "service": meta.services,
                "receiver": meta.receivers,
                "provider": meta.providers,
            }[kind]
            for child in app.findall(tag):
                info = _component(child, kind if tag != "activity-alias" else "activity", target)
                if info:
                    bucket.append(info)
    return meta


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def lookup_protection_level(metadata: AndroidMetadata, permission: str | None) -> str | None:
    if not permission:
        return None
    for item in metadata.custom_permissions:
        if item.get("name") == permission:
            level = item.get("protectionLevel")
            return str(level) if level is not None else None
    if permission.startswith("android.permission."):
        return "system"
    return None
