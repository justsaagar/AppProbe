"""Build minimal APK/AAB/IPA fixtures for tests. Never uses production credentials."""

from __future__ import annotations

import io
import json
import plistlib
import struct
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from app.analyzers.axml import (
    ANDROID_NS,
    RES_STRING_POOL_TYPE,
    RES_XML_END_ELEMENT_TYPE,
    RES_XML_END_NAMESPACE_TYPE,
    RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_START_NAMESPACE_TYPE,
    RES_XML_TYPE,
    TYPE_INT_BOOLEAN,
    TYPE_INT_DEC,
    TYPE_STRING,
)

ANDROID_ATTR_RESOURCE_IDS = {
    "theme": 0x01010000,
    "label": 0x01010001,
    "name": 0x01010003,
    "permission": 0x01010006,
    "protectionLevel": 0x01010009,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "authorities": 0x01010018,
    "allowBackup": 0x0101002D,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
    "usesCleartextTraffic": 0x010104EC,
    "networkSecurityConfig": 0x01010527,
}


def build_text_manifest(
    *,
    package: str = "com.example.app",
    version_name: str = "1.0",
    version_code: int = 1,
    min_sdk: int = 21,
    target_sdk: int = 33,
    permissions: list[str] | None = None,
    debuggable: bool = False,
    allow_backup: bool = False,
    cleartext: bool = False,
    activities: list[dict] | None = None,
    services: list[dict] | None = None,
    receivers: list[dict] | None = None,
    providers: list[dict] | None = None,
) -> str:
    perms = permissions or []
    acts = activities or [{"name": ".MainActivity", "exported": True, "launcher": True}]
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        (
            f'<manifest xmlns:android="{ANDROID_NS}" package="{escape(package)}"'
            f' android:versionCode="{version_code}" android:versionName="{escape(version_name)}">'
        ),
        f'  <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="{target_sdk}" />',
    ]
    for perm in perms:
        lines.append(f'  <uses-permission android:name="{escape(perm)}" />')
    app_attrs = ['android:name=".App"']
    if debuggable:
        app_attrs.append('android:debuggable="true"')
    if allow_backup:
        app_attrs.append('android:allowBackup="true"')
    if cleartext:
        app_attrs.append('android:usesCleartextTraffic="true"')
    lines.append(f'  <application {" ".join(app_attrs)}>')
    for item in acts:
        lines.append(_component_xml("activity", item))
    for item in services or []:
        lines.append(_component_xml("service", item))
    for item in receivers or []:
        lines.append(_component_xml("receiver", item))
    for item in providers or []:
        lines.append(_component_xml("provider", item))
    lines.append("  </application>")
    lines.append("</manifest>")
    return "\n".join(lines)


def _component_xml(kind: str, item: dict) -> str:
    name = escape(str(item["name"]))
    exported = item.get("exported")
    permission = item.get("permission")
    attrs = [f'android:name="{name}"']
    if exported is not None:
        attrs.append(f'android:exported="{"true" if exported else "false"}"')
    if permission:
        attrs.append(f'android:permission="{escape(str(permission))}"')
    if kind == "provider" and item.get("authorities"):
        attrs.append(f'android:authorities="{escape(str(item["authorities"]))}"')
    inner = ""
    if item.get("launcher") or item.get("intent_filters"):
        filters = item.get("intent_filters") or [
            {
                "actions": ["android.intent.action.MAIN"],
                "categories": ["android.intent.category.LAUNCHER"],
            }
        ]
        parts = []
        for flt in filters:
            parts.append("      <intent-filter>")
            for action in flt.get("actions") or []:
                parts.append(f'        <action android:name="{escape(action)}" />')
            for category in flt.get("categories") or []:
                parts.append(f'        <category android:name="{escape(category)}" />')
            parts.append("      </intent-filter>")
        inner = "\n" + "\n".join(parts) + "\n    "
        return f'    <{kind} {" ".join(attrs)}>\n{inner}</{kind}>'
    return f'    <{kind} {" ".join(attrs)} />'


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def build_apk_bytes(*, binary_manifest: bool = False, extra_entries: dict[str, bytes] | None = None, **manifest_kwargs) -> bytes:
    xml = build_text_manifest(**manifest_kwargs)
    manifest = build_axml_from_text(xml) if binary_manifest else xml.encode("utf-8")
    entries = {
        "AndroidManifest.xml": manifest,
        "classes.dex": b"dex\n035\x00fake",
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
    }
    if extra_entries:
        entries.update(extra_entries)
    return _zip_bytes(entries)


def write_apk(path: Path, **kwargs) -> Path:
    path.write_bytes(build_apk_bytes(**kwargs))
    return path


def build_aab_bytes(**manifest_kwargs) -> bytes:
    xml = build_text_manifest(**manifest_kwargs)
    return _zip_bytes(
        {
            "BundleConfig.pb": b"\x0a\x04test",
            "base/manifest/AndroidManifest.xml": xml.encode("utf-8"),
            "base/dex/classes.dex": b"dex\n035\x00fake",
        }
    )


def build_ipa_bytes(
    *,
    bundle_id: str = "com.example.ios",
    version: str = "1.2.3",
    build: str = "42",
) -> bytes:
    plist = plistlib.dumps(
        {
            "CFBundleIdentifier": bundle_id,
            "CFBundleShortVersionString": version,
            "CFBundleVersion": build,
            "CFBundleName": "Example",
            "MinimumOSVersion": "15.0",
            "NSCameraUsageDescription": "Camera",
        }
    )
    return _zip_bytes({"Payload/Example.app/Info.plist": plist})


def build_axml_from_text(xml: str) -> bytes:
    """Minimal binary AXML encoder used to test the parser round-trip."""
    root = ET.fromstring(xml)
    strings: list[str] = []
    resource_ids: list[int] = []

    def intern(value: str | None) -> int:
        if value is None:
            return 0xFFFFFFFF
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    intern(ANDROID_NS)
    intern("android")
    for res_name in ANDROID_ATTR_RESOURCE_IDS:
        intern(res_name)
        while len(resource_ids) < len(strings):
            name = strings[len(resource_ids)]
            resource_ids.append(ANDROID_ATTR_RESOURCE_IDS.get(name, 0))

    def intern_tree(element: ET.Element) -> None:
        intern(element.tag.split("}")[-1])
        for key, value in element.attrib.items():
            intern(key.split("}")[-1])
            intern(value)
        for child in list(element):
            intern_tree(child)

    intern_tree(root)

    chunks: list[bytes] = []
    chunks.append(_string_pool(strings))
    chunks.append(_resource_map(resource_ids))
    chunks.append(_namespace_chunk(True, intern("android"), intern(ANDROID_NS)))
    chunks.extend(_element_chunks(root, intern))
    chunks.append(_namespace_chunk(False, intern("android"), intern(ANDROID_NS)))
    body = b"".join(chunks)
    header = struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body))
    return header + body


def _string_pool(strings: list[str]) -> bytes:
    offsets = []
    data = b""
    for item in strings:
        encoded = item.encode("utf-16le")
        char_len = len(item)
        entry = struct.pack("<H", char_len) + encoded + struct.pack("<H", 0)
        pad = (4 - (len(entry) % 4)) % 4
        offsets.append(len(data))
        data += entry + (b"\x00" * pad)
    header_size = 28
    offsets_blob = b"".join(struct.pack("<I", off) for off in offsets)
    strings_start = header_size + len(offsets_blob)
    size = strings_start + len(data)
    header = struct.pack(
        "<HHIIIIII",
        RES_STRING_POOL_TYPE,
        header_size,
        size,
        len(strings),
        0,
        0,
        strings_start,
        0,
    )
    return header + offsets_blob + data


def _resource_map(resource_ids: list[int]) -> bytes:
    payload = b"".join(struct.pack("<I", rid) for rid in resource_ids)
    size = 8 + len(payload)
    return struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, size) + payload


def _namespace_chunk(start: bool, prefix: int, uri: int) -> bytes:
    ctype = RES_XML_START_NAMESPACE_TYPE if start else RES_XML_END_NAMESPACE_TYPE
    header = struct.pack("<HHI", ctype, 16, 24)
    node = struct.pack("<II", 1, 0xFFFFFFFF)
    ext = struct.pack("<II", prefix, uri)
    return header + node + ext


def _element_chunks(element: ET.Element, intern) -> list[bytes]:
    name = intern(element.tag.split("}")[-1])
    attrs = []
    for key, raw in element.attrib.items():
        attr_name = key.split("}")[-1]
        ns = intern(ANDROID_NS) if key.startswith("{") or attr_name in ANDROID_ATTR_RESOURCE_IDS else 0xFFFFFFFF
        if attr_name == "package":
            ns = 0xFFFFFFFF
        name_idx = intern(attr_name)
        value, data_type, data = _typed_value(attr_name, raw, intern)
        raw_idx = intern(raw) if data_type == TYPE_STRING else 0xFFFFFFFF
        attrs.append((ns, name_idx, raw_idx, data_type, data, value))
    start = _start_element(0xFFFFFFFF, name, attrs)
    chunks = [start]
    for child in list(element):
        chunks.extend(_element_chunks(child, intern))
    chunks.append(_end_element(0xFFFFFFFF, name))
    return chunks


def _typed_value(name: str, raw: str, intern) -> tuple[str, int, int]:
    if raw in {"true", "false"}:
        return raw, TYPE_INT_BOOLEAN, 0xFFFFFFFF if raw == "true" else 0
    if name in {"versionCode", "minSdkVersion", "targetSdkVersion"} and raw.isdigit():
        return raw, TYPE_INT_DEC, int(raw)
    return raw, TYPE_STRING, intern(raw)


def _start_element(ns: int, name: int, attrs: list[tuple]) -> bytes:
    attr_ext_size = 20
    attr_size = 20
    size = 16 + attr_ext_size + attr_size * len(attrs)
    header = struct.pack("<HHI", RES_XML_START_ELEMENT_TYPE, 16, size)
    node = struct.pack("<II", 1, 0xFFFFFFFF)
    ext = struct.pack("<IIHHHHHH", ns, name, 20, attr_size, len(attrs), 0, 0, 0)
    blob = b""
    for ans, aname, raw_idx, data_type, data, _value in attrs:
        blob += struct.pack("<IIIHBBI", ans, aname, raw_idx, 8, 0, data_type, data)
    return header + node + ext + blob


def _end_element(ns: int, name: int) -> bytes:
    header = struct.pack("<HHI", RES_XML_END_ELEMENT_TYPE, 16, 24)
    node = struct.pack("<II", 1, 0xFFFFFFFF)
    ext = struct.pack("<II", ns, name)
    return header + node + ext


def firebase_config_bytes() -> bytes:
    return json.dumps(
        {
            "project_info": {"project_id": "example-test-project"},
            "client": [{"api_key": [{"current_key": "AIzaSyDummyTestKeyNotReal"}]}],
        }
    ).encode("utf-8")
