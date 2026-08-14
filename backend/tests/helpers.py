"""Helpers for building synthetic Android/iOS artifacts used in tests."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

from app.analyzers.axml import XmlNode, encode_axml


def vulnerable_manifest() -> XmlNode:
    return XmlNode(
        name="manifest",
        attributes={
            "package": "com.example.vulnerable",
            "android:versionCode": "42",
            "android:versionName": "1.2.3",
        },
        children=[
            XmlNode(
                name="uses-sdk",
                attributes={
                    "android:minSdkVersion": "21",
                    "android:targetSdkVersion": "28",
                },
            ),
            XmlNode(name="uses-permission", attributes={"android:name": "android.permission.INTERNET"}),
            XmlNode(name="uses-permission", attributes={"android:name": "android.permission.CAMERA"}),
            XmlNode(
                name="application",
                attributes={
                    "android:label": "VulnApp",
                    "android:debuggable": "true",
                    "android:allowBackup": "true",
                    "android:usesCleartextTraffic": "true",
                },
                children=[
                    XmlNode(
                        name="activity",
                        attributes={"android:name": ".MainActivity", "android:exported": "true"},
                        children=[
                            XmlNode(
                                name="intent-filter",
                                children=[
                                    XmlNode(
                                        name="action",
                                        attributes={"android:name": "android.intent.action.MAIN"},
                                    ),
                                    XmlNode(
                                        name="category",
                                        attributes={"android:name": "android.intent.category.LAUNCHER"},
                                    ),
                                ],
                            )
                        ],
                    ),
                    XmlNode(
                        name="activity",
                        attributes={"android:name": ".ExportedActivity", "android:exported": "true"},
                    ),
                    XmlNode(
                        name="service",
                        attributes={"android:name": ".ExportedService", "android:exported": "true"},
                    ),
                    XmlNode(
                        name="receiver",
                        attributes={"android:name": ".ExportedReceiver", "android:exported": "true"},
                    ),
                    XmlNode(
                        name="provider",
                        attributes={
                            "android:name": ".ExportedProvider",
                            "android:exported": "true",
                            "android:authorities": "com.example.vulnerable.provider",
                        },
                    ),
                ],
            ),
        ],
    )


def write_apk(path: Path, manifest: XmlNode | None = None) -> Path:
    node = manifest or vulnerable_manifest()
    encoded = encode_axml(node)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", encoded)
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        archive.writestr("resources.arsc", b"\x00" * 16)
        archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF")
    return path


def write_aab(path: Path, manifest: XmlNode | None = None) -> Path:
    node = manifest or vulnerable_manifest()
    encoded = encode_axml(node)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("BundleConfig.pb", b"\x0a\x00")
        archive.writestr("base/manifest/AndroidManifest.xml", encoded)
        archive.writestr("base/dex/classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        archive.writestr("base/lib/arm64-v8a/libdemo.so", b"\x7fELF")
    return path


def write_ipa(path: Path) -> Path:
    plist = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.iosdemo",
            "CFBundleName": "iOSDemo",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
        }
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/iOSDemo.app/Info.plist", plist)
        archive.writestr("Payload/iOSDemo.app/iOSDemo", b"\x00")
    return path
