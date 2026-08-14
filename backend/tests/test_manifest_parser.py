from app.analyzers.axml import encode_axml, parse_axml, parse_manifest_bytes
from app.analyzers.metadata import metadata_from_manifest
from tests.helpers import vulnerable_manifest


def test_axml_round_trip_preserves_manifest_fields() -> None:
    original = vulnerable_manifest()
    encoded = encode_axml(original)
    assert encoded[:2] != b"<m"
    parsed = parse_axml(encoded)
    assert parsed.get("package") == "com.example.vulnerable"
    assert parsed.get("android:versionName") == "1.2.3"
    assert parsed.get("android:versionCode") == "42"
    sdk = parsed.find("uses-sdk")
    assert sdk is not None
    assert sdk.get("android:minSdkVersion") == "21"
    assert sdk.get("android:targetSdkVersion") == "28"
    permissions = [node.get("android:name") for node in parsed.findall("uses-permission")]
    assert "android.permission.CAMERA" in permissions
    application = parsed.find("application")
    assert application is not None
    assert application.get("android:debuggable") == "true"
    assert application.get("android:usesCleartextTraffic") == "true"
    activities = [child.get("android:name") for child in application.children if child.name == "activity"]
    assert ".MainActivity" in activities
    assert ".ExportedActivity" in activities


def test_plaintext_xml_fallback() -> None:
    xml = b"""<?xml version="1.0"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.plain.xml">
      <application android:debuggable="false"/>
    </manifest>
    """
    node = parse_manifest_bytes(xml)
    assert node.get("package") == "com.plain.xml"


def test_metadata_from_manifest() -> None:
    from app.models.enums import ArtifactKind

    meta = metadata_from_manifest(vulnerable_manifest(), kind=ArtifactKind.APK)
    assert meta.package_name == "com.example.vulnerable"
    assert meta.version_name == "1.2.3"
    assert meta.version_code == 42
    assert meta.min_sdk == 21
    assert meta.target_sdk == 28
    assert "android.permission.CAMERA" in meta.permissions
    assert ".MainActivity" in meta.activities
    assert ".ExportedService" in meta.services
    assert ".ExportedReceiver" in meta.receivers
    assert ".ExportedProvider" in meta.providers
    assert meta.main_activity is not None
    assert meta.main_activity.endswith("MainActivity")
