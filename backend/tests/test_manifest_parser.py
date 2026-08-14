from app.analyzers.axml import parse_manifest_bytes
from app.analyzers.manifest_parser import parse_android_metadata
from tests.helpers.apk_builder import build_axml_from_text, build_text_manifest


def test_text_manifest_metadata() -> None:
    xml = build_text_manifest(
        package="com.sample.app",
        version_name="2.3.4",
        version_code=88,
        min_sdk=24,
        target_sdk=34,
        permissions=["android.permission.CAMERA", "android.permission.INTERNET"],
        debuggable=True,
        allow_backup=True,
        cleartext=True,
        activities=[{"name": "com.sample.app.MainActivity", "exported": True, "launcher": True}],
        services=[{"name": "com.sample.app.SyncService", "exported": True}],
        receivers=[{"name": "com.sample.app.BootReceiver", "exported": False}],
        providers=[{"name": "com.sample.app.DataProvider", "exported": True, "authorities": "com.sample.app.provider"}],
    )
    root = parse_manifest_bytes(xml.encode("utf-8"))
    meta = parse_android_metadata(root)
    assert meta.package_name == "com.sample.app"
    assert meta.version_name == "2.3.4"
    assert meta.version_code == 88
    assert meta.min_sdk == 24
    assert meta.target_sdk == 34
    assert "android.permission.CAMERA" in meta.permissions
    assert meta.debuggable is True
    assert meta.allow_backup is True
    assert meta.uses_cleartext_traffic is True
    assert meta.activities[0].exported is True
    assert meta.services[0].exported is True
    assert meta.receivers[0].exported is False
    assert meta.providers[0].exported is True
    assert meta.providers[0].authorities == "com.sample.app.provider"


def test_binary_axml_round_trip() -> None:
    xml = build_text_manifest(
        package="com.binary.app",
        version_name="9.9",
        version_code=9,
        min_sdk=21,
        target_sdk=30,
        permissions=["android.permission.INTERNET"],
        debuggable=True,
        cleartext=True,
        activities=[{"name": ".Main", "exported": True, "launcher": True}],
    )
    binary = build_axml_from_text(xml)
    assert binary[:2] != b"<?"
    root = parse_manifest_bytes(binary)
    meta = parse_android_metadata(root)
    assert meta.package_name == "com.binary.app"
    assert meta.version_code == 9
    assert meta.min_sdk == 21
    assert meta.target_sdk == 30
    assert meta.debuggable is True
    assert meta.uses_cleartext_traffic is True
    assert meta.activities[0].name == ".Main"


def test_exported_default_with_intent_filter_pre_s() -> None:
    xml = build_text_manifest(
        target_sdk=29,
        activities=[{"name": ".Share", "intent_filters": [{"actions": ["android.intent.action.SEND"]}]}],
    )
    meta = parse_android_metadata(parse_manifest_bytes(xml.encode("utf-8")))
    assert meta.activities[0].exported is True


def test_exported_default_without_intent_filter() -> None:
    xml = build_text_manifest(activities=[{"name": ".Internal"}])
    meta = parse_android_metadata(parse_manifest_bytes(xml.encode("utf-8")))
    assert meta.activities[0].exported is False
