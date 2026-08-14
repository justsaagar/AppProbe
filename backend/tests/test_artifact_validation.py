from pathlib import Path

import pytest

from app.analyzers.artifact import ArtifactValidationError, validate_artifact_file
from app.config import Settings
from tests.helpers.apk_builder import build_aab_bytes, build_apk_bytes, build_ipa_bytes


def test_valid_apk(tmp_path: Path, tmp_settings: Settings) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(build_apk_bytes(package="com.valid.app"))
    result = validate_artifact_file(
        apk, original_filename="app.apk", content_type="application/vnd.android.package-archive", settings=tmp_settings
    )
    assert result.kind.value == "apk"
    assert result.platform.value == "android"
    assert result.inventory.has_android_manifest


def test_rejects_non_zip(tmp_path: Path, tmp_settings: Settings) -> None:
    blob = tmp_path / "app.apk"
    blob.write_bytes(b"not-an-apk")
    with pytest.raises(ArtifactValidationError, match="ZIP magic"):
        validate_artifact_file(blob, original_filename="app.apk", content_type=None, settings=tmp_settings)


def test_rejects_zip_without_manifest(tmp_path: Path, tmp_settings: Settings) -> None:
    import zipfile

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex")
    with pytest.raises(ArtifactValidationError, match="AndroidManifest"):
        validate_artifact_file(apk, original_filename="app.apk", content_type=None, settings=tmp_settings)


def test_rejects_bad_extension(tmp_path: Path, tmp_settings: Settings) -> None:
    blob = tmp_path / "app.exe"
    blob.write_bytes(build_apk_bytes())
    with pytest.raises(ArtifactValidationError, match="Unsupported extension"):
        validate_artifact_file(blob, original_filename="app.exe", content_type=None, settings=tmp_settings)


def test_rejects_zip_slip(tmp_path: Path, tmp_settings: Settings) -> None:
    import zipfile

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("../evil.txt", b"nope")
    with pytest.raises(ArtifactValidationError, match="traversal"):
        validate_artifact_file(apk, original_filename="app.apk", content_type=None, settings=tmp_settings)


def test_aab_structure(tmp_path: Path, tmp_settings: Settings) -> None:
    aab = tmp_path / "app.aab"
    aab.write_bytes(build_aab_bytes(package="com.bundle.app"))
    result = validate_artifact_file(aab, original_filename="app.aab", content_type="application/octet-stream", settings=tmp_settings)
    assert result.kind.value == "aab"
    assert any("bundletool" in note.lower() or "AAB" in note for note in result.notes)


def test_ipa_structure(tmp_path: Path, tmp_settings: Settings) -> None:
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(build_ipa_bytes())
    result = validate_artifact_file(ipa, original_filename="app.ipa", content_type="application/octet-stream", settings=tmp_settings)
    assert result.platform.value == "ios"
    assert any("macOS" in note for note in result.notes)


def test_size_limit(tmp_path: Path, tmp_settings: Settings) -> None:
    tmp_settings.max_upload_bytes = 10
    apk = tmp_path / "app.apk"
    apk.write_bytes(build_apk_bytes())
    with pytest.raises(ArtifactValidationError, match="size limit"):
        validate_artifact_file(apk, original_filename="app.apk", content_type=None, settings=tmp_settings)
