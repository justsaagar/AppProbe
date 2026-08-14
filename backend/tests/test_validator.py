from pathlib import Path

import pytest

from app.analyzers.validator import ArtifactValidationError, validate_artifact
from tests.helpers import write_aab, write_apk, write_ipa


def test_validate_apk_structure(tmp_path: Path) -> None:
    apk = write_apk(tmp_path / "sample.apk")
    result = validate_artifact(apk, original_filename="sample.apk")
    assert result.kind.value == "apk"
    assert result.platform.value == "android"
    assert "AndroidManifest.xml" in result.zip_entries


def test_reject_non_zip(tmp_path: Path) -> None:
    path = tmp_path / "fake.apk"
    path.write_bytes(b"not an apk")
    with pytest.raises(ArtifactValidationError, match="ZIP"):
        validate_artifact(path, original_filename="fake.apk")


def test_reject_apk_without_manifest(tmp_path: Path) -> None:
    import zipfile

    path = tmp_path / "empty.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    with pytest.raises(ArtifactValidationError, match="AndroidManifest"):
        validate_artifact(path, original_filename="empty.apk")


def test_reject_zip_slip(tmp_path: Path) -> None:
    import zipfile

    path = tmp_path / "slip.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../evil.txt", b"nope")
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
    with pytest.raises(ArtifactValidationError, match="traversal"):
        validate_artifact(path, original_filename="slip.apk")


def test_validate_aab_and_ipa(tmp_path: Path) -> None:
    aab = write_aab(tmp_path / "app.aab")
    aab_result = validate_artifact(aab, original_filename="app.aab")
    assert aab_result.kind.value == "aab"
    assert any("not an installable APK" in note for note in aab_result.notes)

    ipa = write_ipa(tmp_path / "app.ipa")
    ipa_result = validate_artifact(ipa, original_filename="app.ipa")
    assert ipa_result.platform.value == "ios"
    assert any("macOS" in note for note in ipa_result.notes)


def test_reject_unknown_extension(tmp_path: Path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"PK\x03\x04")
    with pytest.raises(ArtifactValidationError):
        validate_artifact(path, original_filename="file.bin")
