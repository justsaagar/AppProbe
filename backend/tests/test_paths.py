from pathlib import Path

import pytest

from app.utils.paths import (
    UnsafePathError,
    assert_relative_zip_entry,
    safe_join,
    sanitize_filename,
)


def test_sanitize_filename_strips_directories() -> None:
    assert sanitize_filename("../../etc/passwd.apk") == "passwd.apk"
    assert sanitize_filename("My App (1).apk") == "My_App_1_.apk"
    assert sanitize_filename("") == "upload.bin"


def test_sanitize_rejects_nul() -> None:
    with pytest.raises(UnsafePathError):
        sanitize_filename("ok\x00.apk")


def test_zip_entry_traversal_rejected() -> None:
    with pytest.raises(UnsafePathError):
        assert_relative_zip_entry("../AndroidManifest.xml")
    with pytest.raises(UnsafePathError):
        assert_relative_zip_entry("/tmp/evil")
    assert assert_relative_zip_entry("res/values/strings.xml") == "res/values/strings.xml"


def test_safe_join(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    inside = safe_join(root, "a", "b.txt")
    assert str(inside).startswith(str(root.resolve()))
    with pytest.raises(UnsafePathError):
        safe_join(root, "..", "b.txt")
