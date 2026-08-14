from pathlib import Path

import pytest

from app.utils.paths import PathTraversalError, safe_join, sanitize_filename


def test_sanitize_filename_strips_paths() -> None:
    assert sanitize_filename("../../etc/passwd.apk") == "passwd.apk"
    assert sanitize_filename("C:\\\\Windows\\\\app.apk") == "app.apk"
    assert sanitize_filename("") == "upload.bin"
    assert sanitize_filename("..") == "upload.bin"


def test_safe_join_allows_nested(tmp_path: Path) -> None:
    target = safe_join(tmp_path, "scans", "abc", "job.json")
    assert target.is_relative_to(tmp_path.resolve())


def test_safe_join_rejects_parent(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "..", "outside.txt")


def test_safe_join_rejects_absolute(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "/etc/passwd")
