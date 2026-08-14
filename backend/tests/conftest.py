from pathlib import Path

import pytest

from app.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(workspace_dir=tmp_path / "workspace", max_upload_bytes=5 * 1024 * 1024)
