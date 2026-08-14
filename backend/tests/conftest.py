from pathlib import Path

import pytest

from app.config import Settings
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager


@pytest.fixture
def tmp_settings(tmp_path: Path) -> Settings:
    settings = Settings(workspace_dir=tmp_path / "workspace")
    settings.workspace_dir.mkdir(parents=True, exist_ok=True)
    return settings


@pytest.fixture
def workspace(tmp_settings: Settings) -> WorkspaceManager:
    return WorkspaceManager(tmp_settings)


@pytest.fixture
def store(workspace: WorkspaceManager) -> JobStore:
    return JobStore(workspace)
