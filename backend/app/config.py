"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _repo_root() -> Path:
    # backend/app/config.py -> repository root
    return Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Runtime settings. Secrets must come from the environment, never source."""

    model_config = SettingsConfigDict(
        env_file=(_repo_root() / ".env", Path(".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AppProbe"
    app_env: str = "development"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8000

    max_upload_bytes: int = 200 * 1024 * 1024
    workspace_dir: Path = Field(default=_repo_root() / "workspace")
    allowed_extensions: tuple[str, ...] = (".apk", ".aab", ".ipa")

    subprocess_timeout_seconds: int = 60
    scan_stage_timeout_seconds: int = 300
    tool_timeout_seconds: int = 180
    max_secret_file_bytes: int = 2 * 1024 * 1024
    max_secret_scan_files: int = 4000

    mobsf_url: str = ""
    mobsf_api_key: str = ""
    jadx_bin: str = ""
    apktool_bin: str = ""

    # Milestone 6 placeholders — unused in Milestone 2.
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str = ""
    llm_provider: str = ""

    cors_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )

    @property
    def repo_root(self) -> Path:
        return _repo_root()


@lru_cache
def get_settings() -> Settings:
    return Settings()
