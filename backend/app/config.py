"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
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
        populate_by_name=True,
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
    tool_max_output_bytes: int = 1_048_576
    max_secret_file_bytes: int = Field(
        default=2 * 1024 * 1024,
        validation_alias=AliasChoices(
            "SECRET_SCAN_MAX_FILE_BYTES",
            "MAX_SECRET_FILE_BYTES",
            "max_secret_file_bytes",
        ),
    )
    max_secret_scan_files: int = 4000
    max_secret_scan_total_bytes: int = Field(
        default=32 * 1024 * 1024,
        validation_alias=AliasChoices(
            "SECRET_SCAN_MAX_TOTAL_BYTES",
            "MAX_SECRET_SCAN_TOTAL_BYTES",
            "max_secret_scan_total_bytes",
        ),
    )
    secret_scan_binary_string_limit: int = Field(
        default=2000,
        validation_alias=AliasChoices(
            "SECRET_SCAN_BINARY_STRING_LIMIT",
            "secret_scan_binary_string_limit",
        ),
    )

    advisory_network_enabled: bool = True
    osv_base_url: str = "https://api.osv.dev"
    advisory_timeout_seconds: float = 20.0
    advisory_connect_timeout_seconds: float = 5.0
    advisory_max_response_bytes: int = 1_048_576
    advisory_batch_size: int = 20
    advisory_max_concurrency: int = 2

    mobsf_enabled: bool = False
    mobsf_url: str = ""
    mobsf_api_key: str = ""
    mobsf_timeout_seconds: float = 30.0
    mobsf_connect_timeout_seconds: float = 5.0
    mobsf_poll_interval_seconds: float = 2.0
    mobsf_max_wait_seconds: float = 180.0
    mobsf_max_response_bytes: int = 8 * 1024 * 1024
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
