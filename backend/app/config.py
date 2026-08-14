from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables / .env."""

    model_config = SettingsConfigDict(
        env_prefix="MOBILE_AGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    workspace_dir: Path = Field(default=Path("workspace"))
    max_upload_bytes: int = 200 * 1024 * 1024
    max_uncompressed_bytes: int = 800 * 1024 * 1024
    max_zip_entries: int = 20_000
    max_manifest_bytes: int = 8 * 1024 * 1024
    subprocess_timeout_seconds: float = 120.0
    allowed_extensions: tuple[str, ...] = (".apk", ".aab", ".ipa")
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""

    @property
    def uploads_dir(self) -> Path:
        return self.workspace_dir / "uploads"

    @property
    def scans_dir(self) -> Path:
        return self.workspace_dir / "scans"

    @property
    def artifacts_dir(self) -> Path:
        return self.workspace_dir / "artifacts"

    @property
    def screenshots_dir(self) -> Path:
        return self.workspace_dir / "screenshots"

    @property
    def logs_dir(self) -> Path:
        return self.workspace_dir / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.workspace_dir / "reports"


def get_settings() -> Settings:
    return Settings()
