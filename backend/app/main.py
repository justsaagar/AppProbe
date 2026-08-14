from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import Settings, get_settings
from app.services.pipeline import ScanPipeline
from app.services.scan_service import ScanService
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager
from app.utils.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="AppProbe",
        description="Local-first mobile application QA and security analysis platform (Milestone 1).",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    workspace = WorkspaceManager(settings)
    store = JobStore(workspace)
    pipeline = ScanPipeline(settings, workspace, store)
    service = ScanService(settings, workspace, store, pipeline)
    app.state.settings = settings
    app.state.workspace = workspace
    app.state.scan_service = service
    app.include_router(api_router, prefix="/api")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "milestone": "1"}

    return app


app = create_app()
