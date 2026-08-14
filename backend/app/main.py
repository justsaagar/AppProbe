"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import api_router
from app.config import Settings, get_settings
from app.scanners import default_scanners
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_service import ScanService
from app.storage.job_store import JsonJobStore
from app.storage.workspace import WorkspaceManager
from app.utils.logging import setup_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        setup_logging(resolved.log_level)
        resolved.workspace_dir.mkdir(parents=True, exist_ok=True)
        workspace = WorkspaceManager(resolved.workspace_dir)
        workspace.ensure_base()
        store = JsonJobStore(resolved.workspace_dir / "jobs.json")
        orchestrator = ScanOrchestrator(store, workspace, resolved, default_scanners())
        app.state.settings = resolved
        app.state.workspace = workspace
        app.state.store = store
        app.state.orchestrator = orchestrator
        app.state.scan_service = ScanService(store, workspace, resolved)
        yield

    application = FastAPI(
        title=resolved.app_name,
        version=__version__,
        description="Local-first mobile application QA and security analysis platform.",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(api_router)

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "milestone": "2.9"}

    return application


app = create_app()
