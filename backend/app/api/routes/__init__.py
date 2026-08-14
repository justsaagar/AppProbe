from fastapi import APIRouter

from app.api.routes.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(scans_router)
