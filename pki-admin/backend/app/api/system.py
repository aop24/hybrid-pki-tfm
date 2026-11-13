from fastapi import APIRouter
from app.core.config import settings

router = APIRouter(
    prefix="/system",
    tags=["System"]
)


@router.get("/info")
async def system_info():
    return {
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "environment": "development"
    }
