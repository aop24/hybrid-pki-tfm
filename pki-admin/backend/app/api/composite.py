import subprocess
import logging

from fastapi import APIRouter, HTTPException, Query

from app.services.composite.service import CompositeService


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/composite",
    tags=["Composite PKI"]
)

service = CompositeService()


@router.get("/health")
async def composite_health():
    try:
        return {
            "connected": True,
            **service.get_summary()
        }
    except (OSError, ValueError):
        logger.exception("Composite health check failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to read Composite PKI data"
        )


@router.get("/summary")
async def get_composite_summary():
    try:
        return service.get_summary()
    except (OSError, ValueError):
        logger.exception("Composite summary failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve Composite summary"
        )


@router.get("/certificates")
async def get_composite_certificates(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100)
):
    try:
        return service.get_certificates(
            page=page,
            page_size=page_size
        )
    except FileNotFoundError:
        logger.exception("Composite certificate file not found")
        raise HTTPException(
            status_code=500,
            detail="A Composite certificate file is missing"
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        logger.exception("Composite certificate search failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve Composite certificates"
        )
