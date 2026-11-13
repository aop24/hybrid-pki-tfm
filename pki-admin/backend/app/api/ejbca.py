import logging

import httpx

from fastapi import APIRouter, HTTPException, Query

from app.services.ejbca.service import EJBCAService


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/ejbca",
    tags=["EJBCA"]
)

service = EJBCAService()


@router.get("/health")
async def ejbca_health():
    try:
        status = await service.get_status()

        return {
            "connected": True,
            "status": status.get("status"),
            "version": status.get("version"),
            "revision": status.get("revision")
        }

    except (httpx.HTTPError, ValueError):
        logger.exception("EJBCA health check failed")

        raise HTTPException(
            status_code=502,
            detail="Unable to communicate with EJBCA"
        )


@router.get("/cas")
async def get_certificate_authorities():
    try:
        authorities = await service.get_certificate_authorities()

        return {
            "count": len(authorities),
            "certificate_authorities": authorities
        }

    except (httpx.HTTPError, ValueError):
        logger.exception("EJBCA CA query failed")

        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve EJBCA certificate authorities"
        )


@router.get("/certificates")
async def get_certificates(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100)
):
    try:
        return await service.get_certificates(
            page=page,
            page_size=page_size
        )

    except (httpx.HTTPError, ValueError, KeyError):
        logger.exception("EJBCA certificate search failed")

        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve EJBCA certificates"
        )
