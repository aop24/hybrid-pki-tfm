from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api import health, system, ejbca, composite


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Administrative API for the hybrid PKI infrastructure."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health.router, prefix=settings.API_PREFIX)
app.include_router(system.router, prefix=settings.API_PREFIX)
app.include_router(ejbca.router, prefix=settings.API_PREFIX)
app.include_router(composite.router, prefix=settings.API_PREFIX)


@app.get("/")
async def root():
    return {
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "documentation": "/docs"
    }
