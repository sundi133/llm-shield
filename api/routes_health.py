import asyncio
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

# Build/commit marker so a deployed image is identifiable from outside (answers
# "what code is actually running?" without shell access). Resolution order:
#   1. SHIELD_BUILD_SHA        - explicit override, baked at build time (Dockerfile ARG)
#   2. RAILWAY_GIT_COMMIT_SHA  - auto-injected by Railway; zero-config there
#   3. "unknown"               - local/dev or a builder that sets neither
# Read once at import; the value is fixed for the life of the container.
BUILD_SHA = (
    os.getenv("SHIELD_BUILD_SHA")
    or os.getenv("RAILWAY_GIT_COMMIT_SHA")
    or "unknown"
)


@router.get("/ping")
async def health_check():
    return {"status": "healthy"}


@router.get("/health")
async def health():
    return {"status": "healthy", "build": BUILD_SHA}


@router.get("/health/ready")
async def ready():
    """Readiness: 503 when Redis is configured but does not answer, so the pod
    leaves the Service instead of serving from a per-process memory store.
    /health stays the liveness check and never touches Redis."""
    from storage.tenant_store import readiness_body, redis_ready
    code, body = readiness_body(await asyncio.to_thread(redis_ready))
    return JSONResponse(status_code=code, content={**body, "build": BUILD_SHA})
