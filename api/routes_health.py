import os

from fastapi import APIRouter

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
