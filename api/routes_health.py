from fastapi import APIRouter

router = APIRouter()


@router.get("/ping")
async def health_check():
    return {"status": "healthy"}


@router.get("/health")
async def health():
    return {"status": "healthy"}
