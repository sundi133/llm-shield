"""RBAC testing endpoint - proxies tool checks to avoid CORS issues"""

import os
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# Configuration from environment
RUNPOD_TOKEN = os.getenv("RUNPOD_TOKEN")
RUNPOD_ENDPOINT = os.getenv("RUNPOD_ENDPOINT", "https://kk5losqxwr2ui7.api.runpod.ai")

class RBACTestRequest(BaseModel):
    agent_key: str
    tool_name: str
    user_role: Optional[str] = None
    tool_params: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None

@router.post("/api/rbac/test-tool")
async def test_tool_permission(request: RBACTestRequest, req: Request):
    """
    Proxy tool permission testing to avoid CORS issues in frontend
    """
    try:
        # Check environment configuration
        if not RUNPOD_TOKEN:
            raise HTTPException(status_code=500, detail="RUNPOD_TOKEN environment variable not configured")

        # Get API key from request headers
        api_key = req.headers.get("X-API-Key")
        if not api_key:
            raise HTTPException(status_code=400, detail="X-API-Key header is required")

        # Build request to RunPod endpoint
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {RUNPOD_TOKEN}",
            "X-API-Key": api_key,
            "X-Agent-Key": request.agent_key
        }

        # Only add role header if provided
        if request.user_role:
            headers["X-User-Role"] = request.user_role

        payload = {
            "agent_key": request.agent_key,
            "tool_name": request.tool_name,
            "session_id": request.session_id or f"rbac-test-{req.client.host}",
            "tool_params": request.tool_params or {}
        }

        # Make request to RunPod endpoint
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RUNPOD_ENDPOINT}/v1/shield/tool/check",
                headers=headers,
                json=payload,
                timeout=30.0
            )

            # Forward the response
            if response.status_code == 200:
                result = response.json()
                return result
            else:
                # Forward error response
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("detail", error_detail)
                except:
                    pass

                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"RunPod API error: {error_detail}"
                )

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request to RunPod endpoint timed out")
    except httpx.RequestError as e:
        logger.error(f"Request error: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to connect to RunPod endpoint: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in RBAC testing: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/api/rbac/health")
async def rbac_health():
    """Health check for RBAC testing endpoint"""
    return {
        "status": "healthy",
        "runpod_endpoint": RUNPOD_ENDPOINT,
        "has_token": bool(RUNPOD_TOKEN)
    }