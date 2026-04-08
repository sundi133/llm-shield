from fastapi import APIRouter

router = APIRouter()


@router.get("/ping")
async def health_check():
    return {"status": "healthy"}


@router.get("/health")
async def health():
    return {"status": "healthy"}


@router.get("/v1/agents/registry")
async def temp_agent_registry():
    """Temporary agent registry endpoint for frontend compatibility."""
    # Mock response matching expected format
    mock_agents = [
        {
            "agent_id": "healthcare-doctor",
            "name": "Doctor AI Assistant",
            "description": "Healthcare assistant with full patient access",
            "tools": ["patient_lookup", "prescribe_medication", "view_records"],
            "role_permissions": {
                "doctor": ["patient_lookup", "prescribe_medication", "view_records"],
                "nurse": ["patient_lookup"],
                "patient": []
            },
            "created_at": "2026-04-08T00:00:00Z",
            "status": "active"
        },
        {
            "agent_id": "healthcare-nurse",
            "name": "Nurse AI Assistant",
            "description": "Healthcare assistant with limited access",
            "tools": ["patient_lookup"],
            "role_permissions": {
                "nurse": ["patient_lookup"],
                "patient": []
            },
            "created_at": "2026-04-08T00:00:00Z",
            "status": "active"
        }
    ]

    return {
        "success": True,
        "agents": mock_agents,
        "total": len(mock_agents)
    }
