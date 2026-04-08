"""Agents Registry API - Simple agent management endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/v1/agents", tags=["agents-registry"])


@router.get("/registry")
async def get_agents_registry():
    """Get all registered agents and their configurations."""
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
        },
        {
            "agent_id": "finance-analyst",
            "name": "Finance AI Assistant",
            "description": "Financial data analysis and reporting",
            "tools": ["financial_reports", "market_analysis"],
            "role_permissions": {
                "analyst": ["financial_reports", "market_analysis"],
                "manager": ["financial_reports"],
                "employee": []
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


@router.get("/tools/policies")
async def get_tool_policies():
    """Get tool policies for frontend."""
    mock_policies = [
        {
            "tool_name": "patient_lookup",
            "data_sanitization": {
                "redact_ssn": True,
                "redact_phone": True,
                "redact_email": False
            },
            "role_restrictions": {
                "doctor": "allow",
                "nurse": "redact",
                "patient": "block"
            },
            "compliance_framework": "hipaa"
        },
        {
            "tool_name": "financial_reports",
            "data_sanitization": {
                "redact_account_numbers": True,
                "redact_ssn": True,
                "mask_sensitive_amounts": True
            },
            "role_restrictions": {
                "analyst": "allow",
                "manager": "redact",
                "employee": "block"
            },
            "compliance_framework": "pci_dss"
        }
    ]

    return {
        "success": True,
        "tool_policies": mock_policies,
        "total": len(mock_policies)
    }