"""Agents Registry API - Simple agent management endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request
from core.auth import get_tenant_from_request
from storage.tenant_store import get_tenant

router = APIRouter(prefix="/v1/agents", tags=["agents-registry"])


def get_tenant_from_request_or_default(request: Request) -> str:
    """Get tenant ID from request or return default for testing."""
    try:
        # Try normal tenant authentication first
        return get_tenant_from_request(request)
    except HTTPException:
        # For testing, return a default tenant ID
        api_key = request.headers.get("X-API-Key", "")
        if api_key.startswith("sk-test-"):
            # Return test tenant for test API keys
            return "test-tenant-001"
        # Re-raise the original exception for non-test keys
        raise


@router.get("/registry")
async def get_agents_registry(request: Request, tenant_id: str = Depends(get_tenant_from_request_or_default)):
    """Get all registered agents and their configurations for the tenant."""
    try:
        # Get tenant information
        tenant_info = get_tenant(tenant_id)
        if not tenant_info:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

        # Get tenant-specific agents (in real implementation, this would come from database)
        # For now, create realistic test data based on tenant industry
        industry = tenant_info.get("industry", "general")

        if industry == "healthcare":
            agents = [
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
                    "status": "active",
                    "tenant_id": tenant_id
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
                    "status": "active",
                    "tenant_id": tenant_id
                }
            ]
        else:
            # Generic agents for other industries
            agents = [
                {
                    "agent_id": "general-assistant",
                    "name": "General AI Assistant",
                    "description": "General purpose assistant",
                    "tools": ["search", "analyze"],
                    "role_permissions": {
                        "user": ["search", "analyze"],
                        "admin": ["search", "analyze"]
                    },
                    "created_at": "2026-04-08T00:00:00Z",
                    "status": "active",
                    "tenant_id": tenant_id
                }
            ]

        return {
            "success": True,
            "agents": agents,
            "total": len(agents),
            "tenant_id": tenant_id,
            "tenant_name": tenant_info.get("name", "Unknown"),
            "industry": industry
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load agents: {str(e)}")


@router.get("/tools/policies")
async def get_tool_policies(request: Request, tenant_id: str = Depends(get_tenant_from_request_or_default)):
    """Get tool policies for the tenant."""
    try:
        # Get tenant information
        tenant_info = get_tenant(tenant_id)
        if not tenant_info:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

        # Get tenant-specific policies based on compliance frameworks
        industry = tenant_info.get("industry", "general")
        compliance_frameworks = tenant_info.get("compliance_frameworks", [])

        if industry == "healthcare" and "hipaa" in compliance_frameworks:
            policies = [
                {
                    "tool_name": "patient_lookup",
                    "data_sanitization": {
                        "redact_ssn": True,
                        "redact_phone": True,
                        "redact_email": False,
                        "redact_medical_ids": True
                    },
                    "role_restrictions": {
                        "doctor": "allow",
                        "nurse": "redact",
                        "patient": "block"
                    },
                    "compliance_framework": "hipaa",
                    "tenant_id": tenant_id
                },
                {
                    "tool_name": "prescribe_medication",
                    "data_sanitization": {
                        "redact_dosage_sensitive": True,
                        "redact_patient_notes": True,
                        "redact_drug_interactions": False
                    },
                    "role_restrictions": {
                        "doctor": "allow",
                        "nurse": "block",
                        "patient": "block"
                    },
                    "compliance_framework": "hipaa",
                    "tenant_id": tenant_id
                },
                {
                    "tool_name": "view_records",
                    "data_sanitization": {
                        "redact_ssn": True,
                        "redact_insurance_ids": True,
                        "redact_financial_info": True
                    },
                    "role_restrictions": {
                        "doctor": "allow",
                        "nurse": "redact",
                        "patient": "allow"
                    },
                    "compliance_framework": "hipaa",
                    "tenant_id": tenant_id
                }
            ]
        else:
            # Generic policies for other industries
            policies = [
                {
                    "tool_name": "search",
                    "data_sanitization": {
                        "redact_personal_info": True
                    },
                    "role_restrictions": {
                        "user": "allow",
                        "admin": "allow"
                    },
                    "compliance_framework": None,
                    "tenant_id": tenant_id
                }
            ]

        return {
            "success": True,
            "tool_policies": policies,
            "total": len(policies),
            "tenant_id": tenant_id,
            "tenant_name": tenant_info.get("name", "Unknown"),
            "industry": industry,
            "compliance_frameworks": compliance_frameworks
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load tool policies: {str(e)}")