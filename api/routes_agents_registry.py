"""Agents Registry API - Direct Redis access for tenant data."""

from fastapi import APIRouter, Depends, HTTPException, Request
from core.auth import get_tenant_from_request
from storage.tenant_store import get_tenant, resolve_tenant_by_api_key
import redis
import json
import os

router = APIRouter(prefix="/v1/agents", tags=["agents-registry"])

# Direct Redis connection
redis_client = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))

def get_tenant_from_api_key(request: Request) -> str:
    """Get tenant ID directly from API key without complex auth."""
    api_key = request.headers.get("X-API-Key", "").strip()

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    # For test keys, return test tenant
    if api_key.startswith("sk-test-"):
        return "test-tenant-001"

    # Direct Redis lookup for real tenant keys
    tenant_id = resolve_tenant_by_api_key(api_key)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return tenant_id


@router.get("/registry")
async def get_agents_registry(request: Request):
    """Get all registered agents directly from Redis for the tenant."""
    try:
        tenant_id = get_tenant_from_api_key(request)

        # Direct Redis lookup for agents
        agents_key = f"tenant:{tenant_id}:agents"

        try:
            agents_data = redis_client.get(agents_key)
            if agents_data:
                agents = json.loads(agents_data)
            else:
                agents = {}
        except Exception as e:
            print(f"Redis error: {e}")
            agents = {}

        return {
            "success": True,
            "agents": agents,
            "total": len(agents),
            "tenant_id": tenant_id,
            "source": "redis_direct"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load agents: {str(e)}")


@router.get("/tools/policies")
async def get_tool_policies(request: Request):
    """Get tool policies directly from Redis for the tenant."""
    try:
        tenant_id = get_tenant_from_api_key(request)

        # Direct Redis lookup for tool policies
        policies_key = f"tenant:{tenant_id}:policies"

        try:
            policies_data = redis_client.get(policies_key)
            if policies_data:
                # Parse as array format for frontend compatibility
                policies = json.loads(policies_data)
                # Convert to array if it's an object
                if isinstance(policies, dict):
                    policies = list(policies.values())
            else:
                policies = []
        except Exception as e:
            print(f"Redis error: {e}")
            policies = []

        return {
            "success": True,
            "tool_policies": policies,
            "total": len(policies),
            "tenant_id": tenant_id,
            "source": "redis_direct"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load tool policies: {str(e)}")


@router.post("/seed-test-data")
async def seed_test_data():
    """Seed test tenant with sample agents and policies data."""
    try:
        tenant_id = "test-tenant-001"

        # Sample healthcare agents
        agents = {
            "healthcare-doctor": {
                "agent_id": "healthcare-doctor",
                "name": "Healthcare Doctor Assistant",
                "description": "AI assistant for doctors with full medical access",
                "tools": ["patient_lookup", "diagnosis_update", "prescribe_medication", "view_records"],
                "role_permissions": {
                    "doctor": ["patient_lookup", "diagnosis_update", "prescribe_medication", "view_records"],
                    "nurse": ["patient_lookup"],
                    "admin": ["patient_lookup"],
                    "patient": []
                },
                "created_at": 1775632429,
                "updated_at": 1775632429
            },
            "healthcare-nurse": {
                "agent_id": "healthcare-nurse",
                "name": "Healthcare Nurse Assistant",
                "description": "AI assistant for nurses with limited medical access",
                "tools": ["patient_lookup", "schedule_appointment", "update_vitals", "view_basic_records"],
                "role_permissions": {
                    "nurse": ["patient_lookup", "schedule_appointment", "update_vitals", "view_basic_records"],
                    "doctor": ["patient_lookup", "schedule_appointment"],
                    "admin": ["patient_lookup"],
                    "patient": []
                },
                "created_at": 1775632479,
                "updated_at": 1775632479
            }
        }

        # Sample tool policies
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
                "compliance_framework": "hipaa"
            },
            {
                "tool_name": "prescribe_medication",
                "data_sanitization": {
                    "redact_dosage_sensitive": True,
                    "redact_patient_notes": True
                },
                "role_restrictions": {
                    "doctor": "allow",
                    "nurse": "block",
                    "patient": "block"
                },
                "compliance_framework": "hipaa"
            }
        ]

        # Store in Redis
        redis_client.set(f"tenant:{tenant_id}:agents", json.dumps(agents))
        redis_client.set(f"tenant:{tenant_id}:policies", json.dumps(policies))

        return {
            "success": True,
            "message": f"Test data seeded for tenant {tenant_id}",
            "agents_count": len(agents),
            "policies_count": len(policies)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to seed test data: {str(e)}")