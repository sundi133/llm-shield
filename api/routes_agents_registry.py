"""Agents Registry API - Direct Redis access for tenant data."""

import re
import json

from fastapi import APIRouter, HTTPException, Request
from storage.tenant_store import resolve_tenant_by_api_key, _get_redis

router = APIRouter(prefix="/v1/agents", tags=["agents-registry"])

_VALID_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_MAX_STRING_LEN = 500
_MAX_TOOL_NAME_LEN = 128
_MAX_TOOLS_PER_AGENT = 200


def _validate_agent_id(agent_id: str) -> None:
    """Reject agent IDs that contain path-traversal or special characters.

    IEMLabs VAPT finding 8.7 (Improper Input Validation, May 2026).
    """
    if not agent_id or not _VALID_ID_RE.match(agent_id):
        raise HTTPException(
            status_code=400,
            detail="agent_id must be 1-128 characters, alphanumeric, hyphens, or underscores only",
        )


def _sanitize_string(value: str, max_len: int = _MAX_STRING_LEN) -> str:
    """Strip HTML/JS tags from user-provided strings to prevent stored XSS.

    IEMLabs VAPT finding 8.7 (Improper Input Validation, May 2026).
    """
    if not isinstance(value, str):
        return value
    cleaned = _HTML_TAG_RE.sub("", value)
    return cleaned[:max_len]


def _sanitize_value(value, max_len: int = _MAX_STRING_LEN):
    """Recursively sanitize strings within dicts and lists."""
    if isinstance(value, str):
        return _sanitize_string(value, max_len)
    if isinstance(value, dict):
        return {_sanitize_string(str(k), _MAX_TOOL_NAME_LEN): _sanitize_value(v, max_len) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(item, max_len) for item in value[:_MAX_TOOLS_PER_AGENT]]
    return value


def _validate_agent_body(body: dict) -> None:
    """Validate agent registration/update body fields.

    IEMLabs VAPT finding 8.7 (Improper Input Validation, May 2026).
    """
    name = body.get("name", "")
    if isinstance(name, str) and len(name) > _MAX_STRING_LEN:
        raise HTTPException(status_code=400, detail=f"name must be at most {_MAX_STRING_LEN} characters")

    desc = body.get("description", "")
    if isinstance(desc, str) and len(desc) > _MAX_STRING_LEN:
        raise HTTPException(status_code=400, detail=f"description must be at most {_MAX_STRING_LEN} characters")

    tools = body.get("tools", [])
    if not isinstance(tools, list):
        raise HTTPException(status_code=400, detail="tools must be a list")
    if len(tools) > _MAX_TOOLS_PER_AGENT:
        raise HTTPException(status_code=400, detail=f"too many tools (max {_MAX_TOOLS_PER_AGENT})")
    for t in tools:
        if not isinstance(t, str) or not _VALID_ID_RE.match(t):
            raise HTTPException(
                status_code=400,
                detail=f"tool name must be 1-128 alphanumeric/hyphen/underscore characters, got: {str(t)[:50]}",
            )

    status = body.get("status")
    if status is not None and status not in ("active", "inactive", "disabled"):
        raise HTTPException(status_code=400, detail="status must be active, inactive, or disabled")

def get_tenant_from_api_key(request: Request) -> str:
    """Get tenant ID directly from API key via Redis lookup."""
    api_key = request.headers.get("X-API-Key", "").strip()

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    tenant_id = resolve_tenant_by_api_key(api_key)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return tenant_id

def get_redis_data(key: str):
    """Get data from Redis using the same connection as tenant_store."""
    redis_client = _get_redis()
    if redis_client:
        try:
            data = redis_client.get(key)
            if data:
                if isinstance(data, str):
                    return json.loads(data)
                return data
        except Exception as e:
            print(f"Redis error getting {key}: {e}")
    return None


@router.get("/registry")
async def get_agents_registry(request: Request):
    """Get all registered agents directly from Redis for the tenant."""
    try:
        tenant_id = get_tenant_from_api_key(request)

        # Direct Redis lookup for agents using correct production key format
        agents_key = f"agents:{tenant_id}"
        agents = get_redis_data(agents_key)

        if agents is None:
            agents = {}

        return {
            "success": True,
            "agents": agents,
            "total": len(agents),
            "tenant_id": tenant_id,
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
        policies_key = f"policies:{tenant_id}"
        policies_data = get_redis_data(policies_key)

        if policies_data:
            if isinstance(policies_data, list):
                policies = {p.get("tool_name", f"tool_{i}"): p for i, p in enumerate(policies_data)}
            elif isinstance(policies_data, dict):
                policies = policies_data
            else:
                policies = {}
        else:
            policies = {}

        return {
            "success": True,
            "tool_policies": policies,
            "total": len(policies),
            "tenant_id": tenant_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load tool policies: {str(e)}")


@router.get("/tools/policies/{tool_name}")
async def get_single_tool_policy(tool_name: str, request: Request):
    """Get a single tool policy by name."""
    try:
        tenant_id = get_tenant_from_api_key(request)
        policies_key = f"policies:{tenant_id}"
        policies = get_redis_data(policies_key) or {}

        if isinstance(policies, list):
            policies = {p.get("tool_name", f"tool_{i}"): p for i, p in enumerate(policies)}

        if tool_name not in policies:
            raise HTTPException(status_code=404, detail=f"Tool policy '{tool_name}' not found")

        return {
            "success": True,
            "tool_name": tool_name,
            "policy": policies[tool_name],
            "tenant_id": tenant_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get tool policy: {str(e)}")


@router.get("/roles")
async def get_available_roles(request: Request):
    """Get all roles defined across registered agents for this tenant."""
    try:
        tenant_id = get_tenant_from_api_key(request)
        agents_key = f"agents:{tenant_id}"
        agents = get_redis_data(agents_key) or {}

        role_set = set()
        for agent in agents.values():
            if isinstance(agent, dict):
                for role in (agent.get("role_permissions") or {}).keys():
                    role_set.add(role)

        common_roles = ["admin", "user", "viewer", "editor", "operator",
                        "doctor", "nurse", "patient", "manager", "analyst"]

        return {
            "success": True,
            "tenant_roles": sorted(role_set),
            "common_roles": common_roles,
            "tenant_id": tenant_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get roles: {str(e)}")


@router.put("/tools/policies")
async def save_all_tool_policies(request: Request):
    """Replace all tool policies for the tenant."""
    try:
        tenant_id = get_tenant_from_api_key(request)
        body = await request.json()

        if "policies" in body and isinstance(body["policies"], dict) and len(body) <= 2:
            body = body["policies"]

        policies_key = f"policies:{tenant_id}"
        import time as _time
        body["updated_at"] = int(_time.time())

        redis_client = _get_redis()
        if redis_client:
            redis_client.set(policies_key, json.dumps(body))
        else:
            raise Exception("Redis connection not available")

        return {"success": True, "message": "Tool policies saved"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save tool policies: {str(e)}")


@router.delete("/tools/policies/{tool_name}")
async def delete_tool_policy(tool_name: str, request: Request):
    """Delete a single tool policy."""
    try:
        tenant_id = get_tenant_from_api_key(request)
        policies_key = f"policies:{tenant_id}"
        policies = get_redis_data(policies_key) or {}

        if isinstance(policies, list):
            policies = {p.get("tool_name", f"tool_{i}"): p for i, p in enumerate(policies)}

        if tool_name not in policies:
            raise HTTPException(status_code=404, detail="Tool policy not found")

        del policies[tool_name]

        redis_client = _get_redis()
        if redis_client:
            redis_client.set(policies_key, json.dumps(policies))
        else:
            raise Exception("Redis connection not available")

        return {"success": True, "message": f"Tool policy '{tool_name}' deleted"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete tool policy: {str(e)}")


@router.get("/unregistered")
async def get_unregistered(request: Request):
    """Get agents and tools that were used but never registered."""
    try:
        tenant_id = get_tenant_from_api_key(request)
        key = f"unregistered:{tenant_id}"
        data = get_redis_data(key) or {"agents": {}, "tools": {}}
        return {
            "success": True,
            "tenant_id": tenant_id,
            "unregistered_agents": data.get("agents", {}),
            "unregistered_tools": data.get("tools", {}),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load unregistered items: {str(e)}")


@router.delete("/unregistered/{item_type}/{item_id}")
async def dismiss_unregistered(item_type: str, item_id: str, request: Request):
    """Dismiss (remove) a tracked unregistered agent or tool."""
    if item_type not in ("agents", "tools"):
        raise HTTPException(status_code=400, detail="item_type must be 'agents' or 'tools'")
    try:
        tenant_id = get_tenant_from_api_key(request)
        key = f"unregistered:{tenant_id}"
        redis_client = _get_redis()
        if not redis_client:
            raise Exception("Redis connection not available")

        raw = redis_client.get(key)
        data = json.loads(raw) if raw and isinstance(raw, str) else (raw or {})
        if not isinstance(data, dict):
            data = {}

        section = data.get(item_type, {})
        if item_id in section:
            del section[item_id]
            data[item_type] = section
            redis_client.set(key, json.dumps(data))

        return {"success": True, "message": f"Dismissed {item_type[:-1]} '{item_id}'"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/seed-test-data")
async def seed_test_data():
    """Seed test tenant with sample agents and policies data."""
    try:
        tenant_id = "test-tenant-001"

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
                "agent_permissions": {
                    "healthcare-nurse": ["patient_lookup", "view_records"],
                    "healthcare-triage": ["patient_lookup"]
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
                "agent_permissions": {
                    "healthcare-doctor": ["patient_lookup", "schedule_appointment", "update_vitals", "view_basic_records"],
                    "healthcare-triage": ["patient_lookup", "schedule_appointment"]
                },
                "created_at": 1775632479,
                "updated_at": 1775632479
            }
        }

        policies = [
            {
                "tool_name": "patient_lookup",
                "data_sanitization": {
                    "redact_ssn": True,
                    "redact_phone": True,
                    "redact_email": False,
                    "redact_medical_ids": True,
                    "patterns": [
                        {
                            "name": "SSN Pattern",
                            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                            "replacement": "[REDACTED-SSN]",
                            "enabled": True
                        },
                        {
                            "name": "Phone Pattern",
                            "pattern": r"\b\d{3}-\d{3}-\d{4}\b",
                            "replacement": "[REDACTED-PHONE]",
                            "enabled": True
                        }
                    ]
                },
                "llm_validation": {
                    "enabled": True,
                    "severity": "high",
                    "scan_types": ["pii", "phi", "secrets"],
                    "custom_rules": [
                        "Remove any patient identifiers including names, addresses, or ID numbers",
                        "Redact sensitive medical information that could identify individuals"
                    ],
                    "model": "sanitization-model-v1"
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
                    "redact_patient_notes": True,
                    "patterns": [
                        {
                            "name": "Dosage Sensitive",
                            "pattern": r"(\d+)\s*(mg|ml|mcg|units?)",
                            "replacement": "[DOSAGE-REDACTED]",
                            "enabled": True
                        }
                    ]
                },
                "llm_validation": {
                    "enabled": True,
                    "severity": "critical",
                    "scan_types": ["pii", "phi", "dosage", "prescriptions"],
                    "custom_rules": [
                        "Remove specific dosage amounts and prescription details",
                        "Protect patient-specific medication information"
                    ],
                    "model": "sanitization-model-v1"
                },
                "role_restrictions": {
                    "doctor": "allow",
                    "nurse": "block",
                    "patient": "block"
                },
                "compliance_framework": "hipaa"
            }
        ]

        redis_client = _get_redis()
        if redis_client:
            redis_client.set(f"agents:{tenant_id}", json.dumps(agents))
            redis_client.set(f"policies:{tenant_id}", json.dumps(policies))
        else:
            raise Exception("Redis connection not available")

        return {
            "success": True,
            "message": f"Test data seeded for tenant {tenant_id}",
            "agents_count": len(agents),
            "policies_count": len(policies)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to seed test data: {str(e)}")


@router.post("/registry")
async def create_agent(request: Request):
    """Create a new agent."""
    try:
        tenant_id = get_tenant_from_api_key(request)
        body = await request.json()

        agent_id = body.get("agent_id", "").strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required")
        _validate_agent_id(agent_id)
        _validate_agent_body(body)

        agents_key = f"agents:{tenant_id}"
        agents = get_redis_data(agents_key) or {}

        if agent_id in agents:
            raise HTTPException(status_code=409, detail=f"Agent '{agent_id}' already exists")

        import time as _time
        now = int(_time.time())
        agents[agent_id] = {
            "agent_id": agent_id,
            "name": _sanitize_string(body.get("name", agent_id)),
            "description": _sanitize_string(body.get("description", "")),
            "tools": [_sanitize_string(t, _MAX_TOOL_NAME_LEN) for t in body.get("tools", [])],
            "role_permissions": _sanitize_value(body.get("role_permissions", {})),
            "agent_permissions": _sanitize_value(body.get("agent_permissions", {})),
            "status": body.get("status", "active"),
            "created_at": now,
            "updated_at": now,
        }

        redis_client = _get_redis()
        if redis_client:
            redis_client.set(agents_key, json.dumps(agents))
        else:
            raise Exception("Redis connection not available")

        return {
            "success": True,
            "message": f"Agent {agent_id} created successfully",
            "agent": agents[agent_id],
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create agent: {str(e)}")


@router.put("/registry/{agent_id}")
async def update_agent(agent_id: str, agent_data: dict, request: Request):
    """Update an existing agent."""
    try:
        _validate_agent_id(agent_id)
        tenant_id = get_tenant_from_api_key(request)
        _validate_agent_body(agent_data)

        # Get existing agents
        agents_key = f"agents:{tenant_id}"
        agents = get_redis_data(agents_key) or {}

        if agent_id not in agents:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Sanitize all string fields recursively
        sanitized = _sanitize_value(agent_data)
        if "name" in sanitized:
            sanitized["name"] = _sanitize_string(sanitized["name"])
        if "description" in sanitized:
            sanitized["description"] = _sanitize_string(sanitized["description"])
        if "tools" in sanitized:
            sanitized["tools"] = [_sanitize_string(t, _MAX_TOOL_NAME_LEN) for t in sanitized.get("tools", [])]

        # Prevent overriding immutable fields
        sanitized.pop("created_at", None)

        agents[agent_id] = {
            **agents[agent_id],
            **sanitized,
            "agent_id": agent_id,
            "updated_at": int(__import__('time').time())
        }

        # Save to Redis
        redis_client = _get_redis()
        if redis_client:
            redis_client.set(agents_key, json.dumps(agents))
        else:
            raise Exception("Redis connection not available")

        return {
            "success": True,
            "message": f"Agent {agent_id} updated successfully",
            "agent": agents[agent_id]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update agent: {str(e)}")


@router.delete("/registry/{agent_id}")
async def delete_agent(agent_id: str, request: Request):
    """Delete an agent."""
    try:
        _validate_agent_id(agent_id)
        tenant_id = get_tenant_from_api_key(request)

        # Get existing agents
        agents_key = f"agents:{tenant_id}"
        agents = get_redis_data(agents_key) or {}

        if agent_id not in agents:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Remove agent
        deleted_agent = agents.pop(agent_id)

        # Save to Redis
        redis_client = _get_redis()
        if redis_client:
            redis_client.set(agents_key, json.dumps(agents))
        else:
            raise Exception("Redis connection not available")

        return {
            "success": True,
            "message": f"Agent {agent_id} deleted successfully",
            "deleted_agent": deleted_agent
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete agent: {str(e)}")

