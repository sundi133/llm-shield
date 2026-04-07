"""Agent and Tool Policy Management API Routes.

Provides endpoints for:
- Agent registration with tool access
- Tool policy configuration (data sanitization, LLM validation)
- Role-based access control management

For developers to integrate agentic guardrails into their applications.
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from typing import Dict, List, Optional

from storage.policy_store import (
    register_agent,
    get_agent_registry,
    set_tool_policies,
    get_tool_policies,
    check_tool_authorization,
)
from core.auth import get_tenant_from_request

router = APIRouter(prefix="/v1/agents", tags=["agent-policies"])


# ============================================================================
# Request/Response Models
# ============================================================================

class AgentRegistration(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    name: str = Field(..., description="Display name for the agent")
    description: Optional[str] = Field(None, description="Agent description")
    tools: List[str] = Field(..., description="List of tool names this agent can use")
    role_permissions: Dict[str, List[str]] = Field(
        ...,
        description="Mapping of user roles to allowed tools",
        example={
            "admin": ["patient_lookup", "schedule_appointment", "delete_records"],
            "nurse": ["patient_lookup", "schedule_appointment"],
            "patient": ["schedule_appointment"]
        }
    )


class ToolPolicy(BaseModel):
    data_sanitization: Optional[Dict] = Field(
        None,
        description="Data sanitization rules for this tool",
        example={
            "redact_ssn": True,
            "mask_phone": True,
            "patterns": [
                {"regex": r"\b\d{3}-\d{2}-\d{4}\b", "replacement": "[SSN_REDACTED]"}
            ]
        }
    )
    llm_validation: Optional[Dict] = Field(
        None,
        description="LLM validation settings",
        example={
            "enabled": True,
            "prompt": "Validate if this {tool_name} request is appropriate for {user_role}: {tool_input}",
            "confidence_threshold": 0.7
        }
    )
    role_restrictions: Optional[Dict[str, str]] = Field(
        None,
        description="Role-based access control (allow/block/redact)",
        example={
            "admin": "allow",
            "member": "allow",
            "patient": "block"
        }
    )


class ToolPolicies(BaseModel):
    policies: Dict[str, ToolPolicy] = Field(
        ...,
        description="Mapping of tool names to their policies"
    )


class ToolAuthorizationRequest(BaseModel):
    agent_id: str
    tool_name: str
    user_role: str
    tool_input: Optional[Dict] = None


# ============================================================================
# Agent Management Endpoints
# ============================================================================

@router.post("/register")
async def register_agent_endpoint(
    agent: AgentRegistration,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Register a new agent with its tools and role permissions.

    Example:
    ```json
    {
        "agent_id": "customer-support-bot",
        "name": "Customer Support Assistant",
        "description": "Handles customer inquiries and support tickets",
        "tools": ["ticket_lookup", "customer_info", "refund_process"],
        "role_permissions": {
            "admin": ["ticket_lookup", "customer_info", "refund_process"],
            "support": ["ticket_lookup", "customer_info"],
            "customer": ["ticket_lookup"]
        }
    }
    ```
    """
    try:
        result = register_agent(tenant_id, agent.dict())
        return {"success": True, "agent": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/registry")
async def get_agent_registry_endpoint(
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get all registered agents and their configurations."""
    try:
        agents = get_agent_registry(tenant_id)
        return {"success": True, "agents": agents}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/registry/{agent_id}")
async def get_agent_endpoint(
    agent_id: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get configuration for a specific agent."""
    try:
        agents = get_agent_registry(tenant_id)
        if agent_id not in agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

        return {"success": True, "agent": agents[agent_id]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Tool Policy Management Endpoints
# ============================================================================

@router.put("/tools/policies")
async def set_tool_policies_endpoint(
    policies: ToolPolicies,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Configure tool-specific policies for data sanitization and validation.

    Example:
    ```json
    {
        "policies": {
            "patient_lookup": {
                "data_sanitization": {
                    "redact_ssn": true,
                    "mask_phone": true
                },
                "llm_validation": {
                    "enabled": true,
                    "prompt": "Is this patient lookup appropriate for {user_role}?",
                    "confidence_threshold": 0.8
                },
                "role_restrictions": {
                    "doctor": "allow",
                    "nurse": "allow",
                    "patient": "block"
                }
            }
        }
    }
    ```
    """
    try:
        # Convert ToolPolicy objects to dicts
        policies_dict = {}
        for tool_name, policy in policies.policies.items():
            policies_dict[tool_name] = policy.dict(exclude_none=True)

        result = set_tool_policies(tenant_id, policies_dict)
        return {"success": True, "tool_policies": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/policies")
async def get_tool_policies_endpoint(
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get all tool policies for the tenant."""
    try:
        policies = get_tool_policies(tenant_id)
        return {"success": True, "tool_policies": policies}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/policies/{tool_name}")
async def get_tool_policy_endpoint(
    tool_name: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get policy configuration for a specific tool."""
    try:
        policies = get_tool_policies(tenant_id)
        if tool_name not in policies:
            raise HTTPException(status_code=404, detail=f"Tool policy for {tool_name} not found")

        return {"success": True, "tool_policy": policies[tool_name]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Authorization Check Endpoint
# ============================================================================

@router.post("/authorize")
async def check_authorization_endpoint(
    request: ToolAuthorizationRequest,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Check if a user role is authorized to use a specific tool via an agent.

    This is typically called before making a tool call to verify permissions.

    Example:
    ```json
    {
        "agent_id": "customer-support-bot",
        "tool_name": "refund_process",
        "user_role": "support",
        "tool_input": {"customer_id": "12345", "amount": 50.00}
    }
    ```
    """
    try:
        result = check_tool_authorization(
            tenant_id,
            request.agent_id,
            request.tool_name,
            request.user_role
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Helper Endpoints for Integration
# ============================================================================

@router.get("/roles")
async def get_supported_roles():
    """Get list of commonly supported user roles for reference."""
    return {
        "supported_roles": [
            "admin",
            "manager",
            "member",
            "support",
            "user",
            "customer",
            "patient",
            "doctor",
            "nurse",
            "guest"
        ],
        "description": "These are common role names. You can define custom roles in your agent configurations."
    }


@router.get("/integration/examples")
async def get_integration_examples():
    """Get code examples for integrating agentic guardrails."""
    return {
        "examples": {
            "register_agent": {
                "description": "Register a customer support agent",
                "endpoint": "POST /v1/agents/register",
                "headers": {"X-API-Key": "your-tenant-api-key"},
                "body": {
                    "agent_id": "support-bot-v1",
                    "name": "Customer Support Assistant",
                    "tools": ["ticket_lookup", "customer_info", "refund_process"],
                    "role_permissions": {
                        "admin": ["ticket_lookup", "customer_info", "refund_process"],
                        "support": ["ticket_lookup", "customer_info"],
                        "customer": ["ticket_lookup"]
                    }
                }
            },
            "check_authorization": {
                "description": "Check if user can use a tool",
                "endpoint": "POST /v1/agents/authorize",
                "headers": {"X-API-Key": "your-tenant-api-key"},
                "body": {
                    "agent_id": "support-bot-v1",
                    "tool_name": "refund_process",
                    "user_role": "support"
                }
            },
            "validate_tool_output": {
                "description": "Validate and sanitize tool call output",
                "endpoint": "POST /guardrails/output",
                "headers": {
                    "X-API-Key": "your-tenant-api-key",
                    "X-User-Role": "support",
                    "X-Agent-ID": "support-bot-v1"
                },
                "body": {
                    "output": "Customer refund processed: $50.00 to card ending in 1234",
                    "context": {
                        "tool_name": "refund_process",
                        "tool_input": {"customer_id": "12345", "amount": 50.00}
                    }
                }
            }
        }
    }