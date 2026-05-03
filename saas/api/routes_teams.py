"""SaaS Team Management - Built on existing tenant system"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime

# Leverage existing tenant storage
from storage.tenant_store import store_tenant_config, get_tenant_config
import uuid

router = APIRouter(prefix="/v1/saas/teams", tags=["saas-teams"])

class TeamMember(BaseModel):
    email: str
    role: str  # "admin", "developer", "junior", "intern"
    joined_at: datetime

class Team(BaseModel):
    team_id: str
    team_name: str
    api_key: str
    plan: str  # "free", "pro", "enterprise"
    members: List[TeamMember]
    created_at: datetime
    usage_limit: int
    current_usage: int

class CreateTeamRequest(BaseModel):
    team_name: str
    admin_email: str
    plan: str = "free"

@router.post("/create")
async def create_team(request: CreateTeamRequest):
    """Create new team using existing tenant infrastructure"""

    # Generate team identifiers
    team_id = f"team_{uuid.uuid4().hex[:8]}"
    api_key = f"dg_{team_id}_{uuid.uuid4().hex[:16]}"

    # Create team configuration using existing tenant system
    team_config = {
        "tenant_id": team_id,
        "team_name": request.team_name,
        "api_key": api_key,
        "plan": request.plan,
        "members": [
            {
                "email": request.admin_email,
                "role": "admin",
                "joined_at": datetime.now().isoformat()
            }
        ],
        "created_at": datetime.now().isoformat(),
        "usage_limits": {
            "free": 1000,
            "pro": 10000,
            "enterprise": -1  # unlimited
        },
        "current_usage": 0,
        "guardrails_config": get_default_team_guardrails(request.plan)
    }

    # Store using existing tenant storage
    await store_tenant_config(team_id, team_config)

    return {
        "team_id": team_id,
        "api_key": api_key,
        "message": f"Team '{request.team_name}' created successfully",
        "setup_instructions": {
            "python": f"pip install llm-shield && export SHIELD_API_KEY={api_key}",
            "javascript": f"npm install llmshield && SHIELD_API_KEY={api_key}"
        }
    }

@router.get("/{team_id}")
async def get_team(team_id: str):
    """Get team info using existing tenant system"""
    config = await get_tenant_config(team_id)
    if not config:
        raise HTTPException(status_code=404, detail="Team not found")

    return config

@router.post("/{team_id}/members")
async def add_team_member(team_id: str, email: str, role: str = "developer"):
    """Add member to team"""
    config = await get_tenant_config(team_id)
    if not config:
        raise HTTPException(status_code=404, detail="Team not found")

    # Add new member
    new_member = {
        "email": email,
        "role": role,
        "joined_at": datetime.now().isoformat()
    }
    config["members"].append(new_member)

    # Update team config
    await store_tenant_config(team_id, config)

    return {"message": f"Added {email} to team as {role}"}

def get_default_team_guardrails(plan: str) -> dict:
    """Return default guardrails configuration based on plan"""
    base_config = {
        "input_guardrails": ["system_prompt_leak", "adversarial_detection", "toxicity"],
        "output_guardrails": ["toxicity"],
        "role_based_access": True,
        "audit_logging": True
    }

    if plan in ["pro", "enterprise"]:
        base_config["input_guardrails"].extend(["custom_policy_input", "topic_restriction"])
        base_config["output_guardrails"].extend(["custom_policy_output"])

    if plan == "enterprise":
        base_config["advanced_features"] = ["sso", "custom_roles", "api_analytics"]

    return base_config