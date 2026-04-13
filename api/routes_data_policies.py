"""Data Policies API - Advanced tool-specific data protection with Redis persistence."""

import json
import time

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Dict, List, Optional

from core.auth import get_tenant_from_request
from storage.tenant_store import _get_redis

router = APIRouter(prefix="/v1/data-policies", tags=["data-policies"])


class DataSanitizationRule(BaseModel):
    pattern_id: str
    regex: str
    replacement: str
    description: str
    enabled: bool = True
    severity: str = "medium"  # low, medium, high, critical


class RoleDataPolicy(BaseModel):
    role: str
    action: str  # allow, redact, block, mask
    data_scope: List[str] = []
    redaction_level: str = "partial"  # none, partial, full


class ToolDataPolicy(BaseModel):
    tool_name: str
    sanitization_rules: List[DataSanitizationRule] = []
    role_policies: List[RoleDataPolicy] = []
    compliance_framework: Optional[str] = None  # hipaa, pci_dss, gdpr
    audit_required: bool = False
    retention_days: Optional[int] = None


def _data_policies_key(tenant_id: str) -> str:
    return f"data_policies:{tenant_id}"


def _load_all(tenant_id: str) -> dict:
    r = _get_redis()
    if not r:
        return {}
    raw = r.get(_data_policies_key(tenant_id))
    if not raw:
        return {}
    return json.loads(raw) if isinstance(raw, str) else raw


def _save_all(tenant_id: str, data: dict):
    r = _get_redis()
    if not r:
        raise Exception("Redis connection not available")
    r.set(_data_policies_key(tenant_id), json.dumps(data))


@router.post("/tools/{tool_name}/policy")
async def create_tool_data_policy(
    tool_name: str,
    policy: ToolDataPolicy,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Create or update data policy for a specific tool. Persisted in Redis."""
    try:
        all_policies = _load_all(tenant_id)
        entry = policy.dict()
        entry["updated_at"] = int(time.time())
        if tool_name not in all_policies:
            entry["created_at"] = int(time.time())
        else:
            entry["created_at"] = all_policies[tool_name].get("created_at", int(time.time()))
        all_policies[tool_name] = entry
        _save_all(tenant_id, all_policies)

        return {
            "success": True,
            "message": f"Data policy created for tool '{tool_name}'",
            "policy": entry
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/{tool_name}/policy")
async def get_tool_data_policy(
    tool_name: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get data policy for a specific tool from Redis."""
    try:
        all_policies = _load_all(tenant_id)
        policy = all_policies.get(tool_name, {
            "tool_name": tool_name,
            "sanitization_rules": [],
            "role_policies": [],
            "compliance_framework": None,
            "audit_required": False,
            "retention_days": None,
        })

        return {
            "success": True,
            "tool_name": tool_name,
            "tenant_id": tenant_id,
            "policy": policy
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools")
async def get_all_data_policies(
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get all data policies for this tenant."""
    try:
        all_policies = _load_all(tenant_id)
        return {
            "success": True,
            "tenant_id": tenant_id,
            "policies": all_policies,
            "count": len(all_policies),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/tools/{tool_name}/policy")
async def delete_tool_data_policy(
    tool_name: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Delete a tool's data policy from Redis."""
    try:
        all_policies = _load_all(tenant_id)
        if tool_name not in all_policies:
            raise HTTPException(status_code=404, detail="Data policy not found for this tool")
        del all_policies[tool_name]
        _save_all(tenant_id, all_policies)
        return {"success": True, "message": f"Data policy deleted for '{tool_name}'"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compliance/frameworks")
async def get_compliance_frameworks():
    """Get available compliance frameworks and their requirements."""
    return {
        "frameworks": {
            "hipaa": {
                "name": "Health Insurance Portability and Accountability Act",
                "description": "US healthcare data protection",
                "required_protections": ["phi", "ssn", "medical_records"],
                "audit_required": True,
                "retention_max_days": 365
            },
            "pci_dss": {
                "name": "Payment Card Industry Data Security Standard",
                "description": "Credit card data protection",
                "required_protections": ["pan", "cvv", "cardholder_data"],
                "audit_required": True,
                "retention_max_days": 365
            },
            "gdpr": {
                "name": "General Data Protection Regulation",
                "description": "EU personal data protection",
                "required_protections": ["personal_data", "sensitive_data"],
                "audit_required": True,
                "retention_max_days": 1095
            }
        }
    }


@router.post("/validate")
async def validate_data_against_policies(
    request: Dict,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Validate data against tool data policies using stored rules."""
    import re as _re

    try:
        data = request.get("data", "")
        tool_name = request.get("tool_name")
        user_role = request.get("user_role")

        all_policies = _load_all(tenant_id)
        policy = all_policies.get(tool_name, {})

        violations = []
        sanitized_data = data

        # Apply sanitization rules from policy
        for rule in policy.get("sanitization_rules", []):
            if not rule.get("enabled", True):
                continue
            try:
                if _re.search(rule["regex"], data):
                    violations.append({
                        "violation_type": "pattern_match",
                        "pattern_id": rule.get("pattern_id", "unknown"),
                        "data_type": rule.get("description", ""),
                        "severity": rule.get("severity", "medium"),
                        "pattern": f"{rule.get('description', 'Pattern')} detected",
                    })
                    sanitized_data = _re.sub(rule["regex"], rule.get("replacement", "[REDACTED]"), sanitized_data)
            except _re.error:
                pass

        # Check role-level access
        role_policy = None
        for rp in policy.get("role_policies", []):
            if rp.get("role") == user_role:
                role_policy = rp
                break

        role_action = role_policy.get("action", "allow") if role_policy else "allow"
        if role_action == "block":
            violations.append({
                "violation_type": "role_restriction",
                "data_type": "all",
                "severity": "critical",
                "pattern": f"Role '{user_role}' is blocked from this tool's data",
            })

        risk_level = "high" if any(v["severity"] == "critical" for v in violations) else "medium" if violations else "low"

        return {
            "validation_result": {
                "compliant": len(violations) == 0,
                "risk_level": risk_level,
                "violations_count": len(violations),
                "violations": violations
            },
            "sanitized_data": sanitized_data,
            "original_data": data,
            "data_modified": sanitized_data != data,
            "metadata": {
                "tool_name": tool_name,
                "user_role": user_role,
                "tenant_id": tenant_id,
                "compliance_framework": policy.get("compliance_framework"),
                "audit_required": policy.get("audit_required", False),
                "role_action": role_action,
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
