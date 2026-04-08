"""Data Policies API - Advanced tool-specific data protection."""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Dict, List, Optional

from core.auth import get_tenant_from_request

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
    data_scope: List[str] = []  # specific data types allowed
    redaction_level: str = "partial"  # none, partial, full


class ToolDataPolicy(BaseModel):
    tool_name: str
    sanitization_rules: List[DataSanitizationRule] = []
    role_policies: List[RoleDataPolicy] = []
    compliance_framework: Optional[str] = None  # hipaa, pci_dss, gdpr
    audit_required: bool = False
    retention_days: Optional[int] = None


@router.post("/tools/{tool_name}/policy")
async def create_tool_data_policy(
    tool_name: str,
    policy: ToolDataPolicy,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Create or update data policy for a specific tool."""
    try:
        # Store policy (mock implementation)
        stored_policy = {
            "tool_name": tool_name,
            "tenant_id": tenant_id,
            "policy": policy.dict(),
            "created_at": "2026-04-08T00:00:00Z",
            "updated_at": "2026-04-08T00:00:00Z"
        }

        return {
            "success": True,
            "message": f"Data policy created for tool '{tool_name}'",
            "policy": stored_policy
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/{tool_name}/policy")
async def get_tool_data_policy(
    tool_name: str,
    tenant_id: str = Depends(get_tenant_from_request)
):
    """Get data policy for a specific tool."""
    try:
        # Mock policy retrieval
        if tool_name == "patient_lookup":
            policy = {
                "tool_name": tool_name,
                "sanitization_rules": [
                    {
                        "pattern_id": "ssn_redaction",
                        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
                        "replacement": "[SSN_REDACTED]",
                        "description": "Social Security Numbers",
                        "enabled": True,
                        "severity": "critical"
                    },
                    {
                        "pattern_id": "phone_masking",
                        "regex": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                        "replacement": "[PHONE_MASKED]",
                        "description": "Phone Numbers",
                        "enabled": True,
                        "severity": "high"
                    }
                ],
                "role_policies": [
                    {
                        "role": "doctor",
                        "action": "allow",
                        "data_scope": ["medical", "personal", "contact"],
                        "redaction_level": "partial"
                    },
                    {
                        "role": "nurse",
                        "action": "redact",
                        "data_scope": ["medical", "contact"],
                        "redaction_level": "partial"
                    },
                    {
                        "role": "patient",
                        "action": "block",
                        "data_scope": [],
                        "redaction_level": "full"
                    }
                ],
                "compliance_framework": "hipaa",
                "audit_required": True,
                "retention_days": 90
            }
        else:
            policy = {
                "tool_name": tool_name,
                "sanitization_rules": [],
                "role_policies": [],
                "compliance_framework": None,
                "audit_required": False
            }

        return {
            "success": True,
            "tool_name": tool_name,
            "tenant_id": tenant_id,
            "policy": policy
        }
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
    """
    Validate data against multiple tool policies.

    Example request:
    {
        "data": "Patient: John Doe, SSN: 123-45-6789",
        "tool_name": "patient_lookup",
        "user_role": "nurse",
        "compliance_check": true
    }
    """
    try:
        data = request.get("data", "")
        tool_name = request.get("tool_name")
        user_role = request.get("user_role")
        compliance_check = request.get("compliance_check", False)

        # Mock validation logic
        violations = []
        sanitized_data = data

        # Check for SSN
        import re
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', data):
            violations.append({
                "violation_type": "pii_exposure",
                "data_type": "ssn",
                "severity": "critical",
                "pattern": "SSN detected in output",
                "action_required": "redact" if user_role != "admin" else "log"
            })

            if user_role in ["nurse", "patient"]:
                sanitized_data = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', sanitized_data)

        # Check phone numbers
        if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', data):
            violations.append({
                "violation_type": "pii_exposure",
                "data_type": "phone",
                "severity": "high",
                "pattern": "Phone number detected",
                "action_required": "mask" if user_role != "doctor" else "log"
            })

            if user_role in ["nurse", "admin"]:
                sanitized_data = re.sub(r'\b(\d{3})[-.]?(\d{3})[-.]?(\d{4})\b', r'\1-***-\3', sanitized_data)

        compliance_status = "compliant" if not violations else "violations_found"
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
                "compliance_framework": "hipaa" if compliance_check else None,
                "audit_required": len(violations) > 0
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))