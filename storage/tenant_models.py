"""Pydantic models for tenant configuration validation."""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class GuardrailPolicy(BaseModel):
    """A single guardrail configuration for a tenant."""
    enabled: bool = True
    action: str = Field(default="block", pattern="^(block|warn|log|pass)$")
    settings: dict = Field(default_factory=dict)

    @field_validator("settings")
    @classmethod
    def validate_threshold_range(cls, v):
        if "threshold" in v:
            t = v["threshold"]
            if isinstance(t, (int, float)) and (t < 0.0 or t > 1.0):
                raise ValueError("threshold must be between 0.0 and 1.0")
        return v


class TenantRBACRole(BaseModel):
    """RBAC role definition for a tenant."""
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    max_tokens_per_request: int = Field(default=4096, ge=1, le=1_000_000)
    rate_limit: str = "100/min"
    data_clearance: str = Field(default="public", pattern="^(public|internal|confidential|restricted)$")
    allowed_data_scopes: list[str] = Field(default_factory=list)
    denied_data_scopes: list[str] = Field(default_factory=list)


class TenantRBAC(BaseModel):
    """RBAC block for a tenant — roles and agent mappings."""
    roles: dict[str, TenantRBACRole] = Field(default_factory=dict)
    agents: dict[str, str] = Field(default_factory=dict)


class TenantQuota(BaseModel):
    """Per-tenant usage quotas tied to plan."""
    max_requests_per_minute: int = Field(default=60, ge=1)
    max_requests_per_day: int = Field(default=100_000, ge=1)
    max_tokens_per_day: int = Field(default=10_000_000, ge=1)


class TenantConfig(BaseModel):
    """Full tenant configuration stored in Redis."""
    tenant_id: str = Field(..., min_length=1, max_length=64, pattern="^[a-zA-Z0-9_-]+$")
    name: str = Field(default="", max_length=256)
    plan: str = Field(default="basic", pattern="^(basic|pro|enterprise)$")
    input_guardrails: dict[str, GuardrailPolicy] = Field(default_factory=dict)
    output_guardrails: dict[str, GuardrailPolicy] = Field(default_factory=dict)
    rbac: TenantRBAC = Field(default_factory=TenantRBAC)
    quota: Optional[TenantQuota] = None
    deleted_at: Optional[str] = None  # ISO timestamp for soft delete

    @field_validator("quota", mode="before")
    @classmethod
    def default_quota_from_plan(cls, v, info):
        if v is not None:
            return v
        plan = info.data.get("plan", "basic")
        defaults = {
            "basic":      {"max_requests_per_minute": 60,  "max_requests_per_day": 100_000,    "max_tokens_per_day": 10_000_000},
            "pro":        {"max_requests_per_minute": 300, "max_requests_per_day": 1_000_000,  "max_tokens_per_day": 100_000_000},
            "enterprise": {"max_requests_per_minute": 1000, "max_requests_per_day": 10_000_000, "max_tokens_per_day": 1_000_000_000},
        }
        return defaults.get(plan, defaults["basic"])


_PLAN_QUOTA_DEFAULTS = {
    "basic":      {"max_requests_per_minute": 60,   "max_requests_per_day": 100_000,     "max_tokens_per_day": 10_000_000},
    "pro":        {"max_requests_per_minute": 300,  "max_requests_per_day": 1_000_000,   "max_tokens_per_day": 100_000_000},
    "enterprise": {"max_requests_per_minute": 1000, "max_requests_per_day": 10_000_000,  "max_tokens_per_day": 1_000_000_000},
}


class TenantCreateRequest(BaseModel):
    """Request body for POST /v1/admin/tenants."""
    tenant_id: str = Field(..., min_length=1, max_length=64, pattern="^[a-zA-Z0-9_-]+$")
    name: str = Field(default="", max_length=256)
    plan: str = Field(default="basic", pattern="^(basic|pro|enterprise)$")
    api_keys: list[str] = Field(default_factory=list)
    input_guardrails: dict[str, GuardrailPolicy] = Field(default_factory=dict)
    output_guardrails: dict[str, GuardrailPolicy] = Field(default_factory=dict)
    rbac: TenantRBAC = Field(default_factory=TenantRBAC)
    quota: Optional[TenantQuota] = None

    @field_validator("quota", mode="before")
    @classmethod
    def default_quota_from_plan(cls, v, info):
        if v is not None:
            return v
        plan = info.data.get("plan", "basic")
        return _PLAN_QUOTA_DEFAULTS.get(plan, _PLAN_QUOTA_DEFAULTS["basic"])


class TenantUpdateRequest(BaseModel):
    """Request body for PUT /v1/admin/tenants/{id}. All fields optional."""
    name: Optional[str] = Field(default=None, max_length=256)
    plan: Optional[str] = Field(default=None, pattern="^(basic|pro|enterprise)$")
    input_guardrails: Optional[dict[str, GuardrailPolicy]] = None
    output_guardrails: Optional[dict[str, GuardrailPolicy]] = None
    rbac: Optional[TenantRBAC] = None
    quota: Optional[TenantQuota] = None
