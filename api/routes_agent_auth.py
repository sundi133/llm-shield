"""Agent AuthN/AuthZ orchestration routes.

Three endpoints:
  POST /v1/shield/auth/agent-token   — issue an agent token (AuthN)
  POST /v1/shield/cap/mint           — decide AuthZ + mint capability
  POST /v1/shield/cap/verify         — verify a cap (for tool servers)

Plus two revocation endpoints:
  POST /v1/shield/auth/revoke        — revoke instance/user/jti
"""

from __future__ import annotations

import os
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from core.agent_tokens import (
    DEFAULT_TOKEN_TTL_SECONDS,
    MAX_TOKEN_TTL_SECONDS,
    TokenError,
    mint_agent_token,
)
from core.capabilities import (
    CAP_DEFAULT_TTL_SECONDS,
    CAP_MAX_TTL_SECONDS,
    CapabilityError,
    mint_cap,
    verify_cap,
)
from core.agent_auth_safety import (
    public_denial_payload,
    rate_limit_cap_mint,
    rate_limit_token_issuance,
    verbose_reasons_enabled,
)
from core.identity import IdentityTuple, get_identity_from_request
from core.rbac import enforcer as rbac_enforcer
from storage.agent_auth_stats import (
    EVENT_CAP_DENIED,
    EVENT_CAP_INVALID,
    EVENT_CAP_MINTED,
    EVENT_CAP_REPLAY,
    EVENT_CAP_VERIFIED,
    EVENT_REVOKE,
    EVENT_TOKEN_ISSUED,
    get_counters,
    get_recent,
    record as record_event,
)
from storage.revocation import revoke_instance, revoke_jti, revoke_user

logger = logging.getLogger("votal.routes_agent_auth")

router = APIRouter(prefix="/v1/shield", tags=["agent-auth"])
tenant_router = APIRouter(prefix="/v1/tenant/me/agent-auth", tags=["agent-auth"])


# ─── Schemas ────────────────────────────────────────────────────────────


class AgentTokenRequest(BaseModel):
    user_sub: str = Field(..., description="OIDC sub of the human user")
    agent_id: str = Field(..., description="Logical agent identity")
    agent_instance_id: str = Field(..., description="Unique per-process id")
    tenant_id: str = Field(..., description="Tenant scope")
    build_hash: str = Field(..., description="Exact build hash of agent code")
    model_version: str = Field(..., description="LLM model version in use")
    session_id: str = Field(..., description="Conversation/session id")
    parent_agent_id: Optional[str] = Field(None, description="Delegating agent, if any")
    ttl_seconds: int = Field(DEFAULT_TOKEN_TTL_SECONDS, ge=1, le=MAX_TOKEN_TTL_SECONDS)


class AgentTokenResponse(BaseModel):
    agent_token: str
    expires_in: int


class CapMintRequest(BaseModel):
    tool: str = Field(..., description="Tool the agent intends to call")
    resource: str = Field(..., description="Specific target of the tool")
    data_scope: Optional[str] = Field(None, description="Data scope (for RBAC check)")
    scope_constraints: List[str] = Field(default_factory=list)
    clearance_max: str = Field("public")
    ttl_seconds: int = Field(CAP_DEFAULT_TTL_SECONDS, ge=1, le=CAP_MAX_TTL_SECONDS)


class CapMintResponse(BaseModel):
    cap_token: str
    expires_in: int
    decision: dict


class CapVerifyRequest(BaseModel):
    cap_token: str
    expected_tool: str
    expected_resource: Optional[str] = None
    burn_nonce: bool = True


class CapVerifyResponse(BaseModel):
    valid: bool
    claims: Optional[dict] = None
    error: Optional[str] = None


class RevokeRequest(BaseModel):
    agent_instance_id: Optional[str] = None
    user_sub: Optional[str] = None
    jti: Optional[str] = None
    ttl_seconds: int = 3600


# ─── Admin gate for token exchange ──────────────────────────────────────


def _require_admin(request: Request) -> None:
    """Token-exchange endpoint requires admin key or SPIFFE workload identity.

    Accepts:
    1. X-Admin-Key header (original admin auth)
    2. SPIFFE workload identity (set by SPIFFEMiddleware, on-prem friendly)

    In production, SPIFFE replaces admin-key for automated workloads.
    """
    # Accept SPIFFE workload identity as admin-equivalent
    spiffe_identity = getattr(request.state, "spiffe_identity", None)
    if spiffe_identity:
        return

    admin_key = os.environ.get("SHIELD_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(
            status_code=500,
            detail="SHIELD_ADMIN_KEY not configured — token issuance disabled",
        )
    provided = request.headers.get("X-Admin-Key", "").strip()
    import hmac
    if not provided or not hmac.compare_digest(provided, admin_key):
        raise HTTPException(status_code=403, detail="admin key required")


# ─── Endpoints ──────────────────────────────────────────────────────────


@router.post("/auth/agent-token", response_model=AgentTokenResponse)
async def issue_agent_token(body: AgentTokenRequest, request: Request):
    """Issue a signed agent token (AuthN).

    In production, this endpoint should be wired to an OIDC token exchange
    that takes a verified user id_token + a SPIFFE workload SVID and emits
    the agent token. v1 takes the claims directly, gated by admin key.
    """
    _require_admin(request)
    try:
        token = mint_agent_token(
            user_sub=body.user_sub,
            agent_id=body.agent_id,
            agent_instance_id=body.agent_instance_id,
            tenant_id=body.tenant_id,
            build_hash=body.build_hash,
            model_version=body.model_version,
            session_id=body.session_id,
            parent_agent_id=body.parent_agent_id,
            ttl_seconds=body.ttl_seconds,
        )
    except TokenError as e:
        raise HTTPException(status_code=400, detail=str(e))
    record_event(
        tenant_id=body.tenant_id, event=EVENT_TOKEN_ISSUED,
        agent_id=body.agent_id, user_sub=body.user_sub,
    )
    return AgentTokenResponse(agent_token=token, expires_in=body.ttl_seconds)


@router.post("/cap/mint", response_model=CapMintResponse)
async def mint_capability(
    body: CapMintRequest,
    identity: IdentityTuple = Depends(get_identity_from_request),
):
    """Run AuthZ policy. If allowed, freeze the decision as a cap token.

    Requires a valid X-Agent-Token (verified by AgentIdentityMiddleware).
    Runs the AuthZ checks here in-process and returns the cap on success.
    """
    # M5: per-instance rate limit on cap minting. Keyed by instance + tenant
    # so a noisy pod can't burn the tenant-wide budget.
    allowed, err = rate_limit_cap_mint(identity.agent_instance_id, identity.tenant_id)
    if not allowed:
        raise HTTPException(status_code=429, detail=err or "rate limit exceeded")

    decision = _decide_authz(identity, body)
    if not decision["allowed"]:
        # Full reasons go to the audit log so operators can debug; the
        # response body only includes reasons when SHIELD_VERBOSE_REASONS=1
        # is set. This prevents an attacker from enumerating tools/roles
        # via the public API (M3).
        record_event(
            tenant_id=identity.tenant_id, event=EVENT_CAP_DENIED,
            agent_id=identity.agent_id, user_sub=identity.user_sub,
            tool=body.tool, resource=body.resource,
            reason="; ".join(decision["reasons"])[:240],
        )
        raise HTTPException(
            status_code=403,
            detail=public_denial_payload(decision["reasons"]),
        )

    try:
        cap = mint_cap(
            identity=identity,
            tool=body.tool,
            resource=body.resource,
            scope=body.scope_constraints,
            clearance_max=body.clearance_max,
            ttl_seconds=body.ttl_seconds,
        )
    except CapabilityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    record_event(
        tenant_id=identity.tenant_id, event=EVENT_CAP_MINTED,
        agent_id=identity.agent_id, user_sub=identity.user_sub,
        tool=body.tool, resource=body.resource,
    )
    # In quiet mode return only what the caller needs to use the cap;
    # the full decision (role, reasons, etc.) goes to the audit log.
    if verbose_reasons_enabled():
        public_decision = decision
    else:
        public_decision = {
            "allowed": True,
            "tool": decision["tool"],
            "resource": decision["resource"],
        }
    return CapMintResponse(
        cap_token=cap,
        expires_in=body.ttl_seconds,
        decision=public_decision,
    )


@router.post("/cap/verify", response_model=CapVerifyResponse)
async def verify_capability(body: CapVerifyRequest):
    """Verify a cap token (called by tool/MCP servers).

    Deliberately NOT gated by X-Agent-Token: tool servers verify caps on
    behalf of agents, and the cap itself is the bearer credential.
    """
    try:
        claims = verify_cap(
            body.cap_token,
            expected_tool=body.expected_tool,
            expected_resource=body.expected_resource,
            burn_nonce=body.burn_nonce,
        )
    except CapabilityError as e:
        msg = str(e)
        event = EVENT_CAP_REPLAY if "replay" in msg else EVENT_CAP_INVALID
        # Try to recover tenant_id from the (unverified) cap claims so the
        # event still attributes to the right tenant for the portal.
        recovered_tenant = None
        recovered_agent = None
        try:
            from core.capabilities import _b64url_decode
            import json as _json
            payload_b64 = body.cap_token.split(".", 1)[0]
            _claims = _json.loads(_b64url_decode(payload_b64).decode("utf-8"))
            recovered_tenant = _claims.get("tenant_id")
            recovered_agent = _claims.get("agent_id")
        except Exception:
            pass
        record_event(
            tenant_id=recovered_tenant, event=event,
            agent_id=recovered_agent,
            tool=body.expected_tool, resource=body.expected_resource,
            reason=msg[:240],
        )
        return CapVerifyResponse(valid=False, error=msg)

    record_event(
        tenant_id=claims.tenant_id, event=EVENT_CAP_VERIFIED,
        agent_id=claims.agent_id, user_sub=claims.user_sub,
        tool=claims.tool, resource=claims.resource,
    )
    return CapVerifyResponse(
        valid=True,
        claims={
            "user_sub": claims.user_sub,
            "agent_id": claims.agent_id,
            "agent_instance_id": claims.agent_instance_id,
            "tool": claims.tool,
            "resource": claims.resource,
            "scope": claims.scope,
            "clearance_max": claims.clearance_max,
            "tenant_id": claims.tenant_id,
            "cap_id": claims.cap_id,
            "exp": claims.exp,
        },
    )


class RevokeRequestExt(RevokeRequest):
    tenant_id: Optional[str] = None  # for portal attribution; optional


@router.post("/auth/revoke")
async def revoke(body: RevokeRequestExt, request: Request):
    """Revoke an instance, user, or jti/cap_id. Admin only."""
    _require_admin(request)
    if not any([body.agent_instance_id, body.user_sub, body.jti]):
        raise HTTPException(status_code=400, detail="provide one of: agent_instance_id, user_sub, jti")

    revoked = []
    if body.agent_instance_id:
        revoke_instance(body.agent_instance_id, ttl=body.ttl_seconds)
        revoked.append({"type": "instance", "id": body.agent_instance_id})
    if body.user_sub:
        revoke_user(body.user_sub, ttl=body.ttl_seconds)
        revoked.append({"type": "user", "id": body.user_sub})
    if body.jti:
        revoke_jti(body.jti, ttl=body.ttl_seconds)
        revoked.append({"type": "jti", "id": body.jti})

    for r in revoked:
        record_event(
            tenant_id=body.tenant_id, event=EVENT_REVOKE,
            user_sub=body.user_sub, reason=f"{r['type']}:{r['id']}",
        )

    return {"status": "revoked", "entries": revoked, "ttl_seconds": body.ttl_seconds}


# ─── Internal AuthZ decision ────────────────────────────────────────────


def _decide_authz(identity: IdentityTuple, body: CapMintRequest) -> dict:
    """Compose the AuthZ verdict.

    v1 wires up the two policy primitives that already exist in this
    codebase — RBAC (role → tool, role → data) and cert/identity trust —
    using the IdentityTuple from AuthN. Taint, delegation intersection,
    and sensitive-action confirmation are designed-for hooks that the
    caller can stamp into scope_constraints today and the verifier can
    enforce at the tool boundary.
    """
    reasons: list[str] = []
    allowed = True
    role_name: Optional[str] = None

    # Per-tenant authorization (takes precedence over global/static RBAC).
    # If the tenant explicitly registered this agent, the tenant's config is
    # authoritative: enforce the tenant's allowed tools rather than the global
    # ruleset. Without this, the cap-mint path consulted only the global static
    # RBAC and ignored per-tenant roles entirely.
    from guardrails.agentic.rbac_guard import _load_agent_entry, _registry_agent_status
    agent_entry = _load_agent_entry(identity.agent_id, identity.tenant_id)
    if agent_entry is not None:
        status = _registry_agent_status(identity.agent_id, identity.tenant_id) or "active"
        if status != "active":
            allowed = False
            reasons.append(f"agent '{identity.agent_id}' is disabled for this tenant")
        else:
            allowed_tools = set(agent_entry.get("tools", []) or [])
            for perms in (agent_entry.get("role_permissions", {}) or {}).values():
                allowed_tools.update(perms or [])
            # Fail closed: a registered agent with no permitted tools gets nothing.
            if not allowed_tools or body.tool not in allowed_tools:
                allowed = False
                reasons.append(
                    f"tenant policy does not permit agent '{identity.agent_id}' "
                    f"to use tool '{body.tool}'")
            else:
                # Object-level (target) authorization. Previously the agent could
                # name any `resource` and get a signed cap for it. Enforce the
                # resource against the agent's declared scope patterns, binding
                # {user_sub}/{tenant_id} to the *authenticated* principal so an
                # agent can't mint a cap for another user's/tenant's records.
                patterns = agent_entry.get("allowed_resources", []) or []
                require_scope = bool(agent_entry.get("require_resource_scope", False))
                if patterns:
                    import fnmatch
                    expanded = [
                        p.replace("{user_sub}", identity.user_sub or "\x00")
                         .replace("{tenant_id}", identity.tenant_id or "\x00")
                        for p in patterns
                    ]
                    if not any(fnmatch.fnmatch(body.resource, p) for p in expanded):
                        allowed = False
                        reasons.append(
                            f"resource '{body.resource}' is outside the allowed "
                            f"scope for agent '{identity.agent_id}'")
                elif require_scope:
                    # Strict mode: no resource policy configured ⇒ deny rather
                    # than issue an unbounded capability.
                    allowed = False
                    reasons.append(
                        "resource scoping is required for this agent but no "
                        "allowed_resources are configured")
        return {
            "allowed": allowed,
            "reasons": reasons,
            "agent_id": identity.agent_id,
            "role": "tenant-registry",
            "tool": body.tool,
            "resource": body.resource,
        }

    # RBAC: role → tool + role → data_scope (global/static fallback)
    role = rbac_enforcer.resolve_role(identity.agent_id)
    if role is None:
        # Unknown agent: deny by default — but only if RBAC has any roles
        # configured. If RBAC is unconfigured (tests, dev), pass through.
        if rbac_enforcer._agents:
            allowed = False
            reasons.append(f"unknown agent_id for RBAC: {identity.agent_id}")
    else:
        role_name = role.name
        if not rbac_enforcer.check_tool_access(role, body.tool):
            allowed = False
            reasons.append(f"role '{role.name}' not permitted to use tool '{body.tool}'")
        if body.data_scope and not rbac_enforcer.check_data_access(role, body.data_scope):
            allowed = False
            reasons.append(
                f"role '{role.name}' not permitted to access data_scope '{body.data_scope}'"
            )
        # Clearance ceiling: cap's clearance_max cannot exceed the role's clearance
        role_clearance_value = rbac_enforcer.get_clearance_level(role)
        from core.rbac import _CLEARANCE_LEVELS
        requested_clearance_value = _CLEARANCE_LEVELS.get(body.clearance_max, 0)
        if requested_clearance_value > role_clearance_value:
            allowed = False
            reasons.append(
                f"clearance_max '{body.clearance_max}' exceeds role clearance '{role.data_clearance}'"
            )

    return {
        "allowed": allowed,
        "reasons": reasons,
        "agent_id": identity.agent_id,
        "role": role_name,
        "tool": body.tool,
        "resource": body.resource,
    }


# ─── Tenant-scoped read endpoints (for portal) ──────────────────────────


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="Tenant API key required",
        )
    return tenant_id


@tenant_router.get("/stats")
async def agent_auth_stats(request: Request, days: int = 7):
    """Per-event counters for the calling tenant, last `days` days."""
    tenant_id = _require_tenant(request)
    return {"tenant_id": tenant_id, **get_counters(tenant_id, days=days)}


@tenant_router.get("/recent")
async def agent_auth_recent(request: Request, limit: int = 50):
    """Last N agent-auth events for the calling tenant (newest first)."""
    tenant_id = _require_tenant(request)
    return {"tenant_id": tenant_id, "events": get_recent(tenant_id, limit=limit)}


@tenant_router.get("/diag")
async def agent_auth_diag(request: Request):
    """Self-diagnostic: tests Redis read+write end-to-end for the calling
    tenant and reports exactly what works.

    Surfaces the silent failure modes that otherwise show up only as
    "all zeros in the portal" — backed-up writes, stale reads, missing
    cryptography dep, etc.
    """
    tenant_id = _require_tenant(request)
    import time as _t
    from storage import agent_auth_stats as _stats
    from storage.tenant_store import _get_redis

    result = {
        "tenant_id": tenant_id,
        "redis": {"reachable": False, "type": None, "error": None},
        "write": {"ok": False, "error": None},
        "read":  {"ok": False, "error": None, "value": None},
        "stats_endpoint_works": False,
    }

    # 1. Is Redis reachable?
    r = _get_redis()
    if r is None:
        result["redis"]["error"] = "no Redis client (UPSTASH_REDIS_REST_URL/REDIS_URL unset)"
    else:
        result["redis"]["type"] = type(r).__name__
        try:
            # Cheap probe
            if hasattr(r, "ping"):
                r.ping()
            else:
                r.get("__shield_diag_probe__")
            result["redis"]["reachable"] = True
        except Exception as e:
            result["redis"]["error"] = f"{type(e).__name__}: {e}"

    # 2. Can we WRITE to this tenant's recent buffer?
    probe_key = f"shield:authstats:diag:{tenant_id}"
    probe_value = f"probe-{int(_t.time())}"
    if r and result["redis"]["reachable"]:
        try:
            r.set(probe_key, probe_value, ex=60)
            result["write"]["ok"] = True
        except Exception as e:
            result["write"]["error"] = f"{type(e).__name__}: {e}"

        # 3. Can we READ what we just wrote?
        try:
            got = r.get(probe_key)
            got_s = got.decode() if isinstance(got, bytes) else got
            result["read"]["value"] = got_s
            result["read"]["ok"] = (got_s == probe_value)
            if not result["read"]["ok"]:
                result["read"]["error"] = (
                    f"wrote {probe_value!r}, read back {got_s!r}"
                )
        except Exception as e:
            result["read"]["error"] = f"{type(e).__name__}: {e}"

    # 4. End-to-end: does an actual event recording + read make it through?
    _stats.record(tenant_id=tenant_id, event=_stats.EVENT_TOKEN_ISSUED,
                  agent_id="__diag__", user_sub="__diag__")
    counters = _stats.get_counters(tenant_id, days=1)
    result["stats_endpoint_works"] = counters["totals"][_stats.EVENT_TOKEN_ISSUED] > 0
    result["counters_now"] = counters["totals"]

    return result


# ─── Tenant-scoped token issuance (customer-facing) ─────────────────────
#
# Customers do NOT have the admin key. They have their tenant API key,
# the same one they use everywhere else. This endpoint:
#   * authenticates via X-API-Key (existing AuthMiddleware → request.state.tenant_id)
#   * locks tenant_id to whatever the API key resolves to
#   * accepts agent identity claims in the body (user_sub, agent_id, ...)
#   * returns the same signed agent token shape as the admin endpoint
#
# A customer cannot mint a token for a tenant_id they do not own.


class TenantAgentTokenRequest(BaseModel):
    user_sub: str = Field(..., description="OIDC sub of the human user")
    agent_id: str = Field(..., description="Logical agent identity")
    agent_instance_id: str = Field(..., description="Unique per-process id")
    build_hash: str = Field(..., description="Exact build hash of the agent code")
    model_version: str = Field(..., description="LLM model version in use")
    session_id: str = Field(..., description="Conversation/session id")
    parent_agent_id: Optional[str] = Field(None, description="Delegating agent, if any")
    ttl_seconds: int = Field(DEFAULT_TOKEN_TTL_SECONDS, ge=1, le=MAX_TOKEN_TTL_SECONDS)


@tenant_router.post("/agent-token", response_model=AgentTokenResponse)
async def issue_agent_token_tenant(body: TenantAgentTokenRequest, request: Request):
    """Issue an agent token for the calling tenant (customer-facing).

    Auth: tenant API key via X-API-Key. The tenant_id is taken from the
    resolved API key — clients cannot specify a different tenant.
    Rate limited per-tenant (H3) to slow down compromised-key abuse.
    """
    tenant_id = _require_tenant(request)
    allowed, err = rate_limit_token_issuance(tenant_id)
    if not allowed:
        raise HTTPException(status_code=429, detail=err or "rate limit exceeded")
    try:
        token = mint_agent_token(
            user_sub=body.user_sub,
            agent_id=body.agent_id,
            agent_instance_id=body.agent_instance_id,
            tenant_id=tenant_id,
            build_hash=body.build_hash,
            model_version=body.model_version,
            session_id=body.session_id,
            parent_agent_id=body.parent_agent_id,
            ttl_seconds=body.ttl_seconds,
        )
    except TokenError as e:
        raise HTTPException(status_code=400, detail=str(e))
    record_event(
        tenant_id=tenant_id, event=EVENT_TOKEN_ISSUED,
        agent_id=body.agent_id, user_sub=body.user_sub,
    )
    return AgentTokenResponse(agent_token=token, expires_in=body.ttl_seconds)
