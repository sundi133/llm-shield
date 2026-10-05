"""Per-tenant identity policy for the MCP gateway.

    shield:identity_policy:{tenant}   JSON, no TTL

    {
      "mcp_sign_in": {
        "enabled": false,           // people may sign in from MCP clients
        "allowed_groups": [],       // IdP groups allowed to; required to enable
        "provider": ""              // which configured OIDC provider; "" = the first
      }
    }

Sign-in is off until a tenant turns it on, and it cannot be turned on with an
empty `allowed_groups`. Otherwise configuring portal SSO would silently let
every account in the company directory call the tenant's MCP servers, which no
one asked for. Same reasoning as portal SSO's `admin_groups`.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§3.4)
"""

from __future__ import annotations

from typing import Any

from storage.tenant_store import kv_get, kv_set


def _key(tenant_id: str) -> str:
    return f"shield:identity_policy:{tenant_id}"


def _clean_groups(groups: Any) -> list[str]:
    if not isinstance(groups, (list, tuple)):
        return []
    out = []
    for g in groups:
        g = str(g).strip()
        if g and g not in out:
            out.append(g)
    return out


def default_policy() -> dict:
    return {"mcp_sign_in": {"enabled": False, "allowed_groups": [], "provider": ""}}


def get_policy(tenant_id: str) -> dict:
    stored = kv_get(_key(tenant_id)) if tenant_id else None
    policy = default_policy()
    if isinstance(stored, dict) and isinstance(stored.get("mcp_sign_in"), dict):
        s = stored["mcp_sign_in"]
        policy["mcp_sign_in"] = {
            "enabled": bool(s.get("enabled")),
            "allowed_groups": _clean_groups(s.get("allowed_groups")),
            "provider": str(s.get("provider") or ""),
        }
    return policy


def set_policy(tenant_id: str, policy: dict) -> dict:
    """Validate and store. Raises ValueError with an operator-facing message."""
    s = (policy or {}).get("mcp_sign_in") or {}
    if not isinstance(s, dict):
        raise ValueError("mcp_sign_in must be an object")
    clean = {
        "enabled": bool(s.get("enabled")),
        "allowed_groups": _clean_groups(s.get("allowed_groups")),
        "provider": str(s.get("provider") or "").strip(),
    }
    if clean["enabled"] and not clean["allowed_groups"]:
        raise ValueError(
            "mcp_sign_in.allowed_groups is empty. Name the IdP groups whose "
            "members may sign in to your MCP servers; an empty list would admit "
            "everyone in your directory.")
    doc = {"mcp_sign_in": clean}
    kv_set(_key(tenant_id), doc)
    return doc


def sign_in_allowed(policy: dict, groups: list) -> bool:
    s = policy.get("mcp_sign_in") or {}
    allowed = set(s.get("allowed_groups") or [])
    return bool(s.get("enabled")) and bool(allowed) and bool(allowed.intersection(groups or []))
