"""Guard-path side of the declarative policy engine (M2 Task 2).

Reads a tenant's published, compiled policy snapshot and turns it into one
authorization result that composes with the existing guard chain in
core.mcp.enforcement.enforce_tool_call. Three properties keep it on the guard
path within budget:

- **Compile at publish, not at call** — this only *reads* the snapshot the admin
  plane already compiled.
- **Immutable, version-keyed cache** — a snapshot never changes, so it is cached
  in-process forever by (tenant, version); only the current-version pointer is
  re-read, behind a short TTL. A publish takes effect within that TTL.
- **Fail-closed in declarative mode** — if the snapshot cannot be loaded, the
  call is denied. A tenant that chose default-deny must not fall open to
  allow-all on a Redis outage. Legacy tenants never reach here.

Spec: docs/specs/spec-mcp-gateway-m2-policy-engine.md.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

from core.mcp.policy_lang import evaluate
from storage import policy_snapshot_store as store

logger = logging.getLogger("votal.policy_runtime")

_MODES = ("legacy", "declarative")
_ver_cache: dict = {}        # tenant_id -> (version:int, expires_at:float)
_snap_cache: dict = {}       # (tenant_id, version) -> snapshot (immutable)


def _ttl() -> int:
    try:
        return max(1, int(os.environ.get("POLICY_SNAPSHOT_CACHE_TTL", "60")))
    except (TypeError, ValueError):
        return 60


def default_new_tenant_mode() -> str:
    """The authz_mode a newly created tenant gets.

    Default `legacy` (today's allow-all-on-empty) so turning M2 on is non-breaking
    per the repo invariant: creating a tenant does not silently change until a
    deployment opts in with `SHIELD_MCP_AUTHZ_DEFAULT=declarative`, which makes new
    tenants default-deny with a visible starter allow-all to narrow. An existing
    tenant is migrated individually via PUT /v1/admin/tenants/{id}/authz-mode."""
    v = os.environ.get("SHIELD_MCP_AUTHZ_DEFAULT", "legacy").strip().lower()
    return v if v in _MODES else "legacy"


def authz_mode(tenant_config: Optional[dict]) -> str:
    """A tenant's authorization mode. Unset (every tenant from before M2) reads
    as `legacy` — today's allow-all-on-empty — so nothing changes until an
    operator migrates the tenant."""
    m = (tenant_config or {}).get("authz_mode")
    return m if m in _MODES else "legacy"


def _current_version(tenant_id: str) -> int:
    now = time.time()
    hit = _ver_cache.get(tenant_id)
    if hit and hit[1] > now:
        return hit[0]
    version = store.get_current_version(tenant_id)
    _ver_cache[tenant_id] = (version, now + _ttl())
    return version


def _snapshot(tenant_id: str):
    version = _current_version(tenant_id)
    if not version:
        return None, version
    key = (tenant_id, version)
    snap = _snap_cache.get(key)
    if snap is None:
        snap = store.get_snapshot(tenant_id, version)
        if snap is not None:
            _snap_cache[key] = snap        # immutable: cache for this process
    return snap, version


def invalidate_cache(tenant_id: Optional[str] = None) -> None:
    """Drop cached pointers/snapshots. Called by tests and after a publish in the
    same process; cross-process propagation is bounded by the TTL."""
    if tenant_id is None:
        _ver_cache.clear()
        _snap_cache.clear()
    else:
        _ver_cache.pop(tenant_id, None)
        for k in [k for k in _snap_cache if k[0] == tenant_id]:
            _snap_cache.pop(k, None)


def authz_result(tenant_id: Optional[str], tenant_config: Optional[dict],
                 user_role: Optional[str], tool_name: str) -> Optional[dict]:
    """One guard-chain result for the declarative authorization decision, or None
    when the tenant is in legacy mode (no snapshot gate — today's behaviour).

    A deny is a normal (non-administrative) block, so monitor mode can preview it
    without enforcing. Fail-closed: any load failure, or declarative-with-no-policy,
    denies.
    """
    if authz_mode(tenant_config) != "declarative":
        return None

    effect, version, rule_id, default_used = "deny", 0, None, True
    try:
        snapshot, version = _snapshot(tenant_id or "")
        if snapshot is None:
            effect = "deny"                 # declarative but nothing published: fail-closed
        else:
            decision = evaluate(snapshot, user_role or "", tool_name)
            effect = decision["effect"]
            rule_id = decision.get("rule_id")
            default_used = decision.get("default_used", True)
            version = snapshot.get("version", version)
    except Exception as e:                  # noqa: BLE001 — never fall open
        logger.debug("policy snapshot load failed, denying: %s", e)
        effect = "deny"

    passed = effect == "allow"
    return {
        "guardrail": "policy_authz",
        "passed": passed,
        "action": "pass" if passed else "block",
        "message": "" if passed else (
            f"'{tool_name}' is not permitted for role '{user_role or ''}' by the "
            "tenant authorization policy"),
        "details": {"administrative": False, "policy_version": version,
                    "rule_id": rule_id, "default_used": default_used, "effect": effect},
    }
