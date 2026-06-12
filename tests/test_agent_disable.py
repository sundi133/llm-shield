"""Offline tests: agent status=disabled is enforced at every layer.

    PYTHONPATH=. python tests/test_agent_disable.py
"""

import asyncio
import json

from storage.tenant_store import kv_set
from guardrails.agentic.rbac_guard import RBACGuard, _load_agent_entry
from core.middleware import _get_registered_agents, invalidate_registry_cache

TENANT = "disable-test-tenant"


def _seed(status):
    agents = {
        "cs-agent": {
            "agent_id": "cs-agent",
            "tools": ["customer_profile_get", "email_send"],
            "role_permissions": {"customer_support": ["customer_profile_get", "email_send"]},
            **({"status": status} if status is not None else {}),
        },
    }
    kv_set(f"agents:{TENANT}", agents)
    invalidate_registry_cache(TENANT)


def _check(role="customer_support", tool="customer_profile_get"):
    guard = RBACGuard()
    ctx = {"agent_key": "cs-agent", "tool_name": tool, "tenant_id": TENANT,
           "user_role": role, "tool_params": {}}
    return asyncio.run(guard.check("", ctx))


def test_active_agent_allowed():
    _seed("active")
    r = _check()
    assert r.passed, r.message


def test_legacy_agent_without_status_allowed():
    _seed(None)
    r = _check()
    assert r.passed, r.message


def test_disabled_agent_blocked_regardless_of_role():
    _seed("disabled")
    r = _check()
    assert not r.passed
    assert r.action == "block"
    assert "disabled" in r.message
    assert r.details.get("administrative") is True


def test_loader_reads_fallback_store():
    _seed("disabled")
    entry = _load_agent_entry("cs-agent", TENANT)
    assert entry and entry["status"] == "disabled"


def test_middleware_registry_statuses():
    _seed("disabled")
    reg = _get_registered_agents(TENANT)
    assert reg.get("cs-agent") == "disabled"
    # membership semantics preserved (shadow-agent logic relies on `in`)
    assert "cs-agent" in reg and "ghost" not in reg
    # toggle back on; invalidation makes it visible immediately despite TTL
    _seed("active")
    assert _get_registered_agents(TENANT).get("cs-agent") == "active"


def test_playground_check_rbac_blocks_disabled():
    from admin_app import _check_rbac
    registry = json.loads(json.dumps({
        "cs-agent": {
            "tools": ["email_send"],
            "role_permissions": {"customer_support": ["email_send"]},
            "status": "disabled",
        },
        "caller": {"tools": [], "status": "disabled"},
        "target": {
            "tools": ["email_send"],
            "role_permissions": {"customer_support": ["email_send"]},
            "agent_permissions": {"caller": ["email_send"]},
            "status": "active",
        },
    }))
    # direct: disabled agent blocked even though role permits the tool
    r = _check_rbac("email_send", "cs-agent", "customer_support", None, registry=registry)
    assert not r["allowed"] and r["source"] == "agent_status"
    # delegation: disabled CALLING agent blocked on an active target
    r = _check_rbac("email_send", "target", "customer_support", None,
                    registry=registry, calling_agent="caller")
    assert not r["allowed"] and r["source"] == "agent_status"
    # sanity: active path still allowed
    r = _check_rbac("email_send", "target", "customer_support", None, registry=registry)
    assert r["allowed"], r["message"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
