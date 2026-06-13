"""Offline tests for the MCP proxy enforcement core.

The two slow (LLM-backed) guards are stubbed so the test runs without a model —
we are verifying the proxy's *wiring* to the existing guards, not the LLMs.

    PYTHONPATH=. python tests/test_mcp_enforcement.py
"""

import asyncio
import json

# ── Stub the LLM entry points before importing the enforcement core ──
import guardrails.agentic.tool.tool_call_validation as _tcv
import guardrails.agentic.tool.tool_output_sanitization as _tos


async def _no_issue(*a, **k):
    return None  # payload validation finds nothing


async def _boom(*a, **k):
    raise RuntimeError("offline")  # forces sanitizer's fail-open path


_tcv.evaluate_payload_policy_llm = _no_issue
_tos.async_llm_call = _boom

from storage.tenant_store import kv_set
from core.mcp.enforcement import (
    enforce_tool_call, sanitize_tool_result, filter_tools_for_role,
)

TENANT = "mcp-enf-tenant"
AGENT = "support-bot"


def _seed(status="active"):
    kv_set(f"agents:{TENANT}", {
        AGENT: {
            "agent_id": AGENT,
            "tools": ["get_balance", "wire_transfer"],
            "role_permissions": {
                "admin": ["get_balance", "wire_transfer"],
                "support": ["get_balance"],
            },
            "status": status,
        }
    })


def _enforce(tool, role="support", args=None, tenant_config=None):
    return asyncio.run(enforce_tool_call(
        tool, args or {}, agent_key=AGENT, user_role=role,
        tenant_id=TENANT, tenant_config=tenant_config,
    ))


def test_allowed_call_passes():
    _seed()
    d = _enforce("get_balance", "support")
    assert d["allowed"] is True
    assert d["action"] == "pass"
    assert d["risk"] == "low"


def test_role_violation_blocked_in_enforce():
    _seed()
    d = _enforce("wire_transfer", "support", {"amount": 999})
    assert d["allowed"] is False
    assert d["action"] == "block"
    assert "not allowed" in d["reason"].lower()
    assert d["risk"] == "high"          # name + money arg
    assert "rbac_guard" in d["would_block"]


def test_admin_role_allowed():
    _seed()
    d = _enforce("wire_transfer", "admin", {"amount": 999})
    assert d["allowed"] is True


def test_monitor_mode_does_not_block_policy_finding():
    _seed()
    d = _enforce("wire_transfer", "support", {"amount": 999},
                 tenant_config={"policy_mode": "monitor"})
    assert d["allowed"] is True          # observe-only: nothing blocked
    assert d["mode"] == "monitor"
    assert d["action"] == "monitor"
    assert "rbac_guard" in d["would_block"]   # but it's surfaced


def test_disabled_agent_blocks_even_in_monitor():
    _seed(status="disabled")
    d = _enforce("get_balance", "support",
                 tenant_config={"policy_mode": "monitor"})
    assert d["allowed"] is False          # administrative block is not dry-run
    assert d["action"] == "block"


def test_sanitize_failopen_returns_original():
    _seed()
    out = {"ssn": "123-45-6789"}
    r = asyncio.run(sanitize_tool_result(
        "get_balance", out, agent_key=AGENT, tenant_id=TENANT, user_role="support"))
    assert r["blocked"] is False
    # LLM offline -> fail open; dict output is normalized to JSON text and
    # round-trips unchanged.
    assert json.loads(r["sanitized_output"]) == out


def test_sanitize_string_passthrough():
    _seed()
    r = asyncio.run(sanitize_tool_result(
        "get_balance", "balance: $42", agent_key=AGENT, tenant_id=TENANT, user_role="support"))
    assert r["blocked"] is False
    assert r["sanitized_output"] == "balance: $42"


def test_filter_tools_for_role_hides_disallowed():
    _seed()
    tools = [{"name": "get_balance"}, {"name": "wire_transfer"}, {"name": "delete_x"}]
    visible = filter_tools_for_role(
        tools, agent_key=AGENT, user_role="support", tenant_id=TENANT)
    names = {t["name"] for t in visible}
    assert names == {"get_balance"}                 # role-filtered
    assert visible[0]["x-shield-risk"] == "low"     # annotated

    admin_view = filter_tools_for_role(
        tools, agent_key=AGENT, user_role="admin", tenant_id=TENANT)
    assert {t["name"] for t in admin_view} == {"get_balance", "wire_transfer"}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
