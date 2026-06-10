"""Tests for the Agent Registry on/off toggle enforcement in RBACGuard.

A registry agent whose status is "disabled" must be blocked from acting
regardless of its role permissions (per-agent kill switch). Re-enabling it
(status "active") restores normal RBAC behavior.
"""

import json

import pytest

import storage.tenant_store as ts
from guardrails.agentic.rbac_guard import RBACGuard

TENANT = "tenant-toggle-test"
AGENT = "people-agent"


@pytest.fixture(autouse=True)
def memory_store(monkeypatch):
    """Force the in-memory fallback store so tests don't touch a real Redis."""
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    ts._fallback_store.clear()
    yield
    ts._fallback_store.clear()


def _seed_agent(status: str):
    agents = {
        AGENT: {
            "agent_id": AGENT,
            "name": "People Directory Agent",
            "tools": ["lookup_employee"],
            "role_permissions": {"employee": ["lookup_employee"]},
            "status": status,
        }
    }
    ts._fallback_store[f"agents:{TENANT}"] = json.dumps(agents)


def _context():
    return {
        "agent_key": AGENT,
        "tool_name": "lookup_employee",
        "tenant_id": TENANT,
        "user_role": "employee",
    }


@pytest.mark.asyncio
async def test_disabled_agent_is_blocked():
    """A disabled agent is denied even for a tool its role normally allows."""
    _seed_agent("disabled")
    result = await RBACGuard().check("", _context())
    assert result.passed is False
    assert result.action == "block"
    assert "disabled" in result.message.lower()
    assert result.details.get("status") == "disabled"


@pytest.mark.asyncio
async def test_active_agent_is_allowed():
    """An active agent passes RBAC for a tool its role allows."""
    _seed_agent("active")
    result = await RBACGuard().check("", _context())
    assert result.passed is True


@pytest.mark.asyncio
async def test_inactive_agent_is_blocked():
    """Any non-active registered state (e.g. "inactive") is blocked, not just "disabled"."""
    _seed_agent("inactive")
    result = await RBACGuard().check("", _context())
    assert result.passed is False
    assert result.details.get("status") == "inactive"


@pytest.mark.asyncio
async def test_unknown_status_is_blocked():
    """An unexpected/tampered status value fails closed (only "active" is allowed)."""
    _seed_agent("bogus-injected-value")
    result = await RBACGuard().check("", _context())
    assert result.passed is False


@pytest.mark.asyncio
async def test_reenabling_restores_access():
    """Flipping the toggle back to active restores access for the same agent."""
    _seed_agent("disabled")
    blocked = await RBACGuard().check("", _context())
    assert blocked.passed is False

    _seed_agent("active")
    allowed = await RBACGuard().check("", _context())
    assert allowed.passed is True
