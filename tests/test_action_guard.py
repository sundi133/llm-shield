"""Tests for ActionGuard."""

import pytest
from unittest.mock import patch

from guardrails.agentic.action_guard import ActionGuard, _session_actions, reset_session


@pytest.fixture(autouse=True)
def clean_sessions():
    """Reset session state before each test."""
    _session_actions.clear()
    yield
    _session_actions.clear()


@pytest.fixture
def action_guard(mock_config):
    """Create an ActionGuard with mock config."""
    return ActionGuard()


@pytest.mark.asyncio
async def test_action_within_limits(action_guard):
    """Test that actions within limits pass."""
    context = {"session_id": "s1", "action_type": "delete"}
    result = await action_guard.check("do something", context)
    # delete is in sensitive_actions, so it passes with a warn
    assert result.passed
    assert result.action == "warn"
    assert result.details["sensitive"] is True


@pytest.mark.asyncio
async def test_action_exceeds_limit(action_guard):
    """Test that exceeding the action limit blocks."""
    context = {"session_id": "s2", "action_type": "delete"}
    # max delete = 2, so 2 should pass and 3rd should block
    await action_guard.check("delete", context)
    await action_guard.check("delete", context)
    result = await action_guard.check("delete", context)
    assert not result.passed
    assert result.action == "block"
    assert "limit reached" in result.message


@pytest.mark.asyncio
async def test_sensitive_action_flagged(action_guard):
    """Test that sensitive actions are flagged with a warn."""
    context = {"session_id": "s3", "action_type": "modify_permissions"}
    result = await action_guard.check("modify permissions", context)
    assert result.passed
    assert result.action == "warn"
    assert result.details["sensitive"] is True


@pytest.mark.asyncio
async def test_normal_action_passes(action_guard):
    """Test that a non-sensitive, non-limited action passes cleanly."""
    context = {"session_id": "s4", "action_type": "read"}
    result = await action_guard.check("read data", context)
    assert result.passed
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_requires_approval(action_guard):
    """Test that actions requiring approval are blocked without approval."""
    context = {"session_id": "s5", "action_type": "delete_account"}
    result = await action_guard.check("delete account", context)
    assert not result.passed
    assert "requires approval" in result.message

    # With approval, it should pass
    context["approved"] = True
    result = await action_guard.check("delete account", context)
    assert result.passed
