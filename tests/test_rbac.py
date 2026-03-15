"""Tests for RBACEnforcer."""

import pytest
from unittest.mock import patch

from config.schema import RBACRole, RBACConfig, ShieldConfig


@pytest.fixture
def rbac_enforcer(mock_config):
    """Create an RBACEnforcer with mock config."""
    from core.rbac import RBACEnforcer
    return RBACEnforcer()


def test_resolve_role_known_agent(rbac_enforcer):
    """Test that a known agent key resolves to the correct role."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert role is not None
    assert role.name == "viewer"


def test_resolve_role_unknown_agent(rbac_enforcer):
    """Test that an unknown agent key returns None."""
    role = rbac_enforcer.resolve_role("unknown-agent")
    assert role is None


def test_check_tool_access_allowed(rbac_enforcer):
    """Test that an allowed tool passes the check."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert rbac_enforcer.check_tool_access(role, "search") is True


def test_check_tool_access_denied(rbac_enforcer):
    """Test that a denied tool fails the check."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert rbac_enforcer.check_tool_access(role, "execute_sql") is False


def test_check_tool_access_not_in_allowed_list(rbac_enforcer):
    """Test that a tool not in the allowed list is denied."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert rbac_enforcer.check_tool_access(role, "unknown_tool") is False


def test_check_tool_access_admin_all_allowed(rbac_enforcer):
    """Test that admin with empty allowed/denied lists can use any tool."""
    role = rbac_enforcer.resolve_role("agent-admin")
    assert rbac_enforcer.check_tool_access(role, "anything") is True


def test_check_data_access_allowed(rbac_enforcer):
    """Test that an allowed data scope passes."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert rbac_enforcer.check_data_access(role, "public_docs") is True


def test_check_data_access_denied(rbac_enforcer):
    """Test that a denied data scope fails."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert rbac_enforcer.check_data_access(role, "financials") is False


def test_check_data_access_not_in_allowed(rbac_enforcer):
    """Test that a scope not in the allowed list is denied."""
    role = rbac_enforcer.resolve_role("agent-viewer")
    assert rbac_enforcer.check_data_access(role, "secret_data") is False


def test_clearance_levels(rbac_enforcer):
    """Test that clearance levels are correctly mapped."""
    viewer_role = rbac_enforcer.resolve_role("agent-viewer")
    admin_role = rbac_enforcer.resolve_role("agent-admin")

    assert rbac_enforcer.get_clearance_level(viewer_role) == 0  # public
    assert rbac_enforcer.get_clearance_level(admin_role) == 3   # restricted
