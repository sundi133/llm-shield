"""Tests for Cross-Tenant Policy Inheritance."""

import pytest
import json
from unittest.mock import patch

from storage.tenant_store import (
    set_tenant_parent,
    get_tenant_parent,
    clear_tenant_parent,
    get_tenant_ancestors,
    _would_create_cycle,
)
from storage.policy_store import create_policy
from core.policy_inheritance import (
    get_effective_policies,
    validate_child_policy,
)


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear all relevant data between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("tenant_hierarchy:") or
                      k.startswith("policy:") or
                      k.startswith("policies:") or
                      k.startswith("policy_versions:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if
                      k.startswith("tenant_hierarchy:") or
                      k.startswith("policy:") or
                      k.startswith("policies:") or
                      k.startswith("policy_versions:")]
    for k in keys_to_remove:
        del _fallback_store[k]


@patch("storage.tenant_store._get_redis", return_value=None)
@patch("storage.policy_store._get_redis", return_value=None)
class TestTenantHierarchy:
    """Test tenant parent/child relationship management."""

    def test_set_and_get_parent(self, mock_ps_redis, mock_ts_redis):
        assert set_tenant_parent("child", "parent") is True
        assert get_tenant_parent("child") == "parent"

    def test_no_parent_returns_none(self, mock_ps_redis, mock_ts_redis):
        assert get_tenant_parent("orphan") is None

    def test_prevent_self_reference(self, mock_ps_redis, mock_ts_redis):
        assert set_tenant_parent("t1", "t1") is False

    def test_prevent_circular_dependency(self, mock_ps_redis, mock_ts_redis):
        set_tenant_parent("child", "parent")
        # Trying to set parent's parent to child → cycle
        assert set_tenant_parent("parent", "child") is False

    def test_prevent_deep_circular_dependency(self, mock_ps_redis, mock_ts_redis):
        set_tenant_parent("c", "b")
        set_tenant_parent("b", "a")
        # Trying to set a's parent to c → a → b → c → a cycle
        assert set_tenant_parent("a", "c") is False

    def test_clear_parent(self, mock_ps_redis, mock_ts_redis):
        set_tenant_parent("child", "parent")
        assert clear_tenant_parent("child") is True
        assert get_tenant_parent("child") is None

    def test_clear_parent_no_parent(self, mock_ps_redis, mock_ts_redis):
        assert clear_tenant_parent("orphan") is False

    def test_get_ancestors(self, mock_ps_redis, mock_ts_redis):
        set_tenant_parent("grandchild", "child")
        set_tenant_parent("child", "parent")

        ancestors = get_tenant_ancestors("grandchild")
        assert ancestors == ["child", "parent"]

    def test_get_ancestors_no_parent(self, mock_ps_redis, mock_ts_redis):
        assert get_tenant_ancestors("orphan") == []


@patch("storage.tenant_store._get_redis", return_value=None)
@patch("storage.policy_store._get_redis", return_value=None)
class TestPolicyInheritance:
    """Test policy inheritance merge logic."""

    def test_no_parent_returns_own_policies(self, mock_ps_redis, mock_ts_redis):
        create_policy("child", "p1", {"name": "Child Policy", "patterns": [], "roles": {}})

        effective = get_effective_policies("child")
        assert len(effective) == 1
        assert effective[0]["name"] == "Child Policy"

    def test_inherits_parent_policies(self, mock_ps_redis, mock_ts_redis):
        create_policy("parent", "p1", {"name": "Parent Policy", "patterns": [], "roles": {}})
        set_tenant_parent("child", "parent")

        effective = get_effective_policies("child")
        assert len(effective) == 1
        assert effective[0]["name"] == "Parent Policy"
        assert effective[0]["inherited_from"] == "parent"

    def test_child_adds_own_policies(self, mock_ps_redis, mock_ts_redis):
        create_policy("parent", "p1", {"name": "Parent Policy", "patterns": [], "roles": {}})
        create_policy("child", "p2", {"name": "Child Policy", "patterns": [], "roles": {}})
        set_tenant_parent("child", "parent")

        effective = get_effective_policies("child")
        assert len(effective) == 2
        names = [p["name"] for p in effective]
        assert "Parent Policy" in names
        assert "Child Policy" in names

    def test_child_overrides_parent_policy_stricter(self, mock_ps_redis, mock_ts_redis):
        create_policy("parent", "p1", {
            "name": "Parent",
            "patterns": [],
            "roles": {"user": {"pii": "redact"}},
            "enabled": True,
        })
        create_policy("child", "p1", {
            "name": "Child Override",
            "patterns": [],
            "roles": {"user": {"pii": "block"}},  # Stricter — allowed
            "enabled": True,
        })
        set_tenant_parent("child", "parent")

        effective = get_effective_policies("child")
        assert len(effective) == 1
        assert effective[0]["name"] == "Child Override"

    def test_child_cannot_weaken_parent_policy(self, mock_ps_redis, mock_ts_redis):
        create_policy("parent", "p1", {
            "name": "Parent Strict",
            "patterns": [],
            "roles": {"user": {"pii": "block"}},
            "enabled": True,
        })
        create_policy("child", "p1", {
            "name": "Child Weak",
            "patterns": [],
            "roles": {"user": {"pii": "allow"}},  # Weaker — rejected
            "enabled": True,
        })
        set_tenant_parent("child", "parent")

        effective = get_effective_policies("child")
        assert len(effective) == 1
        # Should use parent policy since child tried to weaken
        assert effective[0]["name"] == "Parent Strict"
        assert "inheritance_override_rejected" in effective[0]

    def test_child_cannot_disable_parent_policy(self, mock_ps_redis, mock_ts_redis):
        create_policy("parent", "p1", {
            "name": "Parent Enabled",
            "patterns": [],
            "roles": {},
            "enabled": True,
        })
        create_policy("child", "p1", {
            "name": "Child Disabled",
            "patterns": [],
            "roles": {},
            "enabled": False,  # Trying to disable — rejected
        })
        set_tenant_parent("child", "parent")

        effective = get_effective_policies("child")
        assert len(effective) == 1
        assert effective[0]["name"] == "Parent Enabled"

    def test_multi_level_inheritance(self, mock_ps_redis, mock_ts_redis):
        create_policy("grandparent", "gp1", {"name": "GP Policy", "patterns": [], "roles": {}})
        create_policy("parent", "p1", {"name": "Parent Policy", "patterns": [], "roles": {}})
        create_policy("child", "c1", {"name": "Child Policy", "patterns": [], "roles": {}})

        set_tenant_parent("child", "parent")
        set_tenant_parent("parent", "grandparent")

        effective = get_effective_policies("child")
        assert len(effective) == 3
        names = [p["name"] for p in effective]
        assert "GP Policy" in names
        assert "Parent Policy" in names
        assert "Child Policy" in names


class TestValidateChildPolicy:
    """Test policy validation logic."""

    def test_valid_stricter_override(self):
        parent = {"enabled": True, "roles": {"user": {"pii": "redact"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "block"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is True

    def test_invalid_weaker_override(self):
        parent = {"enabled": True, "roles": {"user": {"pii": "block"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "allow"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is False
        assert "weakened" in reason

    def test_invalid_disable(self):
        parent = {"enabled": True, "roles": {}}
        child = {"enabled": False, "roles": {}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is False
        assert "disable" in reason.lower()

    def test_equal_strictness_is_valid(self):
        parent = {"enabled": True, "roles": {"user": {"pii": "redact"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "redact"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is True

    def test_child_adds_new_role(self):
        parent = {"enabled": True, "roles": {"user": {"pii": "block"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "block"}, "admin": {"pii": "allow"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is True  # Adding new roles is fine
