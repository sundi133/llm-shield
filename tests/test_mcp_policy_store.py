"""Tests for the MCP policy profile store (fleet control plane, phase 1).

Redis forced off (fallback store), mirroring tests/test_mcp_gateway.py.

Phase 1 stores and indexes profiles; nothing enforces them yet. These tests pin
the storage contract the later enforcement phases build on — in particular the
bound-route index, which is what lets a profile write fan out to its routes.
"""

from unittest.mock import patch

import pytest

from storage import mcp_policy_store as store
from storage.mcp_gateway_store import is_valid_route_name

_PREFIXES = ("mcp_profile:", "mcp_profiles:")


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(_PREFIXES)]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


# ── profile CRUD ─────────────────────────────────────────────────────


def test_set_get_list_delete():
    store.set_profile("acme", "saas-untrusted", {"description": "third-party"})
    doc = store.get_profile("acme", "saas-untrusted")
    assert doc["description"] == "third-party"
    assert doc["profile_id"] == "saas-untrusted"
    assert doc["tenant_id"] == "acme"

    store.set_profile("acme", "internal", {"description": "trusted"})
    assert [p["profile_id"] for p in store.list_profiles("acme")] == ["internal", "saas-untrusted"]

    assert store.delete_profile("acme", "internal") is True
    assert store.get_profile("acme", "internal") is None
    assert store.delete_profile("acme", "internal") is False


def test_get_missing_returns_none():
    assert store.get_profile("acme", "nope") is None
    assert store.list_profiles("acme") == []
    assert store.list_bound_routes("acme", "nope") == []


def test_replace_preserves_created_at_and_advances_updated_at():
    """created_at is the profile's birth; updated_at is the revision token routes
    compare against to detect drift, so a replace must move it forward."""
    first = store.set_profile("acme", "p", {"description": "v1"})
    second = store.set_profile("acme", "p", {"description": "v2"})
    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] >= first["updated_at"]
    assert second["description"] == "v2"


def test_caller_cannot_forge_revision_fields():
    """A caller-supplied updated_at could make a stale route look current, so the
    store stamps it regardless of what the body claims."""
    doc = store.set_profile("acme", "p", {"description": "x", "updated_at": 1,
                                          "tenant_id": "other", "profile_id": "other"})
    assert doc["updated_at"] != 1
    assert doc["tenant_id"] == "acme"
    assert doc["profile_id"] == "p"


def test_tenant_isolation():
    store.set_profile("a", "p", {"description": "for-a"})
    store.set_profile("b", "p", {"description": "for-b"})
    assert store.get_profile("a", "p")["description"] == "for-a"
    assert store.get_profile("b", "p")["description"] == "for-b"
    assert [p["profile_id"] for p in store.list_profiles("a")] == ["p"]

    store.delete_profile("a", "p")
    assert store.get_profile("b", "p") is not None  # unaffected


# ── bound-route index (drives fan-out in a later phase) ──────────────


def test_bind_unbind_is_idempotent():
    store.set_profile("acme", "p", {})
    store.bind_route("acme", "p", "higgsfield")
    store.bind_route("acme", "p", "higgsfield")  # again
    assert store.list_bound_routes("acme", "p") == ["higgsfield"]

    store.bind_route("acme", "p", "vendor-x")
    assert store.list_bound_routes("acme", "p") == ["higgsfield", "vendor-x"]  # sorted

    store.unbind_route("acme", "p", "higgsfield")
    store.unbind_route("acme", "p", "higgsfield")  # again
    assert store.list_bound_routes("acme", "p") == ["vendor-x"]


def test_delete_profile_clears_binding_index():
    """A stale index would make a recreated profile inherit routes nobody bound."""
    store.set_profile("acme", "p", {})
    store.bind_route("acme", "p", "r1")
    store.delete_profile("acme", "p")

    store.set_profile("acme", "p", {})
    assert store.list_bound_routes("acme", "p") == []


def test_binding_index_is_tenant_scoped():
    store.set_profile("a", "p", {})
    store.set_profile("b", "p", {})
    store.bind_route("a", "p", "r1")
    assert store.list_bound_routes("b", "p") == []


# ── shared route/profile name rule ───────────────────────────────────


@pytest.mark.parametrize("name", ["higgsfield", "vendor-x", "a", "A1_b-2", "x" * 64])
def test_valid_names(name):
    assert is_valid_route_name(name) is True


@pytest.mark.parametrize("name", [
    "",                  # empty
    "has:colon",         # would make `route:tool` ambiguous
    "has/slash",         # breaks the gateway URL path
    "has space",
    "-leading-dash",     # must start alphanumeric
    "x" * 65,            # too long
])
def test_invalid_names(name):
    assert is_valid_route_name(name) is False
