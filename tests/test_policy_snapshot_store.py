"""Versioned immutable policy snapshots + draft (M2 Task 1)."""
from __future__ import annotations

import pytest

import storage.tenant_store as tstore
from core.mcp.policy_lang import PolicyError, evaluate
from storage import policy_snapshot_store as store

T = "acme"


@pytest.fixture(autouse=True)
def clean():
    tstore._fallback_store.clear()
    yield
    tstore._fallback_store.clear()


def _doc(default, *rules):
    return {"default": default, "rules": list(rules)}


def test_save_draft_validates():
    with pytest.raises(PolicyError):
        store.save_draft(T, {"default": "sideways"})
    saved = store.save_draft(T, _doc("deny", {"id": "r1", "effect": "allow", "roles": ["a"], "tools": ["t"]}))
    assert saved["default"] == "deny"
    assert store.get_draft(T)["rules"][0]["id"] == "r1"


def test_publish_increments_and_sets_current():
    store.save_draft(T, _doc("deny"))
    assert store.get_current_version(T) == 0
    r1 = store.publish(T, published_by="op1", note="first")
    assert r1["version"] == 1 and store.get_current_version(T) == 1
    store.save_draft(T, _doc("allow"))
    r2 = store.publish(T, published_by="op1")
    assert r2["version"] == 2 and store.get_current_version(T) == 2


def test_snapshot_is_immutable_and_enforceable():
    store.save_draft(T, _doc("deny", {"id": "r1", "effect": "allow", "roles": ["*"], "tools": ["read"]}))
    store.publish(T, published_by="op")
    snap = store.get_snapshot(T)      # current
    assert evaluate(snap, "x", "read")["effect"] == "allow"
    assert evaluate(snap, "x", "write")["effect"] == "deny"
    # Editing the draft afterwards does not change the published snapshot.
    store.save_draft(T, _doc("allow"))
    assert evaluate(store.get_snapshot(T, 1), "x", "write")["effect"] == "deny"


def test_rollback_moves_pointer_to_earlier_immutable_version():
    store.save_draft(T, _doc("deny"))
    store.publish(T, published_by="op")           # v1 deny-all
    store.save_draft(T, _doc("allow"))
    store.publish(T, published_by="op")           # v2 allow-all
    assert evaluate(store.get_snapshot(T), "x", "y")["effect"] == "allow"   # current v2
    store.rollback(T, 1)
    assert store.get_current_version(T) == 1
    assert evaluate(store.get_snapshot(T), "x", "y")["effect"] == "deny"    # back to v1


def test_rollback_to_missing_version_raises():
    store.save_draft(T, _doc("deny"))
    store.publish(T, published_by="op")
    with pytest.raises(ValueError):
        store.rollback(T, 99)


def test_publish_without_draft_raises():
    with pytest.raises(ValueError):
        store.publish("nodraft", published_by="op")


def test_history_and_delete_all():
    store.save_draft(T, _doc("deny"))
    store.publish(T, published_by="op1", note="a")
    store.save_draft(T, _doc("allow"))
    store.publish(T, published_by="op2", note="b")
    hist = store.list_versions(T)
    assert [h["version"] for h in hist] == [2, 1]        # newest first
    assert hist[0]["published_by"] == "op2"
    store.delete_all(T)
    assert store.get_current_version(T) == 0 and store.get_draft(T) is None
    assert store.get_snapshot(T, 1) is None
