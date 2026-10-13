"""Decision binding: arg-hash + policy/schema/connector versions (M2 Task 3)."""
from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

import storage.decision_audit as da
import storage.tenant_store as tstore
from core.mcp import policy_runtime
from core.mcp.enforcement import enforce_tool_call
from storage import policy_snapshot_store as store


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    tstore._fallback_store.clear()
    policy_runtime.invalidate_cache()
    monkeypatch.delenv("SHIELD_MCP_AUDIT_REQUIRED", raising=False)
    yield
    tstore._fallback_store.clear()
    policy_runtime.invalidate_cache()


@pytest.fixture
def captured(monkeypatch):
    box = {}
    monkeypatch.setattr(da, "log_decision", lambda **kw: box.update(kw))
    return box


def test_binding_fields_present(captured):
    asyncio.run(enforce_tool_call(
        "balance_get", {"id": 7}, agent_key="", user_role="analyst", tenant_id="t",
        tenant_config={"authz_mode": "legacy"},
        schema_version="cat_abc", connector_version="9"))
    md = captured["metadata"]
    assert md["schema_version"] == "cat_abc"
    assert md["connector_version"] == "9"
    assert md["policy_version"] == 0          # legacy: no policy gate
    # arg_hash is the sha256 of the canonical args, and the args themselves are
    # never recorded.
    expected = hashlib.sha256(json.dumps({"id": 7}, sort_keys=True).encode()).hexdigest()
    assert md["arg_hash"] == expected
    assert "arguments" not in md


def test_arg_hash_is_stable_and_order_independent(captured):
    asyncio.run(enforce_tool_call("t", {"a": 1, "b": 2}, agent_key="", user_role="r",
                                  tenant_id="t", tenant_config={"authz_mode": "legacy"}))
    h1 = captured["metadata"]["arg_hash"]
    asyncio.run(enforce_tool_call("t", {"b": 2, "a": 1}, agent_key="", user_role="r",
                                  tenant_id="t", tenant_config={"authz_mode": "legacy"}))
    assert captured["metadata"]["arg_hash"] == h1


def test_policy_version_is_the_enforcing_snapshot(captured):
    store.save_draft("t", {"default": "allow", "rules": []})
    store.publish("t", published_by="op")       # v1
    policy_runtime.invalidate_cache("t")
    asyncio.run(enforce_tool_call("pay", {}, agent_key="", user_role="r", tenant_id="t",
                                  tenant_config={"authz_mode": "declarative"}))
    assert captured["metadata"]["policy_version"] == 1
