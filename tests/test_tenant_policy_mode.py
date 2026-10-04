"""A tenant can see and switch its own enforcement mode.

Spec: docs/specs/tenant-enforce-mode.md, task 1. Before this, only the platform
admin API set policy_mode, and apply-template lands every tenant in monitor, so
a tenant could not see that it was unprotected nor do anything about it.

The test that carries the weight is the end-to-end one: a switch made here is
what the guard path enforces. The coverage guard keeps the portal's "applies
to" list honest about the one path monitor mode does not reach.
"""

import os
import re
from unittest.mock import patch

import pytest

from config.schema import GuardrailConfig, ShieldConfig

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAD = "default_bad"
TENANT = "mode-test-tenant"   # not the sandbox tenant, which the scope check exempts
TENANT_CFG = {"tenant_id": TENANT, "name": "Mode Co",
              "quota": {"max_requests_per_minute": 100_000}}
ADMIN_KEY = "mode-admin-key-aaaaaaaaaaaa"
RUNTIME_KEY = "mode-runtime-key-bbbbbbbbbb"
ADMIN = {"x-api-key": ADMIN_KEY}
RUNTIME = {"x-api-key": RUNTIME_KEY}
MODE = "/v1/tenant/me/policy-mode"


@pytest.fixture
def app(monkeypatch):
    import config.schema as cs
    from guardrails import registry as reg
    from storage import tenant_store

    cfg = ShieldConfig(guardrails={
        "keyword_blocklist": GuardrailConfig(
            enabled=True, action="block",
            settings={"keywords": [BAD], "case_insensitive": True}),
    })
    original = cs.config
    cs.config = cfg
    reg._registry.clear()
    reg._discovered = False
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(tenant_store, "_fallback_store", {})
    monkeypatch.setattr(tenant_store, "_cache", {})
    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE", raising=False)
    monkeypatch.delenv("SHIELD_TENANT_POLICY_MODE_SELF_SERVICE", raising=False)
    tenant_store.create_tenant(TENANT, dict(TENANT_CFG))
    tenant_store.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    tenant_store.add_api_key(TENANT, RUNTIME_KEY, scope="runtime")
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    yield app
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


@pytest.fixture
def audit(monkeypatch):
    import api.routes_tenant_self as tenant_self
    rows = []
    monkeypatch.setattr(tenant_self, "log_admin_action", lambda **kw: rows.append(kw))
    return rows


@pytest.fixture
def client(app, audit):
    """The guard path reads the tenant from the store on every call (no cache),
    so a switch is visible on the next request."""
    from starlette.testclient import TestClient
    from storage import tenant_store
    with patch("core.middleware._get_cached_tenant",
               side_effect=lambda key: (TENANT, tenant_store.get_tenant(TENANT))):
        yield TestClient(app)


def _stored_mode():
    from storage import tenant_store
    return (tenant_store.get_tenant(TENANT) or {}).get("policy_mode")


def _put(client, mode, reason=None, headers=ADMIN):
    body = {"mode": mode} if reason is None else {"mode": mode, "reason": reason}
    return client.put(MODE, json=body, headers=headers)


# ── reading ─────────────────────────────────────────────────────────────────

def test_default_is_enforce_and_says_what_it_covers(client):
    from core.middleware import _CACHE_TTL_SECONDS
    from storage import tenant_store
    r = client.get(MODE, headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["policy_mode"] == "enforce" and body["self_service"] is True
    assert body["takes_effect_within_seconds"] == _CACHE_TTL_SECONDS + tenant_store._CACHE_TTL
    assert "/guardrails/input" in body["applies_to"]
    assert body["not_applied_to"] == ["/guardrails/output"]


def test_a_hand_edited_value_reads_as_enforce(client):
    from storage import tenant_store
    tenant_store.update_tenant(TENANT, {"policy_mode": "Monitor "})
    assert client.get(MODE, headers=ADMIN).json()["policy_mode"] == "enforce"


def test_needs_a_tenant(app):
    from starlette.testclient import TestClient
    assert TestClient(app).get(MODE).status_code == 401


# ── switching ───────────────────────────────────────────────────────────────

def test_switch_to_monitor_and_back_is_stored_and_audited(client, audit):
    r = _put(client, "monitor", "piloting the new policy for a week")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "updated" and r.json()["previous"] == "enforce"
    assert _stored_mode() == "monitor"
    assert client.get(MODE, headers=ADMIN).json()["policy_mode"] == "monitor"

    r = _put(client, "enforce")                       # no reason needed to enforce
    assert r.status_code == 200 and r.json()["previous"] == "monitor"
    assert _stored_mode() == "enforce"

    assert [(a["action"], a["before"], a["after"], a["metadata"]) for a in audit] == [
        ("tenant_self_set_policy_mode", {"policy_mode": "enforce"}, {"policy_mode": "monitor"},
         {"reason": "piloting the new policy for a week"}),
        ("tenant_self_set_policy_mode", {"policy_mode": "monitor"}, {"policy_mode": "enforce"}, {}),
    ]
    assert all(a["tenant_id"] == TENANT and a["actor"] for a in audit)


@pytest.mark.parametrize("reason", [None, "", "   "])
def test_monitor_needs_a_reason(client, audit, reason):
    r = _put(client, "monitor", reason)
    assert r.status_code == 400 and "reason is required" in r.json()["detail"]
    assert _stored_mode() is None and audit == []


@pytest.mark.parametrize("body", [{"mode": "off"}, {"mode": "ENFORCE"},
                                  {"mode": "monitor", "reason": "x" * 501}])
def test_bad_requests_change_nothing(client, audit, body):
    assert client.put(MODE, json=body, headers=ADMIN).status_code == 400
    assert _stored_mode() is None and audit == []


def test_the_same_mode_again_is_unchanged_and_not_audited(client, audit):
    r = _put(client, "enforce")
    assert r.status_code == 200 and r.json()["status"] == "unchanged"
    assert _stored_mode() is None and audit == []


def test_another_tenant_id_in_the_body_is_refused(client):
    r = client.put(MODE, json={"mode": "monitor", "reason": "r", "tenant_id": "other"},
                   headers=ADMIN)
    assert r.status_code == 403
    assert _stored_mode() is None


# ── who may switch ──────────────────────────────────────────────────────────

def test_under_enforced_key_scope_only_an_admin_key_switches(client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    r = _put(client, "monitor", "testing", headers=RUNTIME)
    assert r.status_code == 403 and "change the enforcement mode" in r.json()["detail"]
    assert _stored_mode() is None
    assert _put(client, "monitor", "testing", headers=ADMIN).status_code == 200


def test_self_service_can_be_switched_off(client, monkeypatch, audit):
    monkeypatch.setenv("SHIELD_TENANT_POLICY_MODE_SELF_SERVICE", "off")
    r = _put(client, "enforce")
    assert r.status_code == 403 and "managed by your Shield administrator" in r.json()["detail"]
    assert client.get(MODE, headers=ADMIN).json()["self_service"] is False
    assert audit == []


# ── failure modes ───────────────────────────────────────────────────────────

def test_a_degraded_store_refuses_rather_than_writing_to_one_process(client, monkeypatch, audit):
    import core.auth as auth
    monkeypatch.setattr(auth, "_store_is_degraded", lambda: True)
    r = _put(client, "monitor", "testing")
    assert r.status_code == 503 and "not changed" in r.json()["detail"]
    assert _stored_mode() is None and audit == []


def test_a_change_lost_to_a_concurrent_write_is_409(client, monkeypatch, audit):
    import api.routes_tenant_self as tenant_self
    from storage import tenant_store

    def update_then_overwritten(tenant_id, updates):
        tenant_store.update_tenant(tenant_id, updates)
        # another writer that read the record before ours lands after it
        tenant_store.update_tenant(tenant_id, {"policy_mode": "enforce"})

    monkeypatch.setattr(tenant_self, "update_tenant", update_then_overwritten)
    r = _put(client, "monitor", "testing")
    assert r.status_code == 409 and "Reload and try again" in r.json()["detail"]
    assert audit == []


# ── end to end ──────────────────────────────────────────────────────────────

def test_the_switch_is_what_the_guard_path_enforces(client):
    def classify():
        return client.post("/guardrails/input", json={"message": f"a {BAD} prompt"},
                           headers=ADMIN).json()

    assert classify()["action"] == "block"

    assert _put(client, "monitor", "dry run").status_code == 200
    out = classify()
    assert out["action"] == "monitor" and out["safe"] is True
    assert "keyword_blocklist" in out["would_block"]

    assert _put(client, "enforce").status_code == 200
    assert classify()["action"] == "block"


# ── regression guard ────────────────────────────────────────────────────────

# Files that apply policy_mode on a guard path, and the label each earns in
# POLICY_MODE_APPLIES_TO. Adding or removing a call site must update both.
_CALL_SITE_LABELS = {
    "api/routes_classify.py": {"/guardrails/input", "/guardrails/file"},
    "api/routes_tool.py": {"tool and MCP calls"},
    "core/mcp/enforcement.py": {"tool and MCP calls"},
    "api/routes_gateway.py": {"gateway"},
    "api/routes_openai_compat.py": {"OpenAI-compatible proxy"},
    "api/routes_agent_chat.py": {"agent chat"},
    "api/routes_litellm_guardrail.py": {"LiteLLM"},
}
_NOT_GUARD_PATHS = {"core/policy_mode.py", "api/routes_tenant_self.py"}   # define / display only
_CALL = re.compile(r"\b(?:resolve_mode|apply_policy_mode|policy_mode\.apply|apply_to_response)\(")


def test_what_the_portal_says_monitor_covers_matches_the_code():
    import api.routes_tenant_self as tenant_self
    sites = set()
    for top in ("api", "core"):
        for dirpath, _, files in os.walk(os.path.join(ROOT, top)):
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(dirpath, f)
                    rel = os.path.relpath(path, ROOT)
                    if rel not in _NOT_GUARD_PATHS and _CALL.search(open(path, encoding="utf-8").read()):
                        sites.add(rel)
    assert sites == set(_CALL_SITE_LABELS), (
        "policy_mode call sites changed: update POLICY_MODE_APPLIES_TO / NOT_APPLIED_TO "
        f"in api/routes_tenant_self.py and this map. Now: {sorted(sites)}")
    assert set(tenant_self.POLICY_MODE_APPLIES_TO) == set().union(*_CALL_SITE_LABELS.values())
    assert "api/routes_classify_output.py" not in sites
    assert tenant_self.POLICY_MODE_NOT_APPLIED_TO == ["/guardrails/output"]
