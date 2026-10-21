"""The hook route's laptop-key rules (docs/specs/hooks-plugin-production.md, task 2).

F2: whoever holds a laptop's key could name an agent with no runtime profile
and every call was allowed. F3: any tenant key was accepted, including one
that can change the tenant's policy. Plus what the hook script reports about
itself, kept for coverage.
"""

import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.runtime_policy import check as rc
from core.runtime_policy import hook_seen, hooks
from core.runtime_policy import store as rt_store

PROFILE = {"description": "laptop", "process": {"deny_commands": ["openssl enc*"]}}
CALL = {"session_id": "s-1", "cwd": "/Users/dev/proj", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t1"}
DENIED = {**CALL, "tool_input": {"command": "openssl enc -in a"}}


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SHIELD_HOOKS_ALLOW_ADMIN_KEY", raising=False)
    hooks.reset_cache_for_tests()
    hook_seen.reset_for_tests()
    rt_store.reset_memory()
    rc.invalidate()
    yield
    rc.invalidate()


def _tenant(app, config=None):
    from starlette.testclient import TestClient
    from storage.tenant_store import add_api_key, create_tenant

    tid = "lk" + uuid.uuid4().hex[:10]
    settings_key = "sk-lk-admin-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise", **(config or {})})
    add_api_key(tid, settings_key, scope="admin")
    c = TestClient(app)
    h = {"X-API-Key": settings_key}
    assert c.put("/v1/tenant/me/runtime-profiles/laptop", json=PROFILE, headers=h).status_code == 200
    r = c.post("/v1/agents/registry", headers=h, json={
        "agent_id": "claude-code", "tools": ["x"], "role_permissions": {"dev": ["x"]},
        "runtime_profile": "laptop"})
    assert r.status_code in (200, 201), r.text

    def key(scope=None, agent=None):
        k = "sk-lk-" + uuid.uuid4().hex
        add_api_key(tid, k, scope=scope, agent=agent)
        return k

    return SimpleNamespace(id=tid, c=c, settings_key=settings_key, key=key)


def _post(t, key, body=CALL, agent="claude-code", **headers):
    hdrs = {"Content-Type": "application/json", "X-API-Key": key, "X-Shield-User": "dev",
            "X-Device-Id": "mac-1", **headers}
    if agent is not None:
        hdrs["X-Agent-Key"] = agent
    return t.c.post("/v1/shield/hooks/claude-code", content=json.dumps(body), headers=hdrs)


def _denied(r):
    return r.json().get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


# ── admin-scoped keys (F3) ───────────────────────────────────────────


def test_an_admin_scoped_key_is_refused_on_the_hook_route(app):
    t = _tenant(app)
    r = _post(t, t.settings_key)
    assert r.status_code == 403 and "runtime key" in r.text


def test_the_escape_hatch_lets_an_admin_key_through(app, monkeypatch):
    monkeypatch.setenv("SHIELD_HOOKS_ALLOW_ADMIN_KEY", "1")
    t = _tenant(app)
    assert (_post(t, t.settings_key).status_code, _post(t, t.settings_key).json()) == (200, {})


def test_runtime_keys_work_and_unscoped_keys_are_warned(app):
    t = _tenant(app)
    r = _post(t, t.key(scope="runtime"))
    assert r.status_code == 200 and "warning" not in {k.lower() for k in r.headers}
    r = _post(t, t.key())
    assert r.status_code == 200 and "unscoped" in r.headers.get("warning", "")


# ── keys bound to an agent (F2) ──────────────────────────────────────


def test_a_bound_key_uses_its_agent_and_refuses_another(app):
    t = _tenant(app)
    k = t.key(scope="runtime", agent="claude-code")
    assert _denied(_post(t, k, DENIED, agent=None))          # no header: the bound agent applies
    assert _denied(_post(t, k, DENIED, agent="claude-code"))
    r = _post(t, k, DENIED, agent="no-profile-agent")         # the bypass: refused
    assert r.status_code == 403 and "bound to agent 'claude-code'" in r.text


def test_an_unbound_key_still_needs_an_agent_header(app):
    t = _tenant(app)
    assert _post(t, t.key(scope="runtime"), agent=None).status_code == 400


def test_agent_binding_needs_runtime_scope():
    from storage.tenant_store import add_api_key, create_tenant
    tid = "lk" + uuid.uuid4().hex[:10]
    create_tenant(tid, {"name": tid})
    for scope in (None, "admin"):
        with pytest.raises(ValueError, match="scope runtime"):
            add_api_key(tid, "sk-lk-" + uuid.uuid4().hex, scope=scope, agent="claude-code")
    with pytest.raises(ValueError, match="agent must be"):
        add_api_key(tid, "sk-lk-" + uuid.uuid4().hex, scope="runtime", agent="bad agent!")


def test_admin_and_self_service_routes_mint_bound_keys(app, monkeypatch):
    from storage.tenant_store import _hash_key, key_bound_agent_by_hash, key_scope
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin-lk")
    t = _tenant(app)
    k = "sk-lk-minted-" + uuid.uuid4().hex
    r = t.c.post(f"/v1/admin/tenants/{t.id}/api-keys", headers={"X-Admin-Key": "test-admin-lk"},
                 json={"api_key": k, "scope": "runtime", "agent": "claude-code"})
    assert r.status_code == 200, r.text
    assert key_scope(k) == "runtime" and key_bound_agent_by_hash(_hash_key(k)) == "claude-code"
    r = t.c.post(f"/v1/admin/tenants/{t.id}/api-keys", headers={"X-Admin-Key": "test-admin-lk"},
                 json={"api_key": "sk-lk-x-" + uuid.uuid4().hex, "scope": "admin",
                       "agent": "claude-code"})
    assert r.status_code == 400

    r = t.c.post("/v1/tenant/me/api-keys", headers={"X-API-Key": t.settings_key},
                 json={"label": "laptops", "agent": "claude-code"})
    assert r.status_code == 200, r.text
    minted = r.json()["api_key"]
    assert r.json()["scope"] == "runtime" and key_scope(minted) == "runtime"
    assert key_bound_agent_by_hash(_hash_key(minted)) == "claude-code"


# ── hooks.require_profile (F2) ───────────────────────────────────────


def test_no_profile_is_allowed_by_default(app):
    t = _tenant(app)
    assert _post(t, t.key(scope="runtime"), DENIED, agent="unprofiled").json() == {}


def test_require_profile_denies_an_agent_without_one(app):
    t = _tenant(app, config={"hooks": {"require_profile": True}})
    k = t.key(scope="runtime")
    r = _post(t, k, CALL, agent="unprofiled")
    assert _denied(r) and "has no runtime profile" in r.text
    prompt = _post(t, k, {"session_id": "s", "hook_event_name": "UserPromptSubmit",
                          "prompt": "hi"}, agent="unprofiled")
    assert prompt.json()["decision"] == "block"
    assert _post(t, k, CALL).json() == {}                   # an agent with a profile: unchanged


# ── coverage labels ──────────────────────────────────────────────────


def test_what_the_script_reports_is_kept_for_coverage(app):
    t = _tenant(app)
    _post(t, t.key(scope="runtime"), **{"X-Votal-Hook-Version": "1.2.0",
                                        "X-Votal-Hook-Mode": "managed", "X-Votal-Hook-OS": "darwin"})
    [row] = hook_seen.list_seen(t.id)
    assert (row["hook_version"], row["hook_mode"], row["hook_os"]) == ("1.2.0", "managed", "darwin")


def test_unexpected_labels_are_recorded_as_unknown(app):
    t = _tenant(app)
    r = _post(t, t.key(scope="runtime"), **{"X-Votal-Hook-Version": "1.2.0; rm -rf /",
                                            "X-Votal-Hook-Mode": "root", "X-Votal-Hook-OS": "beos"})
    assert r.status_code == 200
    [row] = hook_seen.list_seen(t.id)
    assert (row["hook_version"], row["hook_mode"], row["hook_os"]) == ("unknown",) * 3


def test_the_operator_sets_require_profile(app, monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin-lk")
    t = _tenant(app)
    k = t.key(scope="runtime")
    assert _post(t, k, CALL, agent="unprofiled").json() == {}
    r = t.c.put(f"/v1/admin/tenants/{t.id}", headers={"X-Admin-Key": "test-admin-lk"},
                json={"hooks": {"require_profile": True}})
    assert r.status_code == 200, r.text
    assert _denied(_post(t, k, CALL, agent="unprofiled"))
    bad = t.c.put(f"/v1/admin/tenants/{t.id}", headers={"X-Admin-Key": "test-admin-lk"},
                  json={"hooks": {"require_profile": True, "typo": 1}})
    assert bad.status_code == 422
