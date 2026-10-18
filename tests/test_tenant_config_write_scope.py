"""Authorization for tenant configuration, path-tenant routes and approvals.
Spec: docs/specs/tenant-config-write-scope.md.

A: PUT /v1/shield/config changed the process-wide guardrail and RBAC config
   with no check at all.
B: verify_tenant_path_access read "no tenant on request.state" as "master
   key", so a caller with no credentials could act on any tenant's policies,
   webhooks and decision audit.
"""

import logging
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = "tcws-root-admin-key"
A_KEY, B_KEY = "sk-tcws-tenant-a-0001", "sk-tcws-tenant-b-0001"
PROBE = "tcws_probe_guardrail"
# Made up per run: keys no tenant holds (literal key strings in headers read as
# leaked secrets to secret scanners).
UNKNOWN_KEY = "sk-unknown-" + uuid.uuid4().hex
MASTER_KEY = "sk-master-" + uuid.uuid4().hex


@pytest.fixture
def env(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_GLOBAL_CONFIG_OPEN", "SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_CONFIG_WRITE_SCOPE",
                 "SHIELD_APPROVALS_TENANT_KEY", "SHIELD_ADMIN_CREDENTIALS", "REDIS_URL",
                 "UPSTASH_REDIS_REST_URL", "CONFIG_PATH"):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts.create_tenant("ta", {"name": "A"}, api_keys=[A_KEY])
    ts.create_tenant("tb", {"name": "B"}, api_keys=[B_KEY])
    yield ts
    ts._fallback_store.clear()


@pytest.fixture
def app(env):
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield application
    if cs.config is not None:
        cs.config.guardrails.pop(PROBE, None)
    cs.config = original


@pytest.fixture
def client(app):
    return TestClient(app)


def managed(scope=None):
    from storage.admin_credentials import create_credential
    secret, rec = create_credential("partner", scope=scope)
    return {"X-Admin-Key": secret}, rec["id"]


def probe_enabled():
    import config.schema as cs
    g = cs.config.guardrails.get(PROBE)
    return None if g is None else g.enabled


def put_config(client, headers=None):
    return client.put("/v1/shield/config", headers=headers or {},
                      json={"guardrails": {PROBE: {"enabled": False}}})


# ── A: the global config ─────────────────────────────────────────────


def test_no_credentials_cannot_change_the_global_config(client):
    assert put_config(client).status_code == 401
    assert probe_enabled() is None


def test_a_tenant_key_cannot_change_the_global_config(client):
    assert put_config(client, {"X-API-Key": A_KEY}).status_code == 403
    assert probe_enabled() is None


def test_the_root_key_and_a_full_admin_credential_can(client):
    assert put_config(client, {"X-Admin-Key": ROOT}).status_code == 200
    assert probe_enabled() is False
    import config.schema as cs
    cs.config.guardrails.pop(PROBE)
    h, _ = managed()
    assert put_config(client, h).status_code == 200


def test_a_tenant_restricted_admin_credential_cannot(client):
    h, _ = managed({"operations": ["tenants:write"], "tenants": ["ta"]})
    assert put_config(client, h).status_code == 403
    assert probe_enabled() is None


def test_the_change_is_audited_with_the_actor(client, monkeypatch):
    rows = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: rows.append(k))
    h, cid = managed()
    put_config(client, h)
    assert rows and rows[-1]["action"] == "global_config_updated"
    assert rows[-1]["actor"] == f"adminkey:{cid}"


def test_the_escape_hatch_still_needs_a_credential(client, monkeypatch, caplog):
    import api.routes_config as rc
    monkeypatch.setenv("SHIELD_GLOBAL_CONFIG_OPEN", "true")
    monkeypatch.setattr(rc, "_warned_open", False)
    assert put_config(client).status_code == 401
    assert probe_enabled() is None
    with caplog.at_level(logging.WARNING, logger="votal.config_routes"):
        assert put_config(client, {"X-API-Key": A_KEY}).status_code == 200
    assert any("SHIELD_GLOBAL_CONFIG_OPEN" in r.getMessage() for r in caplog.records)


# ── B: path-tenant routes ────────────────────────────────────────────

POLICY = {"policy_id": "p1", "name": "x", "roles": {},
          "patterns": [{"regex": "x", "type": "pii", "sensitivity": "low"}]}
HOOK = {"url": "https://hooks.example.com/shield", "events": ["tool_disabled"]}


def webhooks(t):
    from storage.webhook_store import get_webhooks
    return get_webhooks(t)


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/v1/shield/policies/tb", None),
    ("POST", "/v1/shield/policies/tb", POLICY),
    ("GET", "/v1/shield/webhooks/tb", None),
    ("POST", "/v1/shield/webhooks/tb", HOOK),
    ("GET", "/v1/shield/decisions/tb", None),
])
@pytest.mark.parametrize("headers", [{}, {"X-API-Key": UNKNOWN_KEY}], ids=["none", "unknown"])
def test_a_caller_with_no_tenant_is_refused(client, method, path, body, headers):
    r = client.request(method, path, json=body, headers=headers)
    assert r.status_code == 401, (path, r.status_code, r.text[:200])
    assert webhooks("tb") == []


def test_own_tenant_works_and_another_tenant_is_403(client):
    assert client.post("/v1/shield/webhooks/ta", json=HOOK, headers={"X-API-Key": A_KEY}).status_code == 200
    assert client.post("/v1/shield/webhooks/tb", json=HOOK, headers={"X-API-Key": A_KEY}).status_code == 403
    assert client.get("/v1/shield/decisions/tb", headers={"X-API-Key": A_KEY}).status_code == 403
    assert len(webhooks("ta")) == 1 and webhooks("tb") == []


def test_admin_callers_act_for_any_tenant_within_their_scope(client):
    assert client.get("/v1/shield/policies/tb", headers={"X-Admin-Key": ROOT}).status_code == 200
    h, _ = managed({"operations": ["tenants:read", "tenants:write"], "tenants": ["ta"]})
    assert client.get("/v1/shield/policies/ta", headers=h).status_code == 200
    assert client.get("/v1/shield/policies/tb", headers=h).status_code == 403
    reader, _ = managed({"operations": ["tenants:read"]})
    assert client.get("/v1/shield/webhooks/tb", headers=reader).status_code == 200
    assert client.post("/v1/shield/webhooks/tb", json=HOOK, headers=reader).status_code == 403
    assert webhooks("tb") == []


def test_a_global_master_key_is_an_admin_caller(client):
    import config.schema as cs
    cs.config.auth.api_keys = [MASTER_KEY]
    try:
        r = client.get("/v1/shield/decisions/tb", headers={"X-API-Key": MASTER_KEY})
        assert r.status_code == 200
    finally:
        cs.config.auth.api_keys = []


# ── C: approvals ─────────────────────────────────────────────────────
#
# A runtime key could approve the request its own agent raised and receive the
# signed grant that satisfies the approval rule, and X-Approver-Sub from any
# caller was recorded as an SSO-verified approver.

RUNTIME, UNSCOPED, ADMIN_SCOPED = "sk-tcws-a-runtime-01", "sk-tcws-a-unscoped-1", "sk-tcws-a-admin-0001"
PROXY_SECRET = "tcws-proxy-secret"


@pytest.fixture
def approvals(env, monkeypatch):
    from core import approvals as ap
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "5c" * 32)
    ap.reset_signer_cache_for_tests()
    env.add_api_key("ta", RUNTIME, scope="runtime")
    env.add_api_key("ta", UNSCOPED)
    env.add_api_key("ta", ADMIN_SCOPED, scope="admin")
    yield ap
    ap.reset_signer_cache_for_tests()


def pending(min_approvals=1):
    from storage.agentic_control_plane import create_approval_request
    return create_approval_request("ta", agent_key="billing-bot", tool_name="refund", session_id="s1",
                                   workflow="default", tool_params={"amount": 900},
                                   rule={"min_approvals": min_approvals})["request_id"]


def status(rid):
    from storage.agentic_control_plane import list_approval_requests
    return next(r for r in list_approval_requests("ta") if r["request_id"] == rid)


def decide(client, rid, headers, decision="approve", approver="cfo@acme.example"):
    return client.post(f"/v1/tenant/me/agentic/approvals/{rid}/{decision}", headers=headers,
                       json={"approver": approver, "reason": "test"})


@pytest.mark.parametrize("mode", ["off", "warn", "enforce"])
@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_an_agents_key_cannot_decide_an_approval_in_any_mode(client, approvals, monkeypatch, mode, decision):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", mode)
    for key in (RUNTIME, UNSCOPED):
        rid = pending()
        r = decide(client, rid, {"X-API-Key": key}, decision)
        assert r.status_code == 403, (key, r.text)
        assert status(rid)["status"] == "pending" and not status(rid).get("approval_grant")


def test_an_admin_scoped_key_decides_and_is_recorded_as_admin(client, approvals):
    rid = pending()
    r = decide(client, rid, {"X-API-Key": ADMIN_SCOPED})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    claims = approvals.verify_grant(r.json()["approval_grant"], expected_tool="refund",
                                    expected_params_hash=approvals.params_hash({"amount": 900}),
                                    expected_session="s1")
    assert claims.approvers == [{"sub": "cfo@acme.example", "method": "admin", "at": claims.approvers[0]["at"]}]


def test_a_signed_in_person_is_the_approver_whatever_the_body_says(client, approvals, monkeypatch):
    person = {"kind": "user", "tenant_id": "ta", "sub": "u-77", "email": "dana@acme.example", "is_admin": False}
    monkeypatch.setattr("core.auth.portal_principal", lambda r: person)
    rid = pending()
    r = decide(client, rid, {"X-API-Key": UNSCOPED}, approver="someone-else@acme.example")
    assert r.status_code == 200
    assert status(rid)["approvals"][0]["approver"] == "dana@acme.example"
    assert status(rid)["approvals"][0]["method"] == "portal_session"


def test_x_approver_sub_counts_only_from_the_trusted_proxy(client, approvals, monkeypatch):
    rid = pending()
    r = decide(client, rid, {"X-API-Key": ADMIN_SCOPED, "X-Approver-Sub": "ceo@acme.example"})
    assert r.status_code == 200
    assert status(rid)["approvals"][0] == {**status(rid)["approvals"][0],
                                           "approver": "cfo@acme.example", "method": "admin"}
    rid = pending()
    r = decide(client, rid, {"X-API-Key": RUNTIME, "X-Approver-Sub": "ceo@acme.example"})
    assert r.status_code == 403                                  # the header grants nothing
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", PROXY_SECRET)
    r = decide(client, rid, {"X-API-Key": RUNTIME, "X-Approver-Sub": "ceo@acme.example",
                             "X-Shield-Proxy-Token": PROXY_SECRET})
    assert r.status_code == 200
    assert status(rid)["approvals"][0]["approver"] == "ceo@acme.example"
    assert status(rid)["approvals"][0]["method"] == "sso"


def test_two_approvals_need_two_people(client, approvals):
    rid = pending(min_approvals=2)
    assert decide(client, rid, {"X-API-Key": ADMIN_SCOPED}).json()["status"] == "pending"
    assert decide(client, rid, {"X-API-Key": ADMIN_SCOPED}).json()["status"] == "pending"
    assert len(status(rid)["approvals"]) == 1
    r = decide(client, rid, {"X-API-Key": ADMIN_SCOPED}, approver="ciso@acme.example")
    assert r.json()["status"] == "approved" and r.json().get("approval_grant")


def test_the_hatch_lets_an_unscoped_key_decide_but_never_a_runtime_key(client, approvals, monkeypatch, caplog):
    import api.routes_agentic_control_plane as cp
    monkeypatch.setenv("SHIELD_APPROVALS_TENANT_KEY", "true")
    monkeypatch.setattr(cp, "_warned_hatch", False)
    rid = pending()
    with caplog.at_level(logging.WARNING, logger="votal.agentic_control_plane"):
        assert decide(client, rid, {"X-API-Key": UNSCOPED}).status_code == 200
    assert status(rid)["approvals"][0]["method"] == "asserted"
    assert any("SHIELD_APPROVALS_TENANT_KEY" in r.getMessage() for r in caplog.records)
    assert decide(client, pending(), {"X-API-Key": RUNTIME}).status_code == 403


def test_the_root_admin_key_decides(client, approvals):
    rid = pending()
    assert decide(client, rid, {"X-API-Key": RUNTIME, "X-Admin-Key": ROOT}).status_code == 200
    assert status(rid)["approvals"][0]["method"] == "admin"


# ── D: the configuration write gate ──────────────────────────────────
#
# Under enforce, a runtime key could still change the tenant's configuration.
# The gate runs before anything is changed; requests here carry no body, so a
# refusal is the gate's (FastAPI would 422 a bad body before any handler).

ONE_PER_GROUP = [   # (plane, method, path) - one body-less write per group of the spec
    ("data", "DELETE", "/v1/tenant/me/custom-policies/cp-1"),
    ("data", "POST", "/v1/tenant/me/policies/custom/cp-1/disable"),
    ("data", "DELETE", "/v1/data-policies/global/policy"),
    ("data", "DELETE", "/v1/agents/tools/policies/refund"),
    ("data", "POST", "/v1/agents/unregistered/stray-bot/block"),
    ("data", "POST", "/v1/tenant/me/agentic/circuit-breakers/refund/reset"),
    ("data", "DELETE", "/v1/tenant/me/mcp-gateway/upstreams/github"),
    ("data", "DELETE", "/v1/shield/webhooks/ta/wh-1"),
    ("data", "DELETE", "/v1/shield/policies/ta/p-1"),
    ("data", "POST", "/v1/governance/reviews/rev-1/close"),
    ("admin", "DELETE", "/v1/tenant/me/mcp/servers/github"),
    ("admin", "DELETE", "/v1/tenant/me/vault/ref-1"),
    ("admin", "DELETE", "/v1/tenant/me/siem/siem-1"),
    ("admin", "DELETE", "/v1/tenant/me/aibom/components/models/m-1"),
]


@pytest.fixture
def planes(app, approvals):
    import admin_app
    return {"data": TestClient(app), "admin": TestClient(admin_app.app)}


@pytest.mark.parametrize("plane,method,path", ONE_PER_GROUP)
def test_enforce_refuses_a_runtime_key_on_configuration_writes(planes, monkeypatch, plane, method, path):
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    r = planes[plane].request(method, path, headers={"X-API-Key": RUNTIME})
    assert r.status_code == 403, (path, r.status_code, r.text[:200])
    assert "SHIELD_CONFIG_WRITE_SCOPE" in r.text


@pytest.mark.parametrize("plane,method,path", ONE_PER_GROUP)
def test_enforce_lets_an_admin_scoped_key_through(planes, monkeypatch, plane, method, path):
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    r = planes[plane].request(method, path, headers={"X-API-Key": ADMIN_SCOPED})
    assert r.status_code != 403, (path, r.status_code, r.text[:200])


@pytest.mark.parametrize("plane,method,path", ONE_PER_GROUP)
def test_off_is_unchanged_and_warn_records(planes, monkeypatch, plane, method, path):
    assert planes[plane].request(method, path, headers={"X-API-Key": RUNTIME}).status_code != 403
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "warn")
    warned = []
    monkeypatch.setattr("core.auth._record_config_warning",
                        lambda req, tenant, scope, action: warned.append((tenant, scope)))
    assert planes[plane].request(method, path, headers={"X-API-Key": RUNTIME}).status_code != 403
    assert warned == [("ta", "runtime")], (path, warned)


def test_a_change_really_is_refused(planes, monkeypatch):
    """End to end on one write with a body: the tenant's tools stay as they were."""
    from storage.tenant_store import get_tenant
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    before = (get_tenant("ta") or {}).get("tools")
    r = planes["data"].put("/v1/tenant/me/tools", headers={"X-API-Key": RUNTIME}, json={"tools": []})
    assert r.status_code == 403 and (get_tenant("ta") or {}).get("tools") == before


@pytest.mark.parametrize("registry,config,expected", [
    ("", "", "off"), ("off", "", "off"), ("warn", "", "warn"), ("enforce", "", "warn"),
    ("enforce", "enforce", "enforce"), ("off", "enforce", "enforce"), ("enforce", "off", "off"),
    ("off", "enforced", "off"),
])
def test_the_mode_follows_the_registry_mode_capped_at_warn(monkeypatch, registry, config, expected):
    from core.auth import config_write_mode
    for name, value in (("SHIELD_REGISTRY_WRITE_SCOPE", registry), ("SHIELD_CONFIG_WRITE_SCOPE", config)):
        if value:
            monkeypatch.setenv(name, value)
        else:
            monkeypatch.delenv(name, raising=False)
    assert config_write_mode() == expected


def test_admin_callers_and_portal_administrators_pass_the_gate(planes, monkeypatch):
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    assert planes["data"].delete("/v1/shield/webhooks/tb/wh-1", headers={"X-Admin-Key": ROOT}).status_code != 403
    admin = {"kind": "user", "tenant_id": "ta", "sub": "u1", "email": "a@acme.example", "is_admin": True}
    monkeypatch.setattr("core.auth.portal_principal", lambda r: admin)
    assert planes["data"].delete("/v1/data-policies/global/policy",
                                 headers={"X-API-Key": RUNTIME}).status_code != 403


def test_validators_stay_open_to_a_runtime_key(planes, monkeypatch):
    monkeypatch.setenv("SHIELD_CONFIG_WRITE_SCOPE", "enforce")
    r = planes["data"].post("/v1/tenant/me/custom-policies/validate-sigma", headers={"X-API-Key": RUNTIME},
                            json={"rule": "title: x"})
    assert r.status_code != 403


def test_the_global_mcp_registry_is_admin_only(planes):
    body = {"name": "srv", "url": "https://mcp.example.com", "tools": ["t"], "trust_score": 1.0}
    assert planes["data"].post("/v1/shield/mcp/register", json=body).status_code == 401
    assert planes["data"].post("/v1/shield/mcp/register", json=body,
                               headers={"X-API-Key": ADMIN_SCOPED}).status_code == 403
    assert planes["data"].post("/v1/shield/mcp/register", json=body,
                               headers={"X-Admin-Key": ROOT}).status_code == 200


# ── task 4: every write route is classified ──────────────────────────
#
# Each POST/PUT/PATCH/DELETE on either app (outside /v1/admin, which has its
# own guard) must reach an authorization gate, or be listed here with the
# reason a runtime key must be able to call it. A new route fails this test
# until someone decides which it is.

GATES = ("require_registry_write(", "require_config_write(", "require_admin_caller(",
         "require_admin_scope(", "require_admin_root_or_operator(", "authorized_tenant_scope(",
         "_decider(", "_authorize_global_write(")

OPEN_BY_DESIGN = {
    "guard and decision checks (what an agent calls to be guarded)": {
        ("POST", "/guardrails/input"), ("POST", "/guardrails/output"), ("POST", "/guardrails/file"),
        ("POST", "/v1/shield/tool/check"), ("POST", "/v1/shield/tool/output"), ("POST", "/v1/shield/tool/confirm"),
        ("POST", "/v1/shield/action/check"), ("POST", "/v1/shield/agent/check"), ("POST", "/v1/shield/agent/budget"),
        ("POST", "/v1/shield/agent/goal"), ("POST", "/v1/shield/topic/check"), ("POST", "/v1/shield/memory/check"),
        ("POST", "/v1/shield/memory/cleanup"), ("POST", "/v1/shield/embodied/check"), ("POST", "/v1/shield/mcp/check"),
        ("POST", "/v1/shield/runtime/check"), ("POST", "/v1/shield/runtime/ext-authz/{path:path}"),
        ("PUT", "/v1/shield/runtime/ext-authz/{path:path}"), ("PATCH", "/v1/shield/runtime/ext-authz/{path:path}"),
        ("DELETE", "/v1/shield/runtime/ext-authz/{path:path}"), ("POST", "/v1/shield/hooks/claude-code"),
        ("POST", "/v1/shield/hooks/codex"), ("POST", "/beta/litellm_basic_guardrail_api"),
        ("POST", "/v1/agents/authorize"), ("POST", "/api/rbac/test-tool"),
    },
    "guarded traffic (chat, MCP, A2A)": {
        ("POST", "/v1/shield/chat/completions"), ("POST", "/v1/chat/completions"), ("POST", "/v1/shield/chat/agent"),
        ("POST", "/a2a/tasks/send"), ("POST", "/a2a/tasks/{task_id}/cancel"), ("POST", "/mcp/message"),
        ("POST", "/mcp/sse/{session_id}/message"), ("POST", "/gateway/{route}/mcp"),
        ("POST", "/gateway/t/{tenant}/{route}/mcp"), ("POST", "/v1/openapi/call"),
    },
    "credentials an agent obtains, and admin-gated in the handler": {
        ("POST", "/v1/shield/cap/mint"), ("POST", "/v1/shield/cap/verify"), ("POST", "/v1/shield/auth/agent-token"),
        ("POST", "/v1/tenant/me/agent-auth/agent-token"), ("POST", "/v1/shield/auth/revoke"),
        ("POST", "/v1/shield/breakglass"),
    },
    "sign-in, OAuth and device enrollment flows": {
        ("POST", "/oauth/token"), ("POST", "/oauth/revoke"), ("POST", "/oauth/register"), ("POST", "/oauth/consent"),
        ("POST", "/connect/{tenant_id}/{route}/start"), ("POST", "/connect/{tenant_id}/{route}/disconnect"),
        ("POST", "/v1/tenant/auth/logout"), ("POST", "/verify-captcha"), ("POST", "/v1/devices/enroll"),
        ("POST", "/v1/devices/heartbeat"), ("POST", "/v1/devices/ca"),
    },
    "telemetry the agent or its runtime reports": {
        ("POST", "/v1/tenant/me/audit"), ("POST", "/v1/tenant/me/siem/ingest"), ("POST", "/v1/shield/ssf/events"),
        ("POST", "/v1/shield/runtime/events"), ("POST", "/v1/tenant/me/agentic/circuit-breakers/report"),
        ("POST", "/v1/tenant/me/agentic/checkpoints"), ("POST", "/v1/tenant/me/aibom/ingest"),
        ("POST", "/v1/tenant/me/aibom/snapshots"), ("POST", "/v1/shield/exceptions"),
    },
    "validators, simulators and generators (change nothing)": {
        ("POST", "/v1/tenant/me/custom-policies/validate-prompt"), ("POST", "/v1/tenant/me/custom-policies/validate-sigma"),
        ("POST", "/v1/tenant/me/policies/custom/validate"), ("POST", "/v1/tenant/me/policies/custom/validate-sigma"),
        ("POST", "/v1/data-policies/exact-match/hash"), ("POST", "/v1/data-policies/preview-sanitization"),
        ("POST", "/v1/data-policies/try"), ("POST", "/v1/data-policies/validate"),
        ("POST", "/v1/tenant/me/dlp-policy/validate"), ("POST", "/v1/tenant/me/embodied-profiles/validate"),
        ("POST", "/v1/tenant/me/embodied-profiles/{name}/simulate"), ("POST", "/v1/tenant/me/flow-control/simulate"),
        ("POST", "/v1/tenant/me/flow-control/validate"), ("POST", "/v1/tenant/me/runtime-profiles/validate"),
        ("POST", "/v1/tenant/me/agent-identity/test"), ("POST", "/v1/shield/policies/test"),
        ("POST", "/v1/tenant/me/siem/test"), ("POST", "/v1/openapi/generate"),
        ("POST", "/v1/tenant/me/compliance/evidence-pack"), ("POST", "/v1/tenant/me/hooks/claude-code/kit"),
    },
    "local tools with their own checks": {
        ("POST", "/playground/llm-proxy"), ("POST", "/playground/proxy/{path:path}"),
        ("POST", "/v1/agents/seed-test-data"),   # refused in production and under enforce
    },
}


def test_every_write_route_is_gated_or_open_by_design():
    from tests.test_principals_template_authz import _apps, _reaches, _routes
    allowed = set().union(*OPEN_BY_DESIGN.values())
    seen, unclassified = set(), []
    for plane, app in _apps().items():
        for m, path, ep in _routes(app):
            if m not in ("POST", "PUT", "PATCH", "DELETE") or path.startswith("/v1/admin/"):
                continue
            seen.add((m, path))
            if (m, path) in allowed or _reaches(ep, GATES):
                continue
            unclassified.append((plane, m, path, ep.__module__))
    assert len(seen) > 150, len(seen)                  # the walk saw the real tables
    assert not unclassified, (
        "write route(s) with no authorization gate and no reason to be open: "
        f"{sorted(set(unclassified))}. Gate them (require_config_write, ...) or add them to "
        "OPEN_BY_DESIGN with the reason.")
    stale = allowed - seen
    assert not stale, f"OPEN_BY_DESIGN lists routes that no longer exist: {sorted(stale)}"
