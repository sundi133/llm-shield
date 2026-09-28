"""Cross-app flow control, end to end on every guard path.

/v1/shield/tool/check and /tool/output run through the real app (auth
middleware, agent registry, RBAC) with a real tenant and API key. MCP
tools/call goes through core.mcp.enforcement; cap/mint through the route
function with a verified identity. Redis is off: the in-process fallbacks
carry the same key shapes. Spec: docs/specs/cross-app-flow-control.md.
"""

import asyncio
import copy
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import core.approvals as ap
from core.models import GuardrailResult
from core.xflow import runtime as xflow
from core.xflow import state as xflow_state
from core.xflow.policy import starter_policy

TOOLS = ["drive_read_file", "github_create_repo", "salesforce_get_account", "gmail_send",
         "slack_post_message", "read_file", "calculator_add"]


def _policy(**over):
    p = starter_policy()
    p["mode"] = "enforce"
    p.update(over)
    return p


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "57" * 32)
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_KID", "approval-xflow-test")
    monkeypatch.setenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", "68" * 32)
    monkeypatch.delenv("SHIELD_XFLOW", raising=False)
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()
    xflow.invalidate()
    xflow_state.reset_memory()
    xflow_state._mem_policies.clear()
    yield
    xflow.invalidate()
    xflow_state.reset_memory()
    xflow_state._mem_policies.clear()
    ap.reset_signer_cache_for_tests()
    ap.clear_nonce_store_for_tests()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _make_tenant(app, *, policy=None, config=None, agent="research-bot"):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "xf" + uuid.uuid4().hex[:10]
    key = "sk-xf-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise", "input_guardrails": {},
                        "output_guardrails": {}, **(config or {})}, api_keys=[key])
    client = TestClient(app)
    headers = {"X-API-Key": key, "X-User-Role": "analyst"}
    r = client.post("/v1/agents/registry", headers=headers,
                    json={"agent_id": agent, "tools": TOOLS, "role_permissions": {"analyst": TOOLS}})
    assert r.status_code == 200, r.text
    if policy is not None:
        r = client.put("/v1/tenant/me/flow-control/policy", headers=headers, json=policy)
        assert r.status_code == 200, r.text
    return SimpleNamespace(id=tid, client=client, headers=headers)


def _check(t, tool, params=None, session="s1", **extra):
    body = {"agent_key": "research-bot", "tool_name": tool, "tool_params": params or {},
            "session_id": session, "user_role": "analyst", **extra}
    r = t.client.post("/v1/shield/tool/check", headers=t.headers, json=body)
    assert r.status_code == 200, r.text
    d = r.json()
    d["flow"] = next((g for g in d["guardrail_results"] if g["guardrail"] == "cross_app_flow"), None)
    return d


# ── /v1/shield/tool/check ────────────────────────────────────────────


def test_no_policy_means_no_flow_result_and_no_state_io(app):
    t = _make_tenant(app)

    def boom(*a, **k):
        raise AssertionError("flow state touched for a tenant without a policy")

    with patch.object(xflow_state, "read", boom), patch.object(xflow_state, "write", boom):
        assert _check(t, "drive_read_file")["allowed"] is True
        d = _check(t, "github_create_repo", {"private": False})
    assert d["allowed"] is True and d["flow"] is None


def test_confidential_read_then_public_repo_is_blocked(app):
    t = _make_tenant(app, policy=_policy())
    assert _check(t, "drive_read_file", {"file_id": "contract-9281"})["allowed"] is True

    d = _check(t, "github_create_repo", {"name": "dump", "private": False})
    assert d["allowed"] is False and d["action"] == "block"
    assert d["flow"]["passed"] is False
    v = d["flow"]["details"]["flow_violations"][0]
    assert v["rule_id"] == "confidential-to-public"
    assert v["sources"][0]["tool"] == "drive_read_file"
    assert v["sources"][0]["evidence"] == "authorized"
    assert "drive_read_file" in d["flow"]["details"]["lineage"][0]

    # Omitting private: GitHub's default is public, so still blocked.
    assert _check(t, "github_create_repo", {"name": "dump"})["allowed"] is False
    # A private repo is fine, and so is a session that never read Drive.
    assert _check(t, "github_create_repo", {"name": "dump", "private": True})["allowed"] is True
    fresh = _check(t, "github_create_repo", {"name": "dump", "private": False}, session="s2")
    assert fresh["allowed"] is True and fresh["flow"]["action"] == "pass"


def test_calls_outside_every_rule_destination_add_nothing(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "drive_read_file")
    d = _check(t, "calculator_add", {"a": 1})
    assert d["allowed"] is True and d["flow"] is None


def test_warn_is_allowed_and_reported(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "drive_read_file")
    d = _check(t, "slack_post_message", {"channel": "general", "text": "summary"})
    assert d["allowed"] is True and d["action"] == "warn"
    assert d["flow"]["action"] == "warn"


def test_guardrails_subset_cannot_skip_flow_control(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "drive_read_file")
    d = _check(t, "github_create_repo", {"private": False}, guardrails=["rbac_guard"])
    assert d["allowed"] is False and d["flow"]["action"] == "block"


def test_session_lineage_endpoint(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "drive_read_file", tool_call_id="tc_1", input_sources=["tc_0"])
    _check(t, "salesforce_get_account", {"id": "1"})
    r = t.client.get("/v1/tenant/me/flow-control/sessions/s1", headers=t.headers)
    assert r.status_code == 200
    recs = r.json()["records"]
    assert [x["tool"] for x in recs] == ["drive_read_file", "salesforce_get_account"]
    assert recs[0]["tool_call_id"] == "tc_1" and recs[0]["input_sources"] == ["tc_0"]
    assert all(x["tool"] != "salesforce_update" for x in recs)
    # Clearing the session lifts the rule for it.
    assert t.client.delete("/v1/tenant/me/flow-control/sessions/s1", headers=t.headers).status_code == 200
    assert _check(t, "github_create_repo", {"private": False})["allowed"] is True


def test_tenants_are_isolated(app):
    a = _make_tenant(app, policy=_policy())
    b = _make_tenant(app, policy=_policy())
    _check(a, "drive_read_file", session="shared-id")
    assert _check(b, "github_create_repo", {"private": False}, session="shared-id")["allowed"] is True
    assert _check(a, "github_create_repo", {"private": False}, session="shared-id")["allowed"] is False


def test_policy_monitor_mode_reports_without_blocking(app):
    t = _make_tenant(app, policy=_policy(mode="monitor"))
    _check(t, "drive_read_file")
    d = _check(t, "github_create_repo", {"private": False})
    assert d["allowed"] is True
    assert d["flow"]["action"] == "log" and d["flow"]["message"].startswith("[monitor] would block")


def test_escape_hatch_disables_everything(app, monkeypatch):
    t = _make_tenant(app, policy=_policy())
    monkeypatch.setenv("SHIELD_XFLOW", "off")
    xflow.invalidate()
    _check(t, "drive_read_file")
    d = _check(t, "github_create_repo", {"private": False})
    assert d["allowed"] is True and d["flow"] is None


def test_state_unavailable_fails_open_by_default_and_closed_when_configured(app):
    def down(*a, **k):
        raise ConnectionError("redis down")

    t = _make_tenant(app, policy=_policy())
    with patch.object(xflow_state, "read", down):
        d = _check(t, "github_create_repo", {"private": False})
    assert d["allowed"] is True and d["flow"]["passed"] is True
    assert d["flow"]["details"]["advisory"] is True

    t = _make_tenant(app, policy=_policy(fail_closed=True))
    with patch.object(xflow_state, "read", down):
        d = _check(t, "github_create_repo", {"private": False})
    assert d["allowed"] is False and "fail-closed" in d["flow"]["message"]
    # Only destination-matched calls read state: an internal call is untouched.
    with patch.object(xflow_state, "read", down):
        assert _check(t, "calculator_add")["allowed"] is True


def test_route_places_an_mcp_tool_in_an_app(app):
    p = _policy()
    p["apps"]["google_drive"]["routes"] = ["drive-mcp"]
    t = _make_tenant(app, policy=p)
    _check(t, "read_file", {"path": "/contracts/9281.pdf"}, route="drive-mcp")
    assert _check(t, "github_create_repo", {"private": False})["allowed"] is False


def test_principal_scope_agent_catches_session_rotation(app):
    t = _make_tenant(app, policy=_policy(principal_scope="agent"))
    _check(t, "drive_read_file", session="s1")
    d = _check(t, "github_create_repo", {"private": False}, session="s-rotated")
    assert d["allowed"] is False
    assert d["flow"]["details"]["flow_violations"][0]["sources"][0]["scope"] == "principal"
    # Default agent_user scope with no verified user: session only, by design.
    t2 = _make_tenant(app, policy=_policy())
    _check(t2, "drive_read_file", session="s1")
    assert _check(t2, "github_create_repo", {"private": False}, session="s-rotated")["allowed"] is True


# ── approvals on /tool/check ─────────────────────────────────────────


def _approve(t, request_id):
    r = t.client.post(f"/v1/tenant/me/agentic/approvals/{request_id}/approve",
                      headers=t.headers, json={"approver": "carol@corp.com", "reason": "ok"})
    assert r.status_code == 200, r.text
    return r.json()


def test_require_approval_full_cycle_with_signed_grant(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "salesforce_get_account", {"id": "1"})
    mail = {"to": "buyer@partner.com", "body": "Q3 numbers"}

    held = _check(t, "gmail_send", mail)
    assert held["allowed"] is False and held["action"] == "pending_confirmation"
    rid = held["flow"]["details"]["request_id"]
    # A retry before approval reuses the same request instead of opening another.
    assert _check(t, "gmail_send", mail)["flow"]["details"]["request_id"] == rid

    grant = _approve(t, rid)["approval_grant"]
    ok = _check(t, "gmail_send", mail, approval_grant=grant)
    assert ok["allowed"] is True
    assert ok["flow"]["details"]["approval"]["via"] == "approval_grant"
    # Single use: replaying the grant is refused.
    replay = _check(t, "gmail_send", mail, approval_grant=grant)
    assert replay["allowed"] is False and "rejected" in replay["flow"]["message"]


def test_grant_does_not_cover_different_arguments(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "salesforce_get_account", {"id": "1"})
    held = _check(t, "gmail_send", {"to": "buyer@partner.com", "body": "Q3"})
    grant = _approve(t, held["flow"]["details"]["request_id"])["approval_grant"]
    d = _check(t, "gmail_send", {"to": "buyer@partner.com", "body": "ALL CUSTOMERS"},
               approval_grant=grant)
    assert d["allowed"] is False and "params" in d["flow"]["message"]


def test_approval_request_id_path_binds_arguments(app):
    t = _make_tenant(app, policy=_policy())
    _check(t, "salesforce_get_account", {"id": "1"})
    mail = {"to": "buyer@partner.com", "body": "Q3"}
    rid = _check(t, "gmail_send", mail)["flow"]["details"]["request_id"]
    _approve(t, rid)
    changed = _check(t, "gmail_send", {**mail, "body": "everything"}, approval_request_id=rid)
    assert changed["allowed"] is False and "arguments changed" in changed["flow"]["message"]
    assert _check(t, "gmail_send", mail, approval_request_id=rid)["allowed"] is True
    again = _check(t, "gmail_send", mail, approval_request_id=rid)
    assert again["allowed"] is False     # consumed


def test_tenant_monitor_mode_opens_no_approval_request(app):
    from storage.agentic_control_plane import list_approval_requests

    t = _make_tenant(app, policy=_policy(), config={"policy_mode": "monitor"})
    _check(t, "salesforce_get_account", {"id": "1"})
    d = _check(t, "gmail_send", {"to": "buyer@partner.com"})
    assert d["allowed"] is True and "cross_app_flow" in d["would_block"]
    assert list_approval_requests(t.id) == []


# ── /v1/shield/tool/output ───────────────────────────────────────────


def _dlp_result(tags_from: str):
    return GuardrailResult(
        passed=False, action="redact", guardrail_name="tool_output_sanitization",
        message="redacted", details={"floor_violations": [{"pattern_id": tags_from}],
                                     "sanitized_output": "[REDACTED]"})


def test_tool_output_records_detected_tags(app):
    import api.routes_tool as rt

    t = _make_tenant(app, policy=_policy())

    async def fake_check(self, content, context=None):
        return _dlp_result("us_ssn")

    with patch.object(rt.ToolOutputSanitizationGuardrail, "check", fake_check):
        r = t.client.post("/v1/shield/tool/output", headers=t.headers, json={
            "tool_name": "crm_lookup", "tool_output": "SSN 123-45-6789",
            "agent_key": "research-bot", "session_id": "s1"})
    assert r.status_code == 200, r.text
    recs = xflow_state.read_session(t.id, "s1")
    assert recs[0]["tags"] == ["PII", "SSN"] and recs[0]["evidence"] == "observed"
    assert recs[0]["tool_call_id"] == r.json()["tool_call_id"]

    d = _check(t, "gmail_send", {"to": "someone@partner.com"})
    assert d["allowed"] is False
    assert d["flow"]["details"]["flow_violations"][0]["rule_id"] == "regulated-pii-anywhere-out"


def test_clean_tool_output_of_a_classified_app_is_recorded(app):
    import api.routes_tool as rt

    t = _make_tenant(app, policy=_policy())

    async def clean(self, content, context=None):
        return GuardrailResult(passed=True, action="pass", guardrail_name="tool_output_sanitization",
                               message="clean", details={})

    with patch.object(rt.ToolOutputSanitizationGuardrail, "check", clean):
        t.client.post("/v1/shield/tool/output", headers=t.headers, json={
            "tool_name": "drive_read_file", "tool_output": "contract text",
            "agent_key": "research-bot", "session_id": "s7"})
    recs = xflow_state.read_session(t.id, "s7")
    assert recs[0]["apps"] == ["google_drive"] and recs[0]["tags"] == []
    assert _check(t, "github_create_repo", {"private": False}, session="s7")["allowed"] is False


# ── MCP tools/call ───────────────────────────────────────────────────


def _mcp(tool, args, *, tenant, session="m1", route=None, tenant_config=None):
    from core.mcp import enforcement
    with patch.object(enforcement, "_tool_guard_chain", return_value=[]):
        return asyncio.run(enforcement.enforce_tool_call(
            tool, args, agent_key="research-bot", user_role="analyst", tenant_id=tenant,
            tenant_config=tenant_config if tenant_config is not None else {},
            session_id=session, route=route))


def test_mcp_path_records_and_blocks(monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", "off")
    xflow.save_policy("mcp-t", _policy())
    assert _mcp("drive_read_file", {}, tenant="mcp-t")["allowed"] is True
    d = _mcp("github_create_repo", {"private": False}, tenant="mcp-t")
    assert d["allowed"] is False and "confidential-to-public" in d["reason"]
    assert _mcp("github_create_repo", {"private": False}, tenant="mcp-t", session="m2")["allowed"]


def test_mcp_require_approval_denies_and_tenant_monitor_allows(monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", "off")
    xflow.save_policy("mcp-t2", _policy())
    _mcp("salesforce_get_account", {"id": 1}, tenant="mcp-t2")
    d = _mcp("gmail_send", {"to": "x@partner.com"}, tenant="mcp-t2")
    assert d["allowed"] is False and "MCP path cannot carry" in d["reason"]
    d = _mcp("gmail_send", {"to": "x@partner.com"}, tenant="mcp-t2",
             tenant_config={"policy_mode": "monitor"})
    assert d["allowed"] is True and "cross_app_flow" in d["would_block"]


def test_mcp_route_membership(monkeypatch):
    monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", "off")
    p = _policy()
    p["apps"]["google_drive"]["routes"] = ["gdrive"]
    xflow.save_policy("mcp-t3", p)
    _mcp("read_file", {"path": "x"}, tenant="mcp-t3", route="gdrive")
    assert _mcp("pastebin_create", {}, tenant="mcp-t3")["allowed"] is False


def test_mcp_result_tags_are_recorded():
    from core.mcp import enforcement

    xflow.save_policy("mcp-t4", _policy())

    async def fake_check(self, content, context=None):
        return _dlp_result("credit_card_pan")

    with patch.object(enforcement.ToolOutputSanitizationGuardrail, "check", fake_check):
        out = asyncio.run(enforcement.sanitize_tool_result(
            "billing_lookup", "4111...", agent_key="research-bot", tenant_id="mcp-t4",
            session_id="m9", tool_call_id="tc_9"))
    assert out["blocked"] is False
    recs = xflow_state.read_session("mcp-t4", "m9")
    assert "credit_card" in recs[0]["tags"] and recs[0]["tool_call_id"] == "tc_9"


# ── cap/mint ─────────────────────────────────────────────────────────


def _identity(user="alice@corp.com", session="c1", tenant="cap-t"):
    from core.identity import IdentityTuple
    return IdentityTuple(user_sub=user, agent_id="research-bot", agent_instance_id="pod-1",
                         tenant_id=tenant, build_hash="sha256:abc", model_version="m",
                         session_id=session)


def _mint(tool, params=None, *, identity=None, session="c1", grant=None, resource="r/1"):
    from api import routes_agent_auth as aa
    from api.routes_agent_auth import CapMintRequest

    body = CapMintRequest(tool=tool, resource=resource, tool_params=params or {},
                          session_id=session, approval_grant=grant)
    with patch.object(aa, "rate_limit_cap_mint", return_value=(True, None)), \
         patch.object(aa, "_decide_authz", return_value={
             "allowed": True, "tool": tool, "resource": resource, "reasons": []}):
        return asyncio.run(aa.mint_capability(body, identity or _identity()))


def test_cap_mint_blocks_and_principal_scope_uses_verified_user():
    from fastapi import HTTPException

    xflow.save_policy("cap-t", _policy())
    assert _mint("drive_read_file").cap_token
    with pytest.raises(HTTPException) as e:
        _mint("github_create_repo", {"private": False})
    assert e.value.status_code == 403
    # Same verified user, rotated session: the principal scope still knows.
    with pytest.raises(HTTPException):
        _mint("github_create_repo", {"private": False}, session="c-rotated",
              identity=_identity(session="c-rotated"))
    # Another user of the same shared agent is not tainted by alice's read.
    assert _mint("github_create_repo", {"private": False}, session="c-bob",
                 identity=_identity(user="bob@corp.com", session="c-bob")).cap_token


def test_cap_mint_require_approval_then_grant():
    from fastapi import HTTPException

    xflow.save_policy("cap-t2", _policy())
    ident = _identity(tenant="cap-t2")
    _mint("salesforce_get_account", {"id": "1"}, identity=ident)
    mail = {"to": "buyer@partner.com"}
    with pytest.raises(HTTPException) as e:
        _mint("gmail_send", mail, identity=ident)
    assert e.value.status_code == 403 and e.value.detail["reason"] == "approval_required"
    rid = e.value.detail["request_id"]
    with pytest.raises(HTTPException) as e2:
        _mint("gmail_send", mail, identity=ident)
    assert e2.value.detail["request_id"] == rid          # deduplicated

    def grant_for(params):
        return ap.mint_grant(
            tenant_id="cap-t2", agent_id="research-bot", agent_instance_id="pod-1",
            session_id="c1", tool="gmail_send", resource="r/1",
            params_hash=ap.params_hash(params),
            approvers=[{"sub": "carol@corp.com", "method": "sso", "at": 1}], request_id=rid)

    with pytest.raises(HTTPException) as e3:
        _mint("gmail_send", mail, identity=ident, grant=grant_for({"to": "other@evil.io"}))
    assert e3.value.status_code == 403
    assert _mint("gmail_send", mail, identity=ident, grant=grant_for(mail)).cap_token


def test_cap_mint_without_policy_is_unchanged():
    assert _mint("github_create_repo", {"private": False},
                 identity=_identity(tenant="cap-none")).cap_token


def test_policy_copy_is_not_mutated_by_save():
    p = _policy()
    before = copy.deepcopy(p)
    xflow.save_policy("t-copy", p)
    assert p == before
