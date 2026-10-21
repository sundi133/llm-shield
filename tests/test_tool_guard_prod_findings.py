"""Tool-check fixes from the production scenario run (Rafay customer checks).

1. An approval for one call could be spent on different arguments: a refund
   approved at 100 went through at 10,000.
2. A role that may never run a tool got an approval request instead of a
   refusal, so a manager could be asked to approve an impossible call.
3. The kill switch answered "disabled" on a deployment that never enforces
   it (SHIELD_ENABLE_KILLSWITCH unset), so operators believed a tool stopped.
4. A role list of ["*"] passed the allowlist but failed RBAC, which matched
   exact names only, so "every tool this agent has" could not be expressed.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

AGENT_TOOLS = ["crm_lookup", "send_email", "refund_payment"]


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    from storage import agentic_control_plane, tenant_store, tool_killswitch
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(tool_killswitch, "_get_redis", lambda: None)
    monkeypatch.setattr(agentic_control_plane, "_get_redis", lambda: None)


def _tenant(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import add_api_key, create_tenant

    tid = "tg" + uuid.uuid4().hex[:10]
    key = "sk-tg-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise", "input_guardrails": {},
                        "output_guardrails": {}}, api_keys=[key])
    approver = {"X-API-Key": "sk-tg-op-" + uuid.uuid4().hex}
    add_api_key(tid, approver["X-API-Key"], scope="admin")
    client = TestClient(app)
    headers = {"X-API-Key": key}
    r = client.post("/v1/agents/registry", headers=approver, json={
        "agent_id": "bot", "tools": AGENT_TOOLS,
        "role_permissions": {"support": ["crm_lookup", "send_email"],
                             "finance": ["crm_lookup", "refund_payment"]}})
    assert r.status_code == 200, r.text
    r = client.put("/v1/tenant/me/agentic/config", headers=approver, json={
        "approvals": {"enabled": True, "rules": [
            {"rule_id": "money", "tool_names": ["refund_payment"], "min_approvals": 1}]}})
    assert r.status_code == 200, r.text
    return SimpleNamespace(id=tid, client=client, headers=headers, approver=approver)


def _check(t, role, tool, params, session="s1", **extra):
    r = t.client.post("/v1/shield/tool/check", headers=t.headers, json={
        "agent_key": "bot", "user_role": role, "tool_name": tool,
        "tool_params": params, "session_id": session, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def _result(d, name):
    return next((g for g in d["guardrail_results"] if g["guardrail"] == name), None)


def _approve(t, rid):
    r = t.client.post(f"/v1/tenant/me/agentic/approvals/{rid}/approve",
                      headers=t.approver, json={"approver": "ops@acme.example", "reason": "ok"})
    assert r.status_code == 200, r.text


# ── 1. approval bound to the arguments ───────────────────────────────


def test_approved_refund_cannot_be_spent_on_a_bigger_amount(app):
    t = _tenant(app)
    held = _check(t, "finance", "refund_payment", {"order": "A1", "amount": 100})
    assert held["action"] == "pending_confirmation"
    rid = _result(held, "approval_lifecycle")["details"]["request_id"]
    _approve(t, rid)

    bigger = _check(t, "finance", "refund_payment", {"order": "A1", "amount": 10000},
                    approval_request_id=rid)
    assert bigger["allowed"] is False
    assert "arguments changed" in _result(bigger, "approval_lifecycle")["message"]

    # Refused without consuming: the approved call itself still goes through, once.
    ok = _check(t, "finance", "refund_payment", {"order": "A1", "amount": 100},
                approval_request_id=rid)
    assert ok["allowed"] is True
    again = _check(t, "finance", "refund_payment", {"order": "A1", "amount": 100},
                   approval_request_id=rid)
    assert again["allowed"] is False


def test_consume_refuses_changed_arguments_without_consuming():
    from storage.agentic_control_plane import (consume_approval_request,
                                               create_approval_request,
                                               update_approval_request)
    tid = "tg" + uuid.uuid4().hex[:10]
    req = create_approval_request(tid, agent_key="bot", tool_name="refund_payment",
                                  session_id="s", workflow="default",
                                  tool_params={"amount": 100}, rule={"min_approvals": 1})
    update_approval_request(tid, req["request_id"], decision="approve", approver="ops")
    kw = dict(agent_key="bot", tool_name="refund_payment", session_id="s")

    ok, msg, item = consume_approval_request(tid, req["request_id"], tool_params={"amount": 9}, **kw)
    assert not ok and "arguments changed" in msg and item["status"] == "approved"
    # Key order and an absent-vs-empty dict do not count as a change.
    req2 = create_approval_request(tid, agent_key="bot", tool_name="refund_payment",
                                   session_id="s", workflow="default", tool_params=None,
                                   rule={"min_approvals": 1})
    update_approval_request(tid, req2["request_id"], decision="approve", approver="ops")
    assert consume_approval_request(tid, req2["request_id"], tool_params={}, **kw)[0]
    assert consume_approval_request(tid, req["request_id"], tool_params={"amount": 100}, **kw)[0]


# ── 2. role checked before an approval is opened ─────────────────────


def test_role_without_the_tool_is_refused_not_sent_for_approval(app):
    from storage.agentic_control_plane import list_approval_requests
    t = _tenant(app)
    d = _check(t, "support", "refund_payment", {"order": "A2", "amount": 5})
    assert d["allowed"] is False and d["action"] == "block"
    assert _result(d, "approval_lifecycle") is None
    assert any(g["guardrail"] in ("rbac_guard", "tool_allowlist") and not g["passed"]
               for g in d["guardrail_results"])
    assert list_approval_requests(t.id) == []


def test_role_with_the_tool_still_waits_for_approval(app):
    t = _tenant(app)
    d = _check(t, "finance", "refund_payment", {"order": "A3", "amount": 5})
    assert d["action"] == "pending_confirmation"


def test_role_star_means_every_tool_the_agent_has(app):
    # The agent's own list names each tool (the registry validates names);
    # a role may use patterns, and both guards now read them the same way.
    t = _tenant(app)
    r = t.client.post("/v1/agents/registry", headers=t.approver, json={
        "agent_id": "any-bot", "tools": ["lookup_weather", "crm_lookup", "send_email"],
        "role_permissions": {"support": ["*"], "crm": ["crm_*"]}})
    assert r.status_code == 200, r.text

    def check(role, tool):
        r = t.client.post("/v1/shield/tool/check", headers=t.headers, json={
            "agent_key": "any-bot", "user_role": role, "tool_name": tool,
            "tool_params": {}, "session_id": "star",
            "guardrails": ["rbac_guard", "tool_allowlist"]})
        assert r.status_code == 200, r.text
        return r.json()

    assert check("support", "lookup_weather")["allowed"] is True
    assert check("crm", "crm_lookup")["allowed"] is True
    assert check("crm", "send_email")["allowed"] is False
    assert check("support", "drop_database")["allowed"] is False  # not on the agent's list


def test_rbac_patterns_unit():
    from config.schema import RBACRole
    from core.rbac import enforcer
    role = RBACRole(name="r", allowed_tools=["crm_*", "send_email"], denied_tools=["crm_delete*"],
                    allowed_data_scopes=[], denied_data_scopes=[], data_clearance="public")
    assert enforcer.check_tool_access(role, "send_email")
    assert enforcer.check_tool_access(role, "crm_lookup")
    assert not enforcer.check_tool_access(role, "crm_delete_all")
    assert not enforcer.check_tool_access(role, "refund_payment")


# ── 3. kill switch says whether it is enforced ───────────────────────


def test_kill_switch_disable_reports_when_it_is_not_enforced(app, monkeypatch):
    import core.feature_flags as ff
    t = _tenant(app)
    monkeypatch.setattr(ff, "KILLSWITCH_ENABLED", False)
    r = t.client.post("/v1/shield/tools/send_email/disable", headers=t.approver,
                      json={"reason": "drill"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enforced"] is False and "SHIELD_ENABLE_KILLSWITCH" in body["warning"]
    listed = t.client.get("/v1/shield/tools/disabled", headers=t.approver).json()
    assert listed["enforced"] is False and listed["count"] == 1

    monkeypatch.setattr(ff, "KILLSWITCH_ENABLED", True)
    listed = t.client.get("/v1/shield/tools/disabled", headers=t.approver).json()
    assert listed["enforced"] is True and "warning" not in listed
