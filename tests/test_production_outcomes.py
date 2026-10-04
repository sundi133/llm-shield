"""The six production outcomes, each delivered by a tool policy, proven through
the real MCP gateway (docs/specs/mcp-production-outcomes.md).

Every outcome is configured the way an ops user configures it on the Tool
Policies screen: the default policy or a tool's own policy, built from the
ready-made protections (core/policy_library.py) and custom rules. Each one is
shown three ways:

  * no policy: the risky call executes, so nothing else is what blocks it;
  * policy on: the risky call is blocked, the tool never runs, and the
    decision is recorded naming the tool policy guard;
  * policy on: the legitimate variant still executes.

Calls go over HTTP to POST /gateway/{route}/mcp on the data-plane app, through
the real MCPGatewayRouter, MCPProxy and guard chain, to a fake upstream that
records what reached it. The one stand-in is the model: a policy-aware judge
that receives exactly the prompt the real judge would and flags a call only
when a rule in that prompt is broken. That proves policy -> judge -> enforcement,
not how well a real model judges (the red-team product's job).

Gaps are written for the correct behaviour and marked xfail(strict=True), so
`pytest tests/test_production_outcomes.py -rxX` is the scoreboard and a fixed
gap fails the suite until its marker is removed.
"""
import asyncio
import json
import re
import time
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import api.routes_mcp_gateway_server as bridge
import core.check_alerts as check_alerts
import core.policy_library as library
import core.webhook_dispatcher as webhooks
import guardrails.agentic.tool.payload_risk as payload_risk
import guardrails.agentic.tool.tool_output_sanitization as output_guard
from core.mcp.gateway import MCPGatewayRouter
from core.mcp.proxy_server import MCPProxy

ROUTE = "bank"
AGENT = "ops-agent"
ROLE = "support"
TOOLS = ["customer_profile_get", "email_send", "delete_account"]
RESULTS = {
    "customer_profile_get": {"customer_id": "C-1001", "name": "Aisha Khan", "tier": "gold"},
    "email_send": {"status": "sent"},
    "delete_account": {"status": "deleted"},
}


# ── the stand-in model ─────────────────────────────────────────────────────


class PolicyAwareJudge:
    """Answers the two model calls a tool policy makes, from the prompt alone.

    It flags only rules that are present in the prompt it was handed, so with
    no policy it never flags. Each prompt is recorded so a test can assert the
    configured rule actually reached the judge. `down` makes every call fail,
    as a model outage does.
    """

    def __init__(self):
        self.prompts = []
        self.down = False

    # tool call arguments (guardrails/agentic/tool/payload_risk.py)
    async def judge_call(self, **kw):
        system, user = kw["messages"][0]["content"], kw["messages"][1]["content"]
        self.prompts.append(system)
        if self.down:
            raise ConnectionError("policy model unavailable")
        args = json.loads(user.split("Parameters: ", 1)[1])
        broken = self._broken_call_rule(system, args)
        line = (f"true,0.95,policy_violation,high,{broken}" if broken
                else "false,0.95,none,low,all parameters comply")
        return {"choices": [{"message": {"content": line}}]}

    @staticmethod
    def _broken_call_rule(system: str, args: dict):
        if "[T14 Cross-tenant access]" in system:
            if any(k in args for k in ("tenant_id", "org_id", "organisation")):
                return "T14 sets a tenant identifier explicitly"
        return None

    # tool results (guardrails/agentic/tool/tool_output_sanitization.py)
    async def judge_result(self, **kw):
        system = kw["messages"][0]["content"]
        self.prompts.append(system)
        if self.down:
            raise ConnectionError("policy model unavailable")
        return {"choices": [{"message": {"content": "false,allow,0.95,none"}}]}


# ── the gateway, its upstreams, and what they record ───────────────────────


class FakeUpstream:
    def __init__(self, tenant):
        self.tenant = tenant
        self.calls = []

    async def list_tools(self):
        return [{"name": t, "description": t} for t in TOOLS]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return RESULTS[name]

    async def aclose(self):
        pass


class _PolicyStore:
    """Just the one key the real policy loader reads."""

    def __init__(self):
        self.kv = {}

    def get(self, k):
        return self.kv.get(k)


class Tenant:
    def __init__(self, world, policy_mode="enforce"):
        from storage.mcp_gateway_store import set_upstream
        from storage.tenant_store import create_tenant, kv_set
        self.world = world
        self.id = "po" + uuid.uuid4().hex[:10]
        self.key = "sk-po-" + uuid.uuid4().hex
        create_tenant(self.id, {"name": self.id, "plan": "enterprise",
                                "policy_mode": policy_mode}, api_keys=[self.key])
        set_upstream(self.id, ROUTE, {"route": ROUTE, "transport": "http",
                                      "url": "http://upstream.invalid/mcp",
                                      "isolation_ack": True})
        kv_set(f"agents:{self.id}", {AGENT: {
            "agent_id": AGENT, "tools": TOOLS, "role_permissions": {ROLE: TOOLS},
            "status": "active"}})
        self.upstream = FakeUpstream(self.id)
        world.upstreams[self.id] = self.upstream

    # policies, built as the portal builds them
    def set_policies(self, **policies):
        self.world.policies.kv[f"data_policies:{self.id}"] = json.dumps(policies)

    def call(self, tool, args, *, route=ROUTE, meta=None):
        params = {"name": tool, "arguments": args}
        if meta:
            params["_meta"] = meta
        r = self.world.client.post(
            f"/gateway/{route}/mcp",
            headers={"X-API-Key": self.key, "X-Agent-Key": AGENT, "X-User-Role": ROLE},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
        assert r.status_code == 200, r.text
        return r.json()

    def decisions(self):
        from storage.decision_audit import query_decisions
        return query_decisions(tenant_id=self.id)


def default_policy(ids=None, domains=None, **extra):
    """The default policy (all tools) with these ready-made protections ticked.
    `domains` fills a rule's <your-domains>, as the editor does."""
    p = library.as_policy(ids)
    if domains:
        for rp in p["role_policies"]:
            for side in ("input_rules", "output_rules"):
                rp[side] = [r.replace("<your-domains>", domains) for r in rp[side]]
    return {**p, "enabled": True, **extra}


class World:
    def __init__(self, client):
        self.client = client
        self.upstreams = {}
        self.policies = _PolicyStore()
        self.judge = PolicyAwareJudge()
        self.sink = []
        self.alerts = []

    def wait_for_alerts(self, n=1, timeout=2.0):
        end = time.monotonic() + timeout
        while len(self.alerts) < n and time.monotonic() < end:
            time.sleep(0.02)
        return self.alerts


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def world(app, monkeypatch):
    for k, v in {"SHIELD_MCP_TOOL_PARITY": "1", "SHIELD_MCP_CONTROL_PLANE": "monitor",
                 "SHIELD_GLOBAL_DATA_POLICY": "on", "SHIELD_WILDCARD_ROLE_POLICY": "on"}.items():
        monkeypatch.setenv(k, v)
    for k in ("SHIELD_DLP_FAIL_CLOSED", "SHIELD_INDIRECT_INJECTION_SCAN",
              "SHIELD_INDIRECT_INJECTION_BLOCK", "SHIELD_DLP_LLM_TIMEOUT_S"):
        monkeypatch.delenv(k, raising=False)
    # Redis off everywhere this path reads or writes; every store falls back
    # to memory, as in tests/test_runtime_checks.py.
    for target in ("storage.tenant_store._get_redis", "storage.decision_audit._get_redis",
                   "storage.mcp_gateway_store._get_redis"):
        monkeypatch.setattr(target, lambda: None)

    with TestClient(app) as client:
        w = World(client)

        # The real policy loader, reading the policies this test set.
        real_load = payload_risk._load_data_policies

        def load(tenant_id, tool_name=""):
            with patch("storage.tenant_store._get_redis", return_value=w.policies):
                return real_load(tenant_id, tool_name)
        monkeypatch.setattr(payload_risk, "_load_data_policies", load)

        monkeypatch.setattr(payload_risk, "async_llm_call", w.judge.judge_call)
        monkeypatch.setattr(output_guard, "async_llm_call", w.judge.judge_result)

        async def capture(tenant_id, event_type, payload):
            w.alerts.append((tenant_id, event_type, payload))
        monkeypatch.setattr(webhooks, "dispatch_event", capture)
        check_alerts._reset()

        async def factory(cfg, tenant_id):
            async def sink(event):
                w.sink.append(event)
            return MCPProxy(w.upstreams[tenant_id], policy=cfg.get("effective_policy"),
                            route=cfg.get("route"), on_decision=sink)
        monkeypatch.setattr(bridge, "gateway_router", MCPGatewayRouter(proxy_factory=factory))
        yield w
    check_alerts._reset()


def _executed(result) -> bool:
    return "result" in result and result["result"]["isError"] is False


def _blocked_by_policy(tenant, tool):
    """The decision recorded for a blocked call names the tool policy guard."""
    rows = [d for d in tenant.decisions() if d.get("tool_name") == tool]
    assert rows, "no decision recorded"
    row = rows[0]
    assert row["action"] == "block"
    assert row["guardrail"] == "tool_call_validation"
    assert row["agent_key"] == AGENT and row["tenant_id"] == tenant.id
    assert row["reason"]
    return row


# ── 1. A legitimate tool call succeeds ─────────────────────────────────────


def test_1_a_legitimate_call_executes_under_the_recommended_policy(world):
    t = Tenant(world)
    t.set_policies(__global__=default_policy())
    out = t.call("customer_profile_get", {"customer_id": "C-1001"})

    assert _executed(out)
    assert t.upstream.calls == [("customer_profile_get", {"customer_id": "C-1001"})]
    assert json.loads(out["result"]["content"][0]["text"]) == RESULTS["customer_profile_get"]
    # The judge was handed the policy the ops user ticked.
    recommended = [e for e in library.ENTRIES if e["recommended"] and e["side"] == "call"]
    assert all(e["tag"] in world.judge.prompts[0] for e in recommended)
    assert t.decisions()[0]["metadata"]["allowed"] is True


# ── 2. An unauthorized cross-tenant request is blocked ─────────────────────

CROSS_TENANT = {"customer_id": "C-1001", "tenant_id": "other-bank"}


def test_2_without_the_policy_a_cross_tenant_lookup_executes(world):
    t = Tenant(world)
    t.set_policies(__global__=default_policy(["call.T1"]))
    assert _executed(t.call("customer_profile_get", CROSS_TENANT))
    assert t.upstream.calls == [("customer_profile_get", CROSS_TENANT)]


def test_2_the_cross_tenant_policy_blocks_it_before_the_tool_runs(world):
    t = Tenant(world)
    t.set_policies(__global__=default_policy(["call.T14"]))
    out = t.call("customer_profile_get", CROSS_TENANT)

    assert not _executed(out)
    assert t.upstream.calls == []
    assert "[T14 Cross-tenant access]" in world.judge.prompts[0]
    _blocked_by_policy(t, "customer_profile_get")


def test_2_the_same_lookup_for_the_callers_own_records_executes(world):
    t = Tenant(world)
    t.set_policies(__global__=default_policy(["call.T14"]))
    assert _executed(t.call("customer_profile_get", {"customer_id": "C-1001"}))
    assert len(t.upstream.calls) == 1


def test_2_beneath_every_policy_another_tenants_server_is_unreachable(world):
    """Built in, no policy needed: routes are looked up under the caller's own
    tenant, so naming another tenant's route reaches nothing."""
    a, b = Tenant(world), Tenant(world)
    from storage.mcp_gateway_store import set_upstream
    set_upstream(b.id, "b-only", {"route": "b-only", "transport": "http",
                                  "url": "http://upstream.invalid/mcp", "isolation_ack": True})
    out = a.call("customer_profile_get", {"customer_id": "C-1001"}, route="b-only")
    assert out["error"]["code"] == -32004
    assert a.upstream.calls == b.upstream.calls == []


# ── 6. A detector outage: the configured safe behaviour, and an alert ──────


def test_6_with_block_chosen_an_outage_blocks_before_the_tool_runs_and_alerts(world):
    t = Tenant(world)
    t.set_policies(__global__=default_policy(fail_closed=True))
    world.judge.down = True
    out = t.call("customer_profile_get", {"customer_id": "C-1001"})

    assert not _executed(out)
    assert t.upstream.calls == []
    row = _blocked_by_policy(t, "customer_profile_get")
    assert "could not run" in row["reason"]
    alerts = world.wait_for_alerts()
    assert [(a[0], a[1], a[2]["decision"], a[2]["side"]) for a in alerts] == [
        (t.id, "check_unavailable", "blocked", "tool_call")]


def test_6_with_nothing_chosen_an_outage_lets_the_call_through_labelled_and_alerts(world):
    t = Tenant(world)
    t.set_policies(__global__=default_policy())
    world.judge.down = True
    out = t.call("customer_profile_get", {"customer_id": "C-1001"})

    assert _executed(out)
    assert len(t.upstream.calls) == 1
    call_stage = [r for r in world.sink[-1]["results"] if r["guardrail"] == "tool_call_validation"]
    assert call_stage and call_stage[0]["details"]["unjudged"] is True
    alerts = world.wait_for_alerts()
    assert alerts[0][2]["decision"] == "let_through"
