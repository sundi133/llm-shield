"""Policy from purpose. Spec: docs/specs/policy-from-purpose.md.

Task 1: what an agent was seen doing (recorded off the guard path, no values),
and the deterministic least-privilege draft built from it."""

import json
import time
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from core.policy_learning import draft as drafts
from core.policy_learning import observe

T, AGENT = "pl-acme", "billing-bot"


@pytest.fixture(autouse=True)
def store(monkeypatch):
    import storage.tenant_store as ts
    from storage import tool_catalog
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    for name in ("SHIELD_POLICY_LEARNING", "SHIELD_REGISTRY_WRITE_SCOPE", "SHIELD_CONFIG_WRITE_SCOPE",
                 "REDIS_URL", "UPSTASH_REDIS_REST_URL"):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    tool_catalog.reset_cache()
    observe.reset_for_tests()
    # Tests flush explicitly; the background flush has its own test.
    monkeypatch.setattr(observe, "_maybe_flush", lambda: None)
    ts.create_tenant(T, {"name": "Acme"})
    ts.kv_set(f"agents:{T}", {AGENT: {"agent_id": AGENT, "status": "active", "updated_at": 100,
                                      "description": "Answers billing questions and issues refunds",
                                      "tools": ["lookup_invoice", "refund_payment", "delete_account"],
                                      "identity": {"require": "any"}}})
    yield ts
    observe.reset_for_tests()
    ts._fallback_store.clear()
    tool_catalog.reset_cache()


def seen(tool, role="support", outcome="allowed", n=1, resource=None, params=None,
         identity="agent_token_dpop", agent=AGENT, via="tool_check"):
    for _ in range(n):
        observe.record(T, agent, tool, role, outcome, via=via, resource=resource,
                       params=params, identity=identity)


# ── observation ──────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,shape", [
    ("order/88123", "order/*"), ("customers/ana@acme.com/invoices", "customers/*/invoices"),
    ("tickets/7f3a9c21e4b0", "tickets/*"), ("reports/q3", "reports/q3"),
    ("files/2024-10-18_report.pdf", "files/*"), ("", ""), (None, ""),
])
def test_resources_are_stored_as_shapes(raw, shape):
    assert observe.resource_shape(raw) == shape


def test_one_call_records_counts_shapes_and_argument_names_never_values():
    seen("lookup_invoice", resource="invoice/55501", params={"invoice_id": "55501", "email": "ana@acme.com"})
    observe.flush()
    [e] = observe.read(T, AGENT)
    assert (e["tool"], e["role"], e["count"]) == ("lookup_invoice", "support", 1)
    assert e["outcomes"] == {"allowed": 1}
    assert e["resources"] == ["invoice/*"] and sorted(e["param_keys"]) == ["email", "invoice_id"]
    assert "55501" not in json.dumps(e) and "ana@acme.com" not in json.dumps(e)
    assert e["identity"] == ["agent_token_dpop"] and e["via"] == ["tool_check"]


def test_flushes_merge_and_the_window_filters():
    seen("lookup_invoice", n=2)
    observe.flush()
    seen("lookup_invoice", outcome="blocked")
    observe.flush()
    [e] = observe.read(T, AGENT)
    assert e["count"] == 3 and e["outcomes"] == {"allowed": 2, "blocked": 1}
    import storage.tenant_store as ts
    h = ts._fallback_store[f"policylearn:{T}:{AGENT}"]
    old = json.loads(h["lookup_invoice|support"])
    old["last_seen"] = int(time.time()) - 20 * 86400
    h["lookup_invoice|support"] = json.dumps(old)
    assert observe.read(T, AGENT, days=14) == [] and len(observe.read(T, AGENT, days=30)) == 1


def test_opt_outs_stop_recording(store, monkeypatch):
    monkeypatch.setenv("SHIELD_POLICY_LEARNING", "off")
    seen("lookup_invoice")
    monkeypatch.delenv("SHIELD_POLICY_LEARNING")
    observe.flush()
    assert observe.read(T, AGENT) == []
    store.update_tenant(T, {"policy_learning": False})
    seen("lookup_invoice")
    observe.flush()
    assert observe.read(T, AGENT) == []


def test_a_store_failure_drops_the_batch_and_never_raises(monkeypatch, caplog):
    seen("lookup_invoice")

    class Broken:
        def hget(self, *a):
            raise ConnectionError("down")
    monkeypatch.setattr("storage.tenant_store._get_redis", lambda: Broken())
    assert observe.flush() == 0
    assert any("dropped" in r.getMessage() for r in caplog.records)


def test_redis_entries_get_a_ttl(monkeypatch):
    calls = {}

    class Fake:
        def __init__(self):
            self.h = {}

        def hget(self, n, f):
            return self.h.get((n, f))

        def hlen(self, n):
            return sum(1 for k in self.h if k[0] == n)

        def hset(self, n, f, v):
            self.h[(n, f)] = v

        def expire(self, n, ttl):
            calls[n] = ttl
    monkeypatch.setattr("storage.tenant_store._get_redis", lambda: Fake())
    seen("lookup_invoice")
    assert observe.flush() == 1
    assert calls == {f"policylearn:{T}:{AGENT}": 30 * 86400}


def test_the_buffer_flushes_itself_in_the_background(monkeypatch):
    monkeypatch.undo()
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    observe.reset_for_tests()
    observe.record(T, AGENT, "lookup_invoice", "support", "allowed", via="tool_check")
    for _ in range(100):
        if observe.read(T, AGENT):
            break
        time.sleep(0.01)
    assert [e["tool"] for e in observe.read(T, AGENT)] == ["lookup_invoice"]


def test_recording_is_cheap_and_does_no_io(monkeypatch):
    """Spec budget: under 0.05 ms per guarded call."""
    monkeypatch.setattr(observe, "_maybe_flush", lambda: None)
    monkeypatch.setattr("storage.tenant_store._get_redis", lambda: pytest.fail("I/O on the guard path"))
    n = 20_000
    start = time.perf_counter()
    for i in range(n):
        observe.record(T, AGENT, f"tool_{i % 50}", "support", "allowed", via="tool_check",
                       resource="order/123", params={"a": 1, "b": 2})
    per_call_ms = (time.perf_counter() - start) * 1000 / n
    assert per_call_ms < 0.05, per_call_ms


def test_the_tool_check_route_records_an_observation():
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    cs.config = original
    TestClient(app).post("/v1/shield/tool/check", headers={"X-Tenant-ID": T, "X-User-Role": "support"},
                         json={"agent_key": AGENT, "tool_name": "lookup_invoice", "tool_params": {"id": 1}})
    observe.flush()
    [e] = observe.read(T, AGENT)
    assert e["tool"] == "lookup_invoice" and e["via"] == ["tool_check"] and e["param_keys"] == ["id"]


# ── the deterministic draft ──────────────────────────────────────────


def build(**kw):
    observe.flush()
    return drafts.build(T, AGENT, **kw)


def items(d, kind=None):
    return {i["id"]: i for i in d["items"] if kind is None or i["kind"] == kind}


@pytest.mark.parametrize("tool,expected", [
    ("lookup_invoice", "low"), ("get_customer", "low"), ("refund_payment", "high"),
    ("deleteAccount", "high"), ("send_email", "high"), ("update_ticket", "medium"),
    ("create_note", "medium"), ("run_shell", "high"),
])
def test_risk_comes_from_the_name(tool, expected):
    assert drafts.risk(tool, approval_tools=set(), sanitized_tools=set())[0] == expected


def test_existing_rules_make_a_tool_high_risk():
    assert drafts.risk("lookup_invoice", approval_tools={"lookup_invoice"}, sanitized_tools=set())[0] == "high"
    assert drafts.risk("lookup_invoice", approval_tools=set(), sanitized_tools={"lookup_invoice"})[0] == "high"


def test_the_draft_holds_exactly_what_was_seen():
    seen("lookup_invoice", n=5, resource="invoice/55501")
    seen("lookup_invoice", role="manager", n=2, resource="invoice/55502")
    seen("refund_payment", n=4, resource="order/88123")
    seen("delete_account", outcome="blocked", n=3)
    d = build()
    tools = items(d, "tool")
    assert set(tools) == {"tool:lookup_invoice", "tool:refund_payment"}       # never delete_account
    assert tools["tool:lookup_invoice"]["roles"] == ["manager", "support"]
    assert tools["tool:lookup_invoice"]["risk"] == "low"
    assert tools["tool:refund_payment"]["risk"] == "high"
    assert all(i["status"] == "pending" for i in d["items"])                  # nothing preselected
    assert items(d, "approval")["approval:refund_payment"]["value"] == {"tool": "refund_payment",
                                                                        "min_approvals": 2}
    assert set(items(d, "resource")) == {"resource:invoice/*", "resource:order/*"}
    assert items(d, "identity")["identity"]["value"] == "token"
    q = {x["id"]: x for x in d["questions"]}
    assert q["blocked:delete_account"]["options"] == ["allow", "allow with approval", "keep blocked"]
    assert d["base_version"] == 100


def test_rule_based_questions_and_their_answers():
    seen("refund_payment", n=1)
    seen("lookup_invoice", n=4)
    seen("lookup_invoice", role="auditor", n=1)
    seen("delete_account", outcome="blocked", n=2)
    d = build()
    q = {x["id"] for x in d["questions"]}
    assert {"rare_high:refund_payment", "one_role:lookup_invoice:auditor", "blocked:delete_account"} <= q
    d = build(answers={"rare_high:refund_payment": "remove",
                       "one_role:lookup_invoice:auditor": "remove this role",
                       "blocked:delete_account": "allow with approval"}, previous=d)
    it = items(d)
    assert it["tool:refund_payment"]["status"] == "rejected"
    assert it["tool:lookup_invoice"]["roles"] == ["support"]
    assert it["tool:delete_account"]["status"] == "pending"
    assert it["approval:delete_account"]["value"]["min_approvals"] == 1


def test_decisions_carry_over_when_the_draft_is_rebuilt():
    seen("lookup_invoice", n=3)
    d = build()
    d["items"][0]["status"] = "accepted"
    seen("lookup_invoice")
    d2 = build(previous=d)
    assert items(d2)["tool:lookup_invoice"]["status"] == "accepted" and d2["id"] == d["id"]


def test_a_tool_no_longer_anywhere_goes_stale():
    seen("lookup_invoice", n=3)
    d = build()
    d["items"].append({"id": "tool:old_tool", "kind": "tool", "value": "old_tool", "roles": [],
                       "risk": "low", "status": "accepted", "evidence": {"observed": 1}})
    d2 = build(previous=d)
    assert items(d2)["tool:old_tool"]["status"] == "stale"


def test_resource_shapes_never_widen_past_one_wildcard():
    seen("lookup_invoice", resource="12345")                       # shape "*" alone
    seen("lookup_invoice", resource="tenants/88/orders/123")       # two wildcards
    seen("lookup_invoice", resource="invoice/55501")
    d = build()
    assert set(items(d, "resource")) == {"resource:invoice/*"}
    assert set(d["skipped_resources"]) == {"*", "tenants/*/orders/*"}


def test_identity_proposal_follows_what_callers_proved():
    seen("lookup_invoice", identity="cert")
    seen("refund_payment", identity="agent_token")
    assert items(build(), "identity")["identity"]["value"] == "cert_or_token"
    observe.reset_for_tests()
    import storage.tenant_store as ts
    ts._fallback_store.pop(f"policylearn:{T}:{AGENT}", None)
    seen("lookup_invoice", identity="string_key")
    assert items(build(), "identity") == {}


def test_an_existing_approval_rule_is_kept_not_duplicated():
    from storage.agentic_control_plane import get_control_plane_config, set_control_plane_config
    cfg = get_control_plane_config(T)
    cfg["approvals"]["rules"] = [{"rule_id": "r1", "tool_names": ["refund_payment"]}]
    set_control_plane_config(T, cfg)
    seen("refund_payment", n=4)
    d = build()
    assert "approval:refund_payment" not in items(d)
    assert items(d)["tool:refund_payment"]["risk"] == "high"


def test_nothing_to_learn_and_unregistered_agents():
    import storage.tenant_store as ts
    ts.kv_set(f"agents:{T}", {AGENT: {"agent_id": AGENT, "description": "", "updated_at": 1}})
    with pytest.raises(drafts.DraftError) as e:
        build()
    assert e.value.code == "nothing_to_learn"
    seen("lookup_invoice", agent="stray-bot")
    observe.flush()
    with pytest.raises(drafts.DraftError) as e:
        drafts.build(T, "stray-bot")
    assert e.value.code == "unregistered_agent"
    with pytest.raises(drafts.DraftError) as e:
        drafts.build(T, "nobody")
    assert e.value.status == 404


def test_simulate_replays_observed_calls():
    seen("lookup_invoice", n=5)
    seen("refund_payment", n=4)
    seen("delete_account", outcome="blocked", n=2)
    d = build()
    sim = drafts.simulate(d, observe.read(T, AGENT))
    assert sim["accepted"]["totals"] == {"allowed": 0, "held": 0, "blocked": 11}
    assert sim["proposed"]["totals"] == {"allowed": 5, "held": 4, "blocked": 2}
    for i in d["items"]:
        if i["id"] == "tool:lookup_invoice":
            i["status"] = "accepted"
    assert drafts.simulate(d, observe.read(T, AGENT))["accepted"]["totals"]["allowed"] == 5


# ── routes ───────────────────────────────────────────────────────────


@pytest.fixture
def client():
    import api.routes_agent_policy_draft as r
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = T
        return await call_next(request)
    app.include_router(r.router)
    return TestClient(app)


def test_the_routes_build_read_and_simulate(client):
    seen("lookup_invoice", n=3)
    seen("refund_payment", n=4)
    observe.flush()
    obs = client.get(f"/v1/tenant/me/agents/{AGENT}/policy/observations").json()
    assert obs["tools"] == 2 and obs["calls"] == 7
    assert client.get(f"/v1/tenant/me/agents/{AGENT}/policy/draft").status_code == 404
    r = client.post(f"/v1/tenant/me/agents/{AGENT}/policy/draft", json={"use_model": False})
    assert r.status_code == 200 and {"tool:lookup_invoice", "tool:refund_payment"} <= set(items(r.json()))
    assert client.get(f"/v1/tenant/me/agents/{AGENT}/policy/draft").json()["id"] == r.json()["id"]
    sim = client.post(f"/v1/tenant/me/agents/{AGENT}/policy/draft/simulate").json()
    assert sim["proposed"]["totals"] == {"allowed": 3, "held": 4, "blocked": 0}


def test_the_routes_explain_why_a_draft_cannot_be_built(client):
    r = client.post("/v1/tenant/me/agents/nobody/policy/draft", json={"use_model": False})
    assert r.status_code == 404 and r.json()["detail"]["error"] == "no_agent"
