"""Model routing, task 4: usage, cost, monthly spend, budgets and the
budget_exceeded webhook. Spec: docs/specs/gateway-routing-failover.md, 3.3."""

import asyncio
import json
import time

import httpx
import pytest

from core.llm_gateway import config, dispatch, select, usage
from tests.test_llm_gateway_routing import (  # noqa: F401  (fixtures)
    CHAT, admin, app, setup_route, store, target, upstream)
from tests.test_llm_gateway_streaming_health import sse  # noqa: E402

PRICED = dict(price={"input_per_mtok": 2.0, "output_per_mtok": 10.0})


def priced_targets():
    return [target("a", "a.test", **PRICED), target("b", "b.test", price={"input_per_mtok": 0.5, "output_per_mtok": 1.0}),
            target("c", "c.test")]


def wait_for(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_cost_of():
    assert usage.cost_of({"price": {"input_per_mtok": 2.0, "output_per_mtok": 10.0}}, 1_000_000, 500_000) == 7.0
    assert usage.cost_of({}, 1000, 1000) == 0.0


def test_calls_are_counted_per_target_with_cost_and_failovers(app, upstream, store):
    setup_route(targets=priced_targets())
    upstream.set("a.test", (503, {}))
    r = app.post("/v1/chat/completions", json=CHAT)
    routing = r.json()["x_shield"]["routing"]
    assert routing["target"] == "b" and routing["cost"] == pytest.approx((10 * 0.5 + 5 * 1.0) / 1e6)
    usage.flush()
    rows = {(x["route"], x["target"]): x for x in usage.read("t1")}
    a, b = rows[("smart", "a")], rows[("smart", "b")]
    assert (a["calls"], a["errors"], a["failovers_from"]) == (1, 1, 1)
    assert (b["calls"], b["ok"], b["input_tokens"], b["output_tokens"]) == (1, 1, 10, 5)
    assert usage.month_spend("t1")["smart"] == pytest.approx(10e-6)


def test_flushes_add_rather_than_overwrite(store):
    for _ in range(2):
        usage.record("t1", "r", [{"target": "a", "outcome": "ok", "ms": 10}], {"a": {**PRICED}}, final="a",
                     usage={"prompt_tokens": 1_000_000, "completion_tokens": 0})
        usage.flush()
    assert usage.stored_spend("t1")["r"] == pytest.approx(4.0)
    assert usage.read("t1")[0]["calls"] == 2


def test_a_stream_without_reported_usage_is_estimated(app, monkeypatch, store):
    async def handler(request):
        return httpx.Response(200, content=sse(request.url.host, 4))
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(handler))
    setup_route(targets=priced_targets())
    with app.stream("POST", "/v1/chat/completions", json={**CHAT, "messages": [
            {"role": "user", "content": "x" * 400}], "stream": True}) as r:
        r.read()
    usage.flush()
    row = [x for x in usage.read("t1") if x["target"] == "a"][0]
    assert row["estimated"] == 1 and row["input_tokens"] >= 100 and row["output_tokens"] > 0 and row["cost"] > 0


def _route_with_budget(at_limit, **extra):
    setup_route(targets=priced_targets(),
                budget={"monthly": 1.0, "at_limit": at_limit, **extra})


def _spend(amount):
    usage.record("t1", "smart", [{"target": "a", "outcome": "ok", "ms": 1}], {"a": {"price": {"input_per_mtok": 1}}},
                 final="a", usage={"prompt_tokens": int(amount * 1_000_000), "completion_tokens": 0})


def test_budget_warn_lets_calls_through_and_says_so(app, upstream, store):
    _route_with_budget("warn")
    _spend(1.5)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["target"] == "a" and r.headers["X-Shield-Budget"] == "warn"


def test_budget_fallback_narrows_to_the_fallback_targets(app, upstream, store):
    _route_with_budget("fallback", fallback_targets=["c"])
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["target"] == "a" and r.headers["X-Shield-Budget"] == "ok"
    _spend(1.0)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["target"] == "c" and r.headers["X-Shield-Budget"] == "fallback"


def test_budget_block_refuses_on_both_endpoints(app, upstream, store):
    _route_with_budget("block")
    _spend(2.0)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["choices"][0]["finish_reason"] == "content_filter"
    assert r.json()["x_shield"]["routing"]["code"] == "budget" and "budget" in r.json()["choices"][0]["message"]["content"]
    r = app.post("/v1/shield/chat/completions", json=CHAT)
    assert r.status_code == 403 and r.json()["routing"]["code"] == "budget"
    assert upstream.calls == []


def test_stored_spend_counts_toward_the_budget(app, upstream, store):
    _route_with_budget("block")
    _spend(2.0)
    usage.flush()
    config.reset_for_tests()                     # a fresh snapshot reads stored spend
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["code"] == "budget"


def test_budget_exceeded_fires_once_per_route_per_month(store, monkeypatch):
    import core.feature_flags as ff
    import core.webhook_dispatcher as wd
    sent = []

    async def fake(tenant, event, payload):
        sent.append((tenant, event, payload["route"], payload["at_limit"]))
    monkeypatch.setattr(wd, "dispatch_event", fake)
    monkeypatch.setattr(ff, "WEBHOOKS_ENABLED", True)
    budget = {"monthly": 1.0, "at_limit": "warn"}
    usage.maybe_alert_budget("t1", "smart", 1.2, budget)
    usage.maybe_alert_budget("t1", "smart", 1.3, budget)            # same process
    assert wait_for(lambda: len(sent) == 1)
    usage._alerted.clear()                                          # another process
    usage.maybe_alert_budget("t1", "smart", 1.4, budget)
    time.sleep(0.2)
    assert sent == [("t1", "budget_exceeded", "smart", "warn")]
    usage.maybe_alert_budget("t1", "other", 1.4, budget)
    assert wait_for(lambda: len(sent) == 2)


def test_lowest_cost_orders_by_price_and_unpriced_last():
    tmap = {t["id"]: t for t in priced_targets()}
    route = config.validate_route("r", {"targets": ["c", "a", "b"], "strategy": "lowest_cost"}, tmap)
    p = select.plan(config.Snapshot(tmap, {"r": route}), route, select.CallContext("t1"))
    assert [t["id"] for t in p.targets] == ["b", "a", "c"]


def test_usage_endpoint_reports_spend_and_missing_prices(admin, store):
    for t in priced_targets():
        config.save_target("t1", t)
    tmap, _ = config.load("t1")
    config.save_route("t1", config.validate_route("smart", {"targets": ["a", "c"], "budget": {"monthly": 5}}, tmap))
    usage.record("t1", "smart", [{"target": "a", "outcome": "ok", "ms": 12}], tmap, final="a",
                 usage={"prompt_tokens": 100, "completion_tokens": 50})
    usage.flush()
    out = admin.get("/v1/tenant/me/gateway/usage?days=3").json()
    assert out["rows"][0]["calls"] == 1 and out["rows"][0]["latency_ms_avg"] == 12.0
    b = out["budgets"][0]
    assert b["route"] == "smart" and b["monthly"] == 5 and b["spend"] == pytest.approx(0.0007, abs=1e-4)
    assert b["spend_incomplete"] is True and b["targets_without_price"] == ["c"]


def test_a_full_buffer_drops_and_counts(store, monkeypatch):
    monkeypatch.setattr(usage, "BUFFER_MAX", 2)
    monkeypatch.setattr(usage, "_last_flush", time.time())          # no background flush mid-test
    for i in range(5):
        usage.record("t1", "r", [{"target": f"t{i}", "outcome": "ok", "ms": 1}], {})
    assert len(usage._buf) == 2 and usage._dropped == 3
    usage.flush()
    assert usage._dropped == 0
