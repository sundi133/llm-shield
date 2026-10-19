"""Model routing, task 2: streaming through a route, target health (circuit
breaker), and the latency and weighted strategies.
Spec: docs/specs/gateway-routing-failover.md."""

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

from core.llm_gateway import config, dispatch, health, select
from tests.test_llm_gateway_routing import (  # noqa: F401  (fixtures)
    CHAT, Upstream, admin, app, setup_route, store, target, upstream)


@pytest.fixture(autouse=True)
def _health():
    health.reset_for_tests()
    yield
    health.reset_for_tests()


def sse(host, n=3):
    lines = []
    for i in range(n):
        lines.append("data: " + json.dumps({"id": "c1", "object": "chat.completion.chunk", "model": f"{host}-m",
                                            "choices": [{"index": 0, "delta": {"content": f"{host}-{i} "}}]}))
        lines.append("")
    lines += ["data: [DONE]", ""]
    return ("\n".join(lines) + "\n").encode()


class Broken(httpx.AsyncByteStream):
    """Sends one chunk, then the connection drops."""

    async def __aiter__(self):
        yield sse("a.test", 1).split(b"data: [DONE]")[0]
        raise httpx.ReadError("connection reset")


def stream_handler(plan):
    async def handler(request):
        host = request.url.host
        plan.setdefault("calls", []).append(host)
        r = plan.get(host, "ok")
        if r == "ok":
            return httpx.Response(200, content=sse(host), headers={"content-type": "text/event-stream"})
        if r == "slow":
            await asyncio.sleep(3)
            return httpx.Response(200, content=sse(host))
        if r == "broken":
            return httpx.Response(200, stream=Broken(), headers={"content-type": "text/event-stream"})
        return httpx.Response(r, json={"error": {"message": f"status {r}"}})
    return handler


def _stream(app, path="/v1/chat/completions"):
    with app.stream("POST", path, json={**CHAT, "stream": True}) as r:
        return r.status_code, dict(r.headers), r.read().decode()


# ── streaming ────────────────────────────────────────────────────────


def test_a_routed_stream_fails_over_before_the_first_byte(app, monkeypatch):
    plan = {"a.test": 503}
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(stream_handler(plan)))
    setup_route()
    status, headers, text = _stream(app)
    assert status == 200 and headers["x-shield-target"] == "b" and headers["x-shield-failovers"] == "1"
    assert "b.test-0" in text and "a.test" not in text and text.rstrip().endswith("data: [DONE]")
    assert plan["calls"] == ["a.test", "b.test"]


def test_a_slow_first_byte_fails_over(app, monkeypatch, store):
    plan = {"a.test": "slow"}
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(stream_handler(plan)))
    setup_route(targets=[target("a", "a.test", first_byte_timeout_s=1), target("b", "b.test")])
    status, headers, text = _stream(app, "/v1/shield/chat/completions")
    assert status == 200 and headers["x-shield-target"] == "b" and "b.test-0" in text


def test_a_stream_that_breaks_after_starting_does_not_fail_over(app, monkeypatch):
    plan = {"a.test": "broken"}
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(stream_handler(plan)))
    setup_route()
    status, headers, text = _stream(app)
    assert status == 200 and "a.test-0" in text and "ended early" in text
    assert plan["calls"] == ["a.test"] and text.rstrip().endswith("data: [DONE]")


def test_every_stream_target_failing_returns_an_error(app, monkeypatch):
    plan = {"a.test": 503, "b.test": 502, "c.test": 500}
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(stream_handler(plan)))
    setup_route()
    r = app.post("/v1/chat/completions", json={**CHAT, "stream": True})
    assert r.status_code == 502 and len(r.json()["x_shield"]["routing"]["attempts"]) == 3
    plan.update({"a.test": 401})
    plan["calls"] = []
    r = app.post("/v1/chat/completions", json={**CHAT, "stream": True})
    assert r.status_code == 401 and plan["calls"] == ["a.test"]


def test_the_stream_body_carries_the_target_model(app, monkeypatch):
    seen = []

    async def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, content=sse("a.test"))
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(handler))
    setup_route()
    _stream(app)
    assert seen[0]["model"] == "a-model" and seen[0]["stream"] is True


# ── health ───────────────────────────────────────────────────────────


def test_the_circuit_opens_half_opens_and_closes(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(health.time, "time", lambda: now[0])
    for _ in range(health.FAIL_THRESHOLD - 1):
        health.record("t1", "a", "5xx", 10)
    assert health.available("t1", "a")
    health.record("t1", "a", "timeout", 10)
    assert not health.available("t1", "a") and health.view("t1")["a"]["state"] == "open"
    now[0] += health.OPEN_S + 1
    assert health.available("t1", "a")                    # the probe
    assert not health.available("t1", "a")                # one at a time
    health.record("t1", "a", "connect", 10)                # probe failed: open again
    assert not health.available("t1", "a")
    now[0] += health.OPEN_S + 1
    assert health.available("t1", "a")
    health.record("t1", "a", "ok", 120)
    assert health.view("t1")["a"]["state"] == "closed" and health.available("t1", "a")


def test_a_client_error_is_not_a_target_failure():
    for _ in range(10):
        health.record("t1", "a", "4xx", 5)
    assert health.available("t1", "a")


def test_failures_outside_the_window_do_not_count(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(health.time, "time", lambda: now[0])
    for _ in range(health.FAIL_THRESHOLD - 1):
        health.record("t1", "a", "5xx", 1)
    now[0] += health.WINDOW_S + 1
    health.record("t1", "a", "5xx", 1)
    assert health.available("t1", "a")


def test_an_open_target_is_skipped_and_the_route_moves_on(app, upstream):
    setup_route()
    for _ in range(health.FAIL_THRESHOLD):
        health.record("t1", "a", "5xx", 1)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["target"] == "b" and [c["host"] for c in upstream.calls] == ["b.test"]


def test_all_targets_open_refuses(app, upstream):
    setup_route()
    for tid in "abc":
        for _ in range(health.FAIL_THRESHOLD):
            health.record("t1", tid, "5xx", 1)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["choices"][0]["finish_reason"] == "content_filter" and upstream.calls == []
    assert r.json()["x_shield"]["routing"]["code"] == "no_target"


def test_repeated_failures_through_the_proxy_open_the_circuit(app, upstream):
    setup_route()
    upstream.set("a.test", (503, {}))
    for _ in range(health.FAIL_THRESHOLD):
        app.post("/v1/chat/completions", json=CHAT)
    upstream.calls.clear()
    r = app.post("/v1/chat/completions", json=CHAT)
    assert [c["host"] for c in upstream.calls] == ["b.test"] and r.json()["x_shield"]["routing"]["target"] == "b"


def test_target_down_alerts_are_throttled(monkeypatch):
    import core.feature_flags as ff
    import core.webhook_dispatcher as wd
    sent = []

    async def fake(tenant, event, payload):
        sent.append((tenant, event, payload["target"]))
    monkeypatch.setattr(wd, "dispatch_event", fake)
    monkeypatch.setattr(ff, "WEBHOOKS_ENABLED", True)

    async def run():
        for _ in range(3):
            for _ in range(health.FAIL_THRESHOLD):
                health.record("t1", "a", "5xx", 1)
            with health._lock:
                health._state[("t1", "a")]["opened_at"] = None      # closes, then fails again
        await asyncio.sleep(0)
    asyncio.run(run())
    assert sent == [("t1", "gateway_target_down", "a")]
    from api.routes_webhooks import VALID_EVENTS
    assert "gateway_target_down" in VALID_EVENTS


def test_health_is_flushed_for_the_portal(store, admin):
    health.record("t1", "a", "ok", 80)
    for _ in range(health.FAIL_THRESHOLD):
        health.record("t1", "b", "timeout", 1)
    assert health.flush() == 2
    rows = admin.get("/v1/tenant/me/gateway/health").json()["targets"]
    by = {r["target"]: r for r in rows}
    assert by["a"]["state"] == "closed" and by["a"]["latency_ms"] == 80.0
    assert by["b"]["state"] == "open" and by["b"]["last_error"] == "timeout" and by["b"]["process"]


# ── strategies ───────────────────────────────────────────────────────


def _plan(route_kw, rng=None):
    tmap = {t: {"id": t, "enabled": True, "model": "m", "base_url": "https://x/v1"} for t in "abc"}
    route = config.validate_route("r", {"targets": ["a", "b", "c"], **route_kw}, tmap)
    snap = config.Snapshot(tmap, {"r": route})
    p = select.plan(snap, route, select.CallContext("t1"), **({"rng": rng} if rng else {}))
    return [t["id"] for t in p.targets]


def test_lowest_latency_measures_new_targets_first():
    health.record("t1", "a", "ok", 900)
    health.record("t1", "b", "ok", 100)
    assert _plan({"strategy": "lowest_latency"}) == ["c", "b", "a"]
    health.record("t1", "c", "ok", 500)
    assert _plan({"strategy": "lowest_latency"}) == ["b", "c", "a"]


def test_weighted_follows_the_weights_and_keeps_zero_weight_targets_as_fallback():
    import random
    rng = random.Random(7).random
    firsts = {"a": 0, "b": 0}
    for _ in range(4000):
        order = _plan({"strategy": "weighted", "weights": {"a": 80, "b": 20}}, rng=rng)
        assert order[-1] == "c" and set(order) == {"a", "b", "c"}
        firsts[order[0]] += 1
    assert 0.75 < firsts["a"] / 4000 < 0.85


def test_strategies_never_add_a_target():
    tmap = {t: {"id": t, "enabled": True, "model": "m", "base_url": "https://x/v1",
                "price": {"input_per_mtok": i, "output_per_mtok": i}} for i, t in enumerate("abcd")}
    for strategy in config.STRATEGIES:
        kw = {"weights": {"b": 1}} if strategy == "weighted" else {}
        route = config.validate_route("r", {"targets": ["b", "c"], "strategy": strategy, **kw}, tmap)
        p = select.plan(config.Snapshot(tmap, {"r": route}), route, select.CallContext("t1"))
        assert {t["id"] for t in p.targets} <= {"b", "c"}
