"""Model routing and failover, task 1: targets, routes, priority failover on
both proxy endpoints, credentials, egress checks, admin routes.
Spec: docs/specs/gateway-routing-failover.md."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from core.llm_gateway import config, dispatch, select
from core.models import GuardrailResult, PipelineResult


# ── fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def store(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    ts._fallback_store.clear()
    config.reset_for_tests()
    yield ts
    ts._fallback_store.clear()
    config.reset_for_tests()


class Upstream:
    """A fake provider per host: a list of responses (status, body) or
    exceptions, consumed in order; the last one repeats."""

    def __init__(self):
        self.plan, self.calls = {}, []

    def set(self, host, *responses):
        self.plan[host] = list(responses)

    def handler(self, request: httpx.Request):
        host = request.url.host
        self.calls.append({"host": host, "url": str(request.url), "headers": dict(request.headers),
                           "body": json.loads(request.content or b"{}")})
        seq = self.plan.get(host) or [(200, None)]
        r = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(r, Exception):
            raise r
        status, body = r
        if body is None:
            body = {"id": "x", "object": "chat.completion", "model": "m",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": f"hi from {host}"},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
        return httpx.Response(status, json=body) if not isinstance(body, str) else httpx.Response(status, text=body)


@pytest.fixture
def upstream(monkeypatch):
    up = Upstream()
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(up.handler))

    async def no_check(url, allow_private):
        return None
    monkeypatch.setattr(dispatch, "_check_url", no_check)
    return up


async def _allow(*a, **k):
    return PipelineResult(allowed=True, results=[GuardrailResult(passed=True, action="pass",
                                                                 guardrail_name="pii_detection")])


async def _allow_flagged(*a, **k):
    return PipelineResult(allowed=True, results=[GuardrailResult(passed=False, action="warn",
                                                                 guardrail_name="pii_detection")])


@pytest.fixture
def app(store, upstream, monkeypatch):
    import api.routes_gateway as rg
    import api.routes_openai_compat as ro
    for mod in (rg, ro):
        monkeypatch.setattr(mod, "run_proxy_input_pipeline", _allow)
        monkeypatch.setattr(mod, "run_proxy_output_pipeline", _allow)
        monkeypatch.setattr(mod.audit_logger, "log", AsyncMock())
    a = FastAPI()

    @a.middleware("http")
    async def state(request: Request, call_next):
        request.state.tenant_id = request.headers.get("x-test-tenant", "t1")
        request.state.tenant_config = None
        request.state.agent_key = request.headers.get("x-test-agent")
        request.state.role_name = request.headers.get("x-test-role")
        request.state.role = None
        return await call_next(request)
    a.include_router(ro.router)
    a.include_router(rg.router)
    return TestClient(a)


def target(tid, host, **kw):
    return config.validate_target(tid, {"base_url": f"https://{host}/v1", "model": kw.pop("model", f"{tid}-model"),
                                        **kw})


def setup_route(tenant="t1", targets=None, **route):
    targets = targets or [target("a", "a.test"), target("b", "b.test"), target("c", "c.test")]
    for t in targets:
        config.save_target(tenant, t)
    tmap, _ = config.load(tenant)
    config.save_route(tenant, config.validate_route(route.pop("name", "smart"),
                                                    {"targets": [t["id"] for t in targets], **route}, tmap))


CHAT = {"model": "smart", "messages": [{"role": "user", "content": "hello"}]}


# ── validation ───────────────────────────────────────────────────────


def test_target_validation():
    t = target("openai-4o", "api.openai.com", model="gpt-4o")
    assert t["auth"] == {"mode": "none", "header": "Authorization", "scheme": "Bearer", "secret_ref": ""}
    assert config.target_url(t) == "https://api.openai.com/v1/chat/completions"
    az = config.validate_target("az", {"base_url": "https://x.openai.azure.com", "flavor": "azure", "model": "gpt-4o",
                                       "azure": {"deployment": "prod", "api_version": "2024-10-21"},
                                       "auth": {"mode": "passthrough"}})
    assert config.target_url(az) == ("https://x.openai.azure.com/openai/deployments/prod/chat/completions"
                                     "?api-version=2024-10-21")
    assert az["auth"]["header"] == "api-key" and az["auth"]["scheme"] == ""
    bad = [("bad id!", {"base_url": "https://x/v1", "model": "m"}),
           ("x", {"base_url": "ftp://x", "model": "m"}),
           ("x", {"base_url": "https://x/v1"}),
           ("x", {"base_url": "https://x/v1", "model": "m", "auth": {"mode": "vault"}}),
           ("x", {"base_url": "https://x/v1", "model": "m", "auth": {"mode": "none", "secret_ref": "shield://k"}}),
           ("x", {"base_url": "https://x/v1", "model": "m", "flavor": "azure"}),
           ("x", {"base_url": "https://x/v1", "model": "m", "timeout_s": 0}),
           ("x", {"base_url": "https://x/v1", "model": "m", "surprise": 1})]
    for tid, raw in bad:
        with pytest.raises(config.ConfigError):
            config.validate_target(tid, raw)
    with pytest.raises(config.ConfigError) as e:
        config.validate_target("x", {"base_url": "https://10.0.0.5/v1", "model": "m"},
                               check_url=lambda u, p: (_ for _ in ()).throw(ValueError("private address")))
    assert "private address" in str(e.value)


def test_route_validation():
    tmap = {"a": {}, "b": {}}
    r = config.validate_route("smart", {"targets": ["a", "b"]}, tmap)
    assert r["strategy"] == "priority" and r["failover"] == {"max_attempts": 3, "deadline_s": 120,
                                                             "on": ["timeout", "connect", "429", "5xx"]}
    for raw in ({"targets": ["a", "zz"]}, {"targets": []}, {"targets": ["a"], "strategy": "random"},
                {"targets": ["a"], "rules": [{"when": {"role": ["x"]}, "use": ["b"]}]},
                {"targets": ["a"], "rules": [{"when": {"role": ["x"]}}]},
                {"targets": ["a"], "rules": [{"when": {}, "deny": "no"}]},
                {"targets": ["a"], "strategy": "weighted"},
                {"targets": ["a"], "budget": {"monthly": 5, "at_limit": "fallback"}},
                {"targets": ["a"], "failover": {"on": ["4xx"]}}):
        with pytest.raises(config.ConfigError):
            config.validate_route("smart", raw, tmap)
    with pytest.raises(config.ConfigError):
        config.validate_route("bad name!", {"targets": ["a"]}, tmap)


def test_store_limits_and_delete_rules(store):
    setup_route()
    with pytest.raises(config.ConfigError) as e:
        config.delete_target("t1", "a")
    assert e.value.status == 409
    assert config.delete_route("t1", "smart") and config.delete_target("t1", "a")
    assert not config.delete_target("t1", "a")


# ── the proxy ────────────────────────────────────────────────────────


def test_no_route_takes_the_default_path(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro
    called = {}

    async def default_llm(**kw):
        called["yes"] = True
        return {"choices": [{"message": {"content": "default"}}], "usage": {}}
    monkeypatch.setattr(ro, "async_llm_call", default_llm)
    monkeypatch.setattr(ro, "_get_upstream_url", lambda: None)
    r = app.post("/v1/chat/completions", json={**CHAT, "model": "gpt-4o"})
    assert r.status_code == 200 and called and "X-Shield-Route" not in r.headers
    assert "routing" not in r.json()["x_shield"] and upstream.calls == []


def test_a_route_sends_the_target_model_and_reports_the_route(app, upstream):
    setup_route()
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "a-model" and body["choices"][0]["message"]["content"] == "hi from a.test"
    assert body["x_shield"]["routing"]["target"] == "a" and r.headers["X-Shield-Route"] == "smart"
    assert r.headers["X-Shield-Target"] == "a" and r.headers["X-Shield-Failovers"] == "0"
    sent = upstream.calls[0]
    assert sent["url"] == "https://a.test/v1/chat/completions" and sent["body"]["model"] == "a-model"
    assert sent["body"]["messages"] == CHAT["messages"]                     # the client's own messages


@pytest.mark.parametrize("failure", [(503, {"error": "down"}), (429, {"error": "slow down"}), (500, "oops"),
                                     httpx.ConnectError("refused"), httpx.ReadTimeout("slow")])
def test_failover_on_retryable_errors(app, upstream, failure):
    setup_route()
    upstream.set("a.test", failure)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 200 and r.json()["x_shield"]["routing"]["target"] == "b"
    assert r.headers["X-Shield-Failovers"] == "1"
    attempts = r.json()["x_shield"]["routing"]["attempts"]
    assert [a["target"] for a in attempts] == ["a", "b"] and attempts[1]["outcome"] == "ok"


def test_a_client_error_does_not_fail_over(app, upstream):
    setup_route()
    upstream.set("a.test", (400, {"error": {"message": "bad tool schema", "type": "invalid_request_error"}}))
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 400 and r.json()["error"]["message"] == "bad tool schema"
    assert [c["host"] for c in upstream.calls] == ["a.test"]


def test_every_target_failing_never_leaves_the_route(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro
    monkeypatch.setattr(ro, "async_llm_call", AsyncMock(side_effect=AssertionError("default upstream used")))
    setup_route()
    for h in ("a.test", "b.test", "c.test"):
        upstream.set(h, (503, {"error": "down"}))
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error"
    assert [a["target"] for a in r.json()["x_shield"]["routing"]["attempts"]] == ["a", "b", "c"]


def test_max_attempts_and_failover_on(app, upstream):
    setup_route(failover={"max_attempts": 2, "on": ["5xx"]})
    for h in ("a.test", "b.test"):
        upstream.set(h, (503, {}))
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 502 and [c["host"] for c in upstream.calls] == ["a.test", "b.test"]
    upstream.calls.clear()
    upstream.set("a.test", (429, {}))
    r = app.post("/v1/chat/completions", json=CHAT)                         # 429 not in "on"
    assert r.status_code == 502 and [c["host"] for c in upstream.calls] == ["a.test"]


def test_disabled_and_missing_targets_are_skipped(app, upstream, store):
    setup_route()
    t = config.load("t1")[0]["a"]
    config.save_target("t1", {**t, "enabled": False})
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["target"] == "b"


def test_output_guardrails_run_on_the_answer_that_came_back(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro
    seen = []

    async def out(content, context, tenant_config=None):
        seen.append(content)
        return PipelineResult(allowed=False, results=[GuardrailResult(passed=False, action="block",
                                                                      guardrail_name="pii_leakage", message="ssn")])
    monkeypatch.setattr(ro, "run_proxy_output_pipeline", out)
    setup_route()
    upstream.set("a.test", (503, {}))
    r = app.post("/v1/chat/completions", json=CHAT)
    assert seen == ["hi from b.test"]                                         # once, on the answer used
    assert r.json()["choices"][0]["finish_reason"] == "content_filter"
    assert r.json()["x_shield"]["routing"]["target"] == "b"
    assert [c["host"] for c in upstream.calls] == ["a.test", "b.test"]        # no retry to find a passing model


def test_input_block_never_reaches_a_target(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro

    async def block(*a, **k):
        return PipelineResult(allowed=False, results=[GuardrailResult(passed=False, action="block",
                                                                      guardrail_name="adversarial", message="no")])
    monkeypatch.setattr(ro, "run_proxy_input_pipeline", block)
    setup_route()
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["choices"][0]["finish_reason"] == "content_filter" and upstream.calls == []


def test_the_legacy_endpoint_routes_too(app, upstream):
    setup_route()
    upstream.set("a.test", httpx.ConnectError("x"))
    r = app.post("/v1/shield/chat/completions", json=CHAT)
    assert r.status_code == 200 and r.json()["text"] == "hi from b.test"
    assert r.json()["routing"]["target"] == "b" and r.headers["X-Shield-Failovers"] == "1"
    for h in ("a.test", "b.test", "c.test"):
        upstream.set(h, (503, {}))
    r = app.post("/v1/shield/chat/completions", json=CHAT)
    assert r.status_code == 502 and len(r.json()["routing"]["attempts"]) == 3


def test_tenants_do_not_see_each_others_routes(app, upstream, monkeypatch):
    import api.routes_gateway as rg
    monkeypatch.setattr(rg, "async_llm_call", AsyncMock(return_value={"choices": [{"message": {"content": "d"}}]}))
    monkeypatch.setattr(rg, "_get_upstream_url", lambda: None)
    setup_route("t1")
    r = app.post("/v1/shield/chat/completions", json=CHAT, headers={"x-test-tenant": "t2"})
    assert "routing" not in r.json()


def test_kill_switch_ignores_routes(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro
    monkeypatch.setattr(ro, "async_llm_call", AsyncMock(return_value={"choices": [{"message": {"content": "d"}}]}))
    monkeypatch.setattr(ro, "_get_upstream_url", lambda: None)
    setup_route()
    monkeypatch.setenv("SHIELD_LLM_ROUTING", "0")
    r = app.post("/v1/chat/completions", json=CHAT)
    assert "routing" not in r.json()["x_shield"] and upstream.calls == []


def test_a_routed_stream_never_goes_to_the_default_upstream(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro
    monkeypatch.setattr(ro, "_stream_chat_completion", AsyncMock(side_effect=AssertionError("default stream")))
    setup_route()
    r = app.post("/v1/chat/completions", json={**CHAT, "stream": True})
    assert r.status_code in (200, 400) and "default stream" not in r.text


# ── what is sent ─────────────────────────────────────────────────────


def test_upstream_body_drops_shield_fields_and_sets_the_model():
    t = target("a", "a.test", model="gpt-4o")
    b = dispatch.upstream_body({"model": "smart", "messages": [1], "temperature": 0.2, "x_shield": {}, "system": "s"},
                               [2], t)
    assert b == {"model": "gpt-4o", "messages": [1], "temperature": 0.2}
    assert dispatch.upstream_body({"model": "smart", "prompt": "hi"}, [{"role": "user", "content": "hi"}], t) == \
        {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}


def test_passthrough_key_goes_only_to_passthrough_targets(app, upstream):
    setup_route(targets=[target("a", "a.test", auth={"mode": "passthrough"}), target("b", "b.test")])
    upstream.set("a.test", (503, {}))
    r = app.post("/v1/chat/completions", json=CHAT, headers={"X-Shield-Upstream-Key": "caller-key-123"})
    assert r.status_code == 200
    a, b = upstream.calls
    assert a["headers"]["authorization"] == "Bearer caller-key-123"
    assert "authorization" not in b["headers"] and "caller-key-123" not in json.dumps(b)


def test_passthrough_without_the_header_skips_the_target(app, upstream):
    setup_route(targets=[target("a", "a.test", auth={"mode": "passthrough"}), target("b", "b.test")])
    r = app.post("/v1/chat/completions", json=CHAT)
    att = r.json()["x_shield"]["routing"]["attempts"]
    assert att[0] == {**att[0], "target": "a", "outcome": "credential_unavailable"}
    assert [c["host"] for c in upstream.calls] == ["b.test"]


def test_vault_key_is_materialized_only_for_its_bound_host(store, monkeypatch):
    import core.secret_vault.materialize as mat
    t = target("a", "a.test", auth={"mode": "vault", "secret_ref": "shield://openai_prod"})

    def fake(tenant, headers, destination):
        if "a.test" in destination:
            return {k: v.replace("shield://openai_prod", "sk-real") for k, v in headers.items()}, []
        return headers, list(headers)
    monkeypatch.setattr(mat, "materialize_headers", fake)
    assert dispatch.headers_for("t1", t, {})["Authorization"] == "Bearer sk-real"
    other = target("b", "b.test", auth={"mode": "vault", "secret_ref": "shield://openai_prod"})
    with pytest.raises(dispatch.CredentialUnavailable):
        dispatch.headers_for("t1", other, {})


def test_unsafe_urls_are_skipped_at_call_time(store, monkeypatch):
    up = Upstream()
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(up.handler))
    dispatch._url_ok.clear()
    import core.url_safety as us

    def check(url, **kw):
        if "a.test" in url:
            raise us.UnsafeURLError("resolves to a private address")
    monkeypatch.setattr(us, "validate_outbound_url", check)
    setup_route()
    snap = config.Snapshot(*config.load("t1"))
    p = select.plan(snap, snap.routes["smart"], select.CallContext("t1"))
    data, info = asyncio.run(dispatch.complete("t1", p, CHAT, CHAT["messages"], {}))
    assert info["target"] == "b" and info["attempts"][0]["outcome"] == "unsafe_url"
    assert [c["host"] for c in up.calls] == ["b.test"]


def test_the_deadline_bounds_the_whole_call(store, upstream):
    setup_route(failover={"deadline_s": 1, "max_attempts": 5})
    upstream.set("a.test", httpx.ReadTimeout("slow"))
    snap = config.Snapshot(*config.load("t1"))
    p = select.plan(snap, snap.routes["smart"], select.CallContext("t1"))
    t = config.load("t1")[0]
    assert p.targets[0]["timeout_s"] == 60
    data, info = asyncio.run(dispatch.complete("t1", p, CHAT, CHAT["messages"], {}))
    assert info["target"] == "b"


# ── the cache ────────────────────────────────────────────────────────


def test_the_cache_serves_without_reading_the_store(store, monkeypatch):
    setup_route()
    snap = asyncio.run(config.cached("t1"))
    assert "smart" in snap.routes
    monkeypatch.setattr(config, "load", lambda t: (_ for _ in ()).throw(AssertionError("store read")))
    assert asyncio.run(config.cached("t1")) is snap                             # fresh: no read
    assert asyncio.run(config.cached("")) is None


def test_a_cold_cache_with_the_store_down_takes_the_default_path(store, monkeypatch):
    monkeypatch.setattr(config, "load", lambda t: (_ for _ in ()).throw(ConnectionError("down")))
    assert asyncio.run(config.cached("t9")) is None


def test_a_matched_route_that_cannot_be_planned_refuses(app, upstream, monkeypatch):
    setup_route()
    monkeypatch.setattr(select, "plan", lambda *a: (_ for _ in ()).throw(RuntimeError("bug")))
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["choices"][0]["finish_reason"] == "content_filter" and upstream.calls == []


def test_routing_overhead_is_small(store):
    import time
    setup_route()
    snap = asyncio.run(config.cached("t1"))
    route = select.match_route(snap, "smart")
    ctx = select.CallContext("t1", flagged=("pii_detection",), prompt_chars=2000)
    n = 2000
    t0 = time.perf_counter()
    for _ in range(n):
        select.plan(snap, route, ctx)
    assert (time.perf_counter() - t0) / n < 0.001


# ── admin routes ─────────────────────────────────────────────────────


@pytest.fixture
def admin(store, monkeypatch):
    import api.routes_llm_gateway_admin as ra
    calls = []
    monkeypatch.setattr(ra, "get_tenant_from_request", lambda r: "t1")
    monkeypatch.setattr(ra, "require_config_write", lambda r, t, what: calls.append(("config", what)))
    import core.auth as auth
    monkeypatch.setattr(auth, "require_registry_write", lambda r, t, what: calls.append(("registry", what)))
    import storage.admin_audit as aa
    audits = []
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: audits.append(k))
    monkeypatch.setattr(dispatch, "check_url_sync", lambda u, p: None)
    a = FastAPI()
    a.include_router(ra.router)
    c = TestClient(a)
    c.calls, c.audits = calls, audits
    return c


def test_admin_crud_and_gates(admin):
    r = admin.put("/v1/tenant/me/gateway/targets/a", json={"base_url": "https://a.test/v1", "model": "gpt-4o"})
    assert r.status_code == 200 and admin.calls == [("config", "change a model routing target")]
    admin.put("/v1/tenant/me/gateway/targets/b", json={"base_url": "https://10.0.0.5/v1", "model": "qwen",
                                                       "allow_private": True, "location": "on_prem"})
    assert ("registry", "let a model target reach a private address") in admin.calls
    r = admin.put("/v1/tenant/me/gateway/routes/team/smart", json={"targets": ["a", "b"]})
    assert r.status_code == 200 and r.json()["name"] == "team/smart"
    assert admin.get("/v1/tenant/me/gateway/routes/team/smart").json()["targets"] == ["a", "b"]
    assert [t["routes"] for t in admin.get("/v1/tenant/me/gateway/targets").json()["targets"]] == \
        [["team/smart"], ["team/smart"]]
    assert admin.delete("/v1/tenant/me/gateway/targets/a").status_code == 409
    r = admin.put("/v1/tenant/me/gateway/routes/x", json={"targets": ["nope"]})
    assert r.status_code == 422 and "no target nope" in json.dumps(r.json())
    assert admin.delete("/v1/tenant/me/gateway/routes/team/smart").status_code == 200
    assert admin.delete("/v1/tenant/me/gateway/targets/a").status_code == 200
    assert {a["action"] for a in admin.audits} >= {"gateway_target_set", "gateway_route_set",
                                                   "gateway_route_deleted", "gateway_target_deleted"}


def test_vault_targets_must_be_bound_to_their_host(admin, monkeypatch):
    import core.secret_vault.keyprovider as kp
    import storage.vault_store as vs
    monkeypatch.setattr(kp, "vault_enabled", lambda: True)
    monkeypatch.setattr(vs, "resolve_binding",
                        lambda t, ref: ("sk-real", ["api.openai.com"], []) if ref == "openai_prod" else None)
    ok = {"base_url": "https://api.openai.com/v1", "model": "gpt-4o",
          "auth": {"mode": "vault", "secret_ref": "shield://openai_prod"}}
    r = admin.put("/v1/tenant/me/gateway/targets/a", json=ok)
    assert r.status_code == 200 and "sk-real" not in r.text
    assert r.json()["auth"]["secret_ref"] == "shield://openai_prod"
    r = admin.put("/v1/tenant/me/gateway/targets/b", json={**ok, "base_url": "https://evil.test/v1"})
    assert r.status_code == 422 and "not bound" in r.text
    r = admin.put("/v1/tenant/me/gateway/targets/c", json={**ok, "auth": {"mode": "vault", "secret_ref": "shield://nope"}})
    assert r.status_code == 422 and "no vault secret" in r.text
    monkeypatch.setattr(kp, "vault_enabled", lambda: False)
    assert admin.put("/v1/tenant/me/gateway/targets/d", json=ok).status_code == 422


def test_simulate_calls_no_model(admin, upstream):
    admin.put("/v1/tenant/me/gateway/targets/a", json={"base_url": "https://a.test/v1", "model": "m"})
    admin.put("/v1/tenant/me/gateway/targets/b", json={"base_url": "https://b.test/v1", "model": "m", "enabled": False})
    admin.put("/v1/tenant/me/gateway/routes/smart", json={"targets": ["b", "a"]})
    r = admin.post("/v1/tenant/me/gateway/routes/smart/simulate", json={"messages": [{"role": "user", "content": "x"}]})
    assert r.json() == {"route": "smart", "outcome": "routed", "order": ["a"], "rule": "", "budget": "ok",
                        "skipped": [{"target": "b", "reason": "disabled"}]}
    assert upstream.calls == []
    assert admin.post("/v1/tenant/me/gateway/routes/nope/simulate", json={}).status_code == 404


def test_admin_router_is_mounted_and_in_the_admin_image():
    import admin_app
    from tests.route_tables import flat_routes
    paths = {path for path, _ in flat_routes(admin_app.app)}
    assert "/v1/tenant/me/gateway/targets/{target_id}" in paths
    df = open("Dockerfile.admin").read()
    assert "COPY core/llm_gateway/ core/llm_gateway/" in df and "COPY api/routes_llm_gateway_admin.py api/" in df
