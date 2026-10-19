"""Model routing, task 3: rules (data sensitivity, data class, agent, role,
prompt size, location, deny) and the narrowing invariant.
Spec: docs/specs/gateway-routing-failover.md, section 3.2."""

import asyncio
import random

import httpx
import pytest

from core.llm_gateway import config, dispatch, health, select
from tests.test_llm_gateway_routing import (  # noqa: F401  (fixtures)
    CHAT, _allow_flagged, app, setup_route, store, target, upstream)


def targets3():
    return [target("cloud", "cloud.test"), target("azure", "azure.test"),
            target("onprem", "onprem.test", location="on_prem")]


RULES = [
    {"when": {"flagged": ["pii_detection", "secrets_detection"]}, "use": ["onprem"], "note": "PII stays on-prem"},
    {"when": {"data_class": ["restricted"]}, "use": ["onprem"]},
    {"when": {"role": ["contractor"]}, "deny": "Contractors cannot use this model"},
    {"when": {"agent": ["batch-bot"], "prompt_tokens_over": 1000}, "use": ["azure"]},
]


def _ctx(**kw):
    return select.CallContext("t1", **kw)


def _plan(rules=RULES, **ctx):
    tmap = {t["id"]: t for t in targets3()}
    route = config.validate_route("smart", {"targets": ["cloud", "azure", "onprem"], "rules": rules}, tmap)
    return select.plan(config.Snapshot(tmap, {"smart": route}), route, _ctx(**ctx))


def ids(p):
    return [t["id"] for t in p.targets]


def test_no_rule_matches_uses_the_route():
    assert ids(_plan()) == ["cloud", "azure", "onprem"]


def test_flagged_input_goes_on_prem():
    p = _plan(flagged=("pii_detection",))
    assert ids(p) == ["onprem"] and p.rule == "rules[0]: PII stays on-prem"
    assert ids(_plan(flagged=("toxicity",))) == ["cloud", "azure", "onprem"]


def test_data_class_role_agent_and_size():
    assert ids(_plan(data_class="restricted")) == ["onprem"]
    assert ids(_plan(data_class="public")) == ["cloud", "azure", "onprem"]
    p = _plan(role="contractor")
    assert isinstance(p, select.Refusal) and p.code == "deny" and "Contractors" in p.reason
    assert ids(_plan(agent="batch-bot", prompt_chars=8000)) == ["azure"]
    assert ids(_plan(agent="batch-bot", prompt_chars=400)) == ["cloud", "azure", "onprem"]   # both must hold
    assert ids(_plan(agent="other", prompt_chars=8000)) == ["cloud", "azure", "onprem"]


def test_the_first_matching_rule_wins():
    p = _plan(flagged=("pii_detection",), role="contractor")
    assert ids(p) == ["onprem"]                                   # rule 0 before the deny


def test_location_required_narrows_a_matched_rule():
    rules = [{"when": {"data_class": ["internal"], "location_required": "on_prem"}, "use": ["cloud", "onprem"]}]
    assert ids(_plan(rules, data_class="internal")) == ["onprem"]
    rules = [{"when": {"location_required": "on_prem"}, "use": ["cloud", "azure", "onprem"]}]
    assert ids(_plan(rules)) == ["onprem"]                        # alone, it always applies


def test_a_rule_whose_targets_are_down_refuses_rather_than_widening():
    health.reset_for_tests()
    for _ in range(health.FAIL_THRESHOLD):
        health.record("t1", "onprem", "5xx", 1)
    try:
        p = _plan(flagged=("pii_detection",))
        assert isinstance(p, select.Refusal) and p.code == "no_target" and "rules[0]" in p.reason
    finally:
        health.reset_for_tests()


def test_rules_may_only_name_the_routes_targets():
    tmap = {t["id"]: t for t in targets3()}
    with pytest.raises(config.ConfigError) as e:
        config.validate_route("r", {"targets": ["cloud"], "rules": [{"when": {"role": ["x"]}, "use": ["onprem"]}]},
                              tmap)
    assert "rules only narrow" in str(e.value)


# ── through the proxy ────────────────────────────────────────────────


def test_pii_flagged_prompt_goes_only_on_prem_even_when_it_fails(app, upstream, monkeypatch):
    import api.routes_openai_compat as ro
    monkeypatch.setattr(ro, "run_proxy_input_pipeline", _allow_flagged)
    setup_route(targets=targets3(), rules=RULES)
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.json()["x_shield"]["routing"]["target"] == "onprem"
    assert r.json()["x_shield"]["routing"]["rule"].startswith("rules[0]")
    upstream.calls.clear()
    upstream.set("onprem.test", (503, {}))
    r = app.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 502 and [c["host"] for c in upstream.calls] == ["onprem.test"]


def test_the_data_class_header_selects_a_rule(app, upstream):
    setup_route(targets=targets3(), rules=RULES)
    r = app.post("/v1/shield/chat/completions", json=CHAT, headers={"X-Shield-Data-Class": "Restricted"})
    assert r.json()["routing"]["target"] == "onprem"


def test_a_deny_rule_refuses_on_both_endpoints(app, upstream):
    setup_route(targets=targets3(), rules=RULES)
    h = {"x-test-role": "contractor"}
    r = app.post("/v1/chat/completions", json=CHAT, headers=h)
    assert r.status_code == 200 and r.json()["choices"][0]["finish_reason"] == "content_filter"
    assert "Contractors" in r.json()["choices"][0]["message"]["content"]
    assert r.json()["x_shield"]["routing"]["code"] == "deny"
    r = app.post("/v1/shield/chat/completions", json=CHAT, headers=h)
    assert r.status_code == 403 and r.json()["routing"]["code"] == "deny"
    assert upstream.calls == []


def test_the_role_comes_from_the_resolved_identity_not_a_raw_header(app, upstream):
    setup_route(targets=targets3(), rules=RULES)
    r = app.post("/v1/chat/completions", json=CHAT, headers={"X-User-Role": "contractor"})
    assert r.json()["x_shield"]["routing"]["target"] == "cloud"


# ── the invariant ────────────────────────────────────────────────────


def test_no_attempt_ever_leaves_the_eligible_set(store, monkeypatch):
    """Random routes, rules, contexts and failures: every target a call tries
    is one the route lists and, when a rule matched, one the rule allows."""
    rnd = random.Random(1234)
    names = [f"t{i}" for i in range(6)]
    tmap = {n: config.validate_target(n, {"base_url": f"https://{n}.test/v1", "model": n,
                                          "location": rnd.choice(config.LOCATIONS)}) for n in names}
    contacted = []

    def handler(request):
        contacted.append(request.url.host.split(".")[0])
        return rnd.choice([httpx.Response(503, json={}), httpx.Response(429, json={}),
                           httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})])
    monkeypatch.setattr(dispatch, "transport", httpx.MockTransport(handler))

    async def no_check(url, allow_private):
        return None
    monkeypatch.setattr(dispatch, "_check_url", no_check)
    routed = refused = calls = 0
    for trial in range(300):
        health.reset_for_tests()
        route_targets = rnd.sample(names, rnd.randint(1, 5))
        rules = []
        for _ in range(rnd.randint(0, 3)):
            when = rnd.choice([{"flagged": ["pii"]}, {"data_class": ["restricted"]}, {"role": ["r1"]},
                               {"location_required": "on_prem"}])
            rules.append({"when": when, "use": rnd.sample(route_targets, rnd.randint(1, len(route_targets)))})
        route = config.validate_route("r", {"targets": route_targets, "rules": rules,
                                            "strategy": rnd.choice(["priority", "lowest_latency", "lowest_cost"]),
                                            "failover": {"max_attempts": 10}}, tmap)
        ctx = _ctx(flagged=rnd.choice([(), ("pii",)]), data_class=rnd.choice(["", "restricted"]),
                   role=rnd.choice(["", "r1"]))
        allowed = set(route_targets)
        for rule in route["rules"]:
            if select.matches(rule["when"], ctx):
                allowed = set(rule["use"])
                loc = rule["when"].get("location_required")
                if loc:
                    allowed = {t for t in allowed if tmap[t]["location"] == loc}
                break
        p = select.plan(config.Snapshot(tmap, {"r": route}), route, ctx)
        contacted.clear()
        if isinstance(p, select.Refusal):
            assert not allowed, trial
            refused += 1
            continue
        routed += 1
        assert {t["id"] for t in p.targets} <= allowed, trial
        try:
            asyncio.run(dispatch.complete("t1", p, CHAT, CHAT["messages"], {}))
        except dispatch.RoutingError:
            pass
        assert set(contacted) <= allowed, (trial, contacted, allowed)
        calls += len(contacted)
    assert routed > 150 and refused > 0 and calls > routed          # it exercised something
