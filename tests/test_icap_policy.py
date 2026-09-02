"""Tier 1 DLP tests (task 3 of docs/spec-swg-icap-adapter.md).

The load-bearing test in this file is `test_cold_start_allows_everything`.
Failing closed on an empty policy would black-hole every AI request in the
enterprise the first time Shield was unreachable at boot, which is a worse
outage than the leak it would prevent.
"""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

from icap.config import IcapConfig
from icap.policy import BUNDLE_PATH, Bundle, PolicyCache, Tier1Screener, compile_bundle, evaluate
from icap.server import IcapRequest

from tests.test_icap_server import Harness, build_reqmod, recv_head


AWS_RULE = {
    "id": "aws-secret-key",
    "regex": r"AKIA[0-9A-Z]{16}",
    "action": "block",
    "severity": "critical",
}
EMAIL_RULE = {
    "id": "email",
    "regex": r"[\w.]+@[\w.]+\.\w+",
    "action": "redact",
    "severity": "medium",
}


def bundle_json(version="v1", rules=None, blocklists=None) -> dict:
    return {
        "tenant_id": "acme",
        "version": version,
        "rules": rules if rules is not None else [AWS_RULE],
        "blocklists": blocklists or [],
    }


def cfg(**kw) -> IcapConfig:
    base = dict(api_key="tenant-key", api_base="https://shield.test", version="build-1")
    base.update(kw)
    return IcapConfig(**base)


def make_request(text: str, host: str = "api.anthropic.com") -> IcapRequest:
    body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode()
    return IcapRequest(
        method="REQMOD", service="/screen", headers={}, body=body,
        http_headers={"host": host},
    )


# ── compilation ──────────────────────────────────────────────────────────────


def test_invalid_regex_is_skipped_not_fatal():
    """One bad pattern typed into the portal must not disarm the whole policy."""
    data = bundle_json(rules=[{"id": "broken", "regex": "([", "action": "block"}, AWS_RULE])
    bundle = compile_bundle(data)

    assert bundle.skipped == 1
    assert [r.id for r in bundle.rules] == ["aws-secret-key"]


@pytest.mark.parametrize(
    "fallback, expected_action",
    [("pass", "pass"), ("block", "block")],
)
def test_redact_rules_resolve_via_fallback(fallback, expected_action):
    """v1 cannot rewrite bodies (spec §5), so `redact` must become a decision
    the adapter can actually carry out."""
    bundle = compile_bundle(bundle_json(rules=[EMAIL_RULE]), redact_fallback=fallback)
    assert bundle.rules[0].action == expected_action
    assert bundle.rules[0].blocks is (expected_action == "block")


# ── evaluation ───────────────────────────────────────────────────────────────


def test_rule_match():
    bundle = compile_bundle(bundle_json())
    hit = evaluate(bundle, "my key is AKIAIOSFODNN7EXAMPLE ok")
    assert hit is not None and hit.rule_id == "aws-secret-key" and hit.severity == "critical"


def test_no_match_returns_none():
    assert evaluate(compile_bundle(bundle_json()), "nothing sensitive here") is None


def test_blocklist_is_case_insensitive():
    bundle = compile_bundle(bundle_json(rules=[], blocklists=["Project Titan"]))
    hit = evaluate(bundle, "tell me about project titan")
    assert hit is not None and hit.kind == "blocklist"


def test_non_blocking_rule_does_not_block():
    warn_only = {"id": "note", "regex": "hello", "action": "warn", "severity": "low"}
    assert evaluate(compile_bundle(bundle_json(rules=[warn_only])), "hello") is None


def test_empty_bundle_matches_nothing():
    assert evaluate(Bundle(), "AKIAIOSFODNN7EXAMPLE") is None


# ── bundle cache ─────────────────────────────────────────────────────────────


def transport(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_bundle_fetch_sends_tenant_key_and_etag():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=bundle_json(), headers={"ETag": '"v1"'})

    async def go():
        cache = PolicyCache(cfg(proxy_token="rp-token"), transport(handler))
        assert await cache.refresh() is True
        assert await cache.refresh() is False, "same version must not re-swap the bundle"
        return cache

    cache = asyncio.run(go())

    assert str(seen[0].url) == "https://shield.test" + BUNDLE_PATH
    assert seen[0].headers["X-API-Key"] == "tenant-key"
    assert seen[0].headers["Authorization"] == "Bearer rp-token"
    assert "if-none-match" not in seen[0].headers
    assert seen[1].headers["If-None-Match"] == '"v1"', "must poll cheaply after the first load"
    assert cache.bundle.version == "v1"
    assert cache.reachable is True


def test_304_keeps_the_cached_bundle():
    state = {"first": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["first"]:
            state["first"] = False
            return httpx.Response(200, json=bundle_json(), headers={"ETag": '"v1"'})
        return httpx.Response(304, headers={"ETag": '"v1"'})

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        await cache.refresh()
        assert await cache.refresh() is False
        return cache

    cache = asyncio.run(go())
    assert cache.bundle.version == "v1"
    assert len(cache.bundle.rules) == 1


def test_version_change_swaps_the_rules():
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(200, json=bundle_json("v1", rules=[AWS_RULE]))
        return httpx.Response(
            200,
            json=bundle_json("v2", rules=[{"id": "ssn", "regex": r"\d{3}-\d{2}-\d{4}", "action": "block"}]),
        )

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        await cache.refresh()
        assert await cache.refresh() is True
        return cache

    cache = asyncio.run(go())
    assert cache.bundle.version == "v2"
    assert [r.id for r in cache.bundle.rules] == ["ssn"]


@pytest.mark.parametrize(
    "failure",
    [
        lambda r: httpx.Response(500),
        lambda r: httpx.Response(200, content=b"not json"),
    ],
    ids=["http_500", "malformed_json"],
)
def test_failure_after_good_load_keeps_serving(failure):
    """Stale policy beats no policy: a Shield outage must not disarm DLP."""
    state = {"first": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["first"]:
            state["first"] = False
            return httpx.Response(200, json=bundle_json())
        return failure(request)

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        await cache.refresh()
        await cache.refresh()
        return cache

    cache = asyncio.run(go())
    assert cache.bundle.version == "v1"
    assert len(cache.bundle.rules) == 1


def test_network_error_marks_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        assert await cache.refresh() is False
        return cache

    cache = asyncio.run(go())
    assert cache.reachable is False
    assert cache.bundle.empty


def test_missing_api_key_does_not_call_out():
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json=bundle_json())

    async def go():
        cache = PolicyCache(cfg(api_key=""), transport(handler))
        return await cache.refresh()

    assert asyncio.run(go()) is False
    assert called["n"] == 0


def test_istag_falls_back_to_build_then_tracks_policy():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=bundle_json("v9"))

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        before = cache.version
        await cache.refresh()
        return before, cache.version

    before, after = asyncio.run(go())
    assert before == "build-1", "the SWG always needs an ISTag, even before policy loads"
    assert after == "v9"


# ── screener ─────────────────────────────────────────────────────────────────


def screen(config: IcapConfig, bundle: Bundle, text: str):
    cache = PolicyCache(config)
    cache._bundle = bundle
    return asyncio.run(Tier1Screener(cache, config)(make_request(text)))


def test_tier1_blocks_on_a_critical_rule():
    verdict = screen(cfg(), compile_bundle(bundle_json()), "here is AKIAIOSFODNN7EXAMPLE")

    assert verdict.block is True
    assert verdict.rule_id == "aws-secret-key"
    # `error` is the sentence, because that is the field AI web apps render
    # and it is the only message a blocked employee ever sees. The machine
    # value moved to `code`.
    assert verdict.payload["code"] == "blocked_by_votal_shield"
    assert "aws-secret-key" in verdict.payload["error"]
    assert verdict.payload["error"].startswith("Blocked by your organization")
    assert verdict.payload["severity"] == "critical"
    assert verdict.payload["policy_version"] == "v1"
    assert "aws-secret-key" in verdict.payload["reason"]


def test_tier1_allows_a_clean_prompt():
    assert screen(cfg(), compile_bundle(bundle_json()), "what is the weather").block is False


def test_cold_start_allows_everything():
    """No bundle ever loaded means no rules, so nothing can match. This must
    hold regardless of fail-open settings -- see the module docstring."""
    verdict = screen(cfg(mode="enforce"), Bundle(), "AKIAIOSFODNN7EXAMPLE")
    assert verdict.block is False


def test_secrets_in_conversation_history_are_caught():
    """Tier 1 screens the whole body, not just the turn being sent: a key
    replayed in history is just as leaked."""
    body = json.dumps(
        {
            "messages": [
                {"role": "user", "content": "here is my key AKIAIOSFODNN7EXAMPLE"},
                {"role": "assistant", "content": "noted"},
                {"role": "user", "content": "now summarise that"},
            ]
        }
    ).encode()
    req = IcapRequest(
        method="REQMOD", service="/screen", headers={}, body=body,
        http_headers={"host": "api.anthropic.com"},
    )
    cache = PolicyCache(cfg())
    cache._bundle = compile_bundle(bundle_json())
    assert asyncio.run(Tier1Screener(cache, cfg())(req)).block is True


def test_scan_timeout_allows_rather_than_stalls():
    """A pattern that cannot finish on an already-capped body is a broken
    pattern, not a decision. Never hold the browser tab.

    This is why the adapter depends on `regex` rather than stdlib `re`. The
    deadline has to actually terminate the match: with `re` it could not, both
    because there is no timeout= and because `re` holds the GIL for the whole
    match, so an outer asyncio deadline cannot fire until the thing it bounds
    has already finished. The total-time assertion below is what catches a
    regression back to `re` -- the verdict alone would still look correct.
    """
    catastrophic = {"id": "redos", "regex": r"(a|a)*$", "action": "block", "severity": "critical"}
    bundle = compile_bundle(bundle_json(rules=[catastrophic]))
    config = cfg(scan_timeout_ms=100)

    async def go():
        cache = PolicyCache(config)
        cache._bundle = bundle
        started = time.monotonic()
        verdict = await Tier1Screener(cache, config)(make_request("a" * 40 + "!"))
        return verdict, time.monotonic() - started

    outer = time.monotonic()
    verdict, transaction_s = asyncio.run(go())
    total_s = time.monotonic() - outer

    assert verdict.block is False, "a pattern that cannot finish is not a verdict"
    assert transaction_s < 0.5, "the transaction must return on the deadline"
    # Nothing outlives the transaction: the engine stopped the match, it was not
    # merely abandoned to a worker thread.
    assert total_s < 1.0, "the abandoned match must not delay teardown"


def test_scan_budget_spans_the_whole_rule_set():
    """Fifty slow patterns must still cost one deadline, not fifty."""
    slow = [
        {"id": f"redos-{i}", "regex": r"(a|a)*$", "action": "block", "severity": "high"}
        for i in range(10)
    ]
    bundle = compile_bundle(bundle_json(rules=slow))

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        evaluate(bundle, "a" * 40 + "!", timeout_s=0.1)
    assert time.monotonic() - started < 0.5


def test_unparsed_body_still_screened_by_tier1():
    """An unknown shape skips Tier 2 but must still feed the DLP sweep."""
    req = IcapRequest(
        method="REQMOD", service="/screen", headers={},
        body=b"key=AKIAIOSFODNN7EXAMPLE&x=1",
        http_headers={"host": "api.openai.com"},
    )
    cache = PolicyCache(cfg())
    cache._bundle = compile_bundle(bundle_json())
    verdict = asyncio.run(Tier1Screener(cache, cfg())(req))

    assert req.prompt.parsed is False
    assert verdict.block is True


# ── end to end over the wire ─────────────────────────────────────────────────


def _served(config: IcapConfig, bundle: Bundle, text: str) -> bytes:
    cache = PolicyCache(config)
    cache._bundle = bundle
    server_cfg = config
    with Harness(server_cfg, Tier1Screener(cache, config)) as h:
        h.server.version_fn = lambda: cache.version
        sock = h.connect()
        body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode()
        sock.sendall(build_reqmod(body=body))
        resp = recv_head(sock)
        sock.close()
    return resp


def test_enforce_mode_returns_403_over_icap():
    resp = _served(cfg(mode="enforce"), compile_bundle(bundle_json()), "key AKIAIOSFODNN7EXAMPLE")

    assert resp.startswith(b"ICAP/1.0 200 OK")
    assert b"HTTP/1.1 403 Forbidden" in resp
    assert b'"rule_id":"aws-secret-key"' in resp
    assert b'"policy_version":"v1"' in resp
    assert b'ISTag: "v1"' in resp, "ISTag must track policy, not the build"


def test_monitor_mode_forwards_the_same_request():
    """Default mode. Reports what would have blocked, changes nothing."""
    resp = _served(cfg(mode="monitor"), compile_bundle(bundle_json()), "key AKIAIOSFODNN7EXAMPLE")
    assert resp.startswith(b"ICAP/1.0 204 No Content")
    assert b"403" not in resp


def test_rejected_key_is_reported_not_swallowed():
    """"Reachable but refused" is the failure that looks healthiest: an
    operator sees ok=true, shield_reachable=true, and misses rules=0."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "No valid tenant API key provided."})

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        await cache.refresh()
        return cache

    cache = asyncio.run(go())
    assert cache.reachable is True, "the server answered, so it is reachable"
    assert "401" in cache.last_error, "but the refusal must be visible"
    assert cache.bundle.empty


def test_successful_refresh_clears_a_previous_error():
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(401, json={})
        return httpx.Response(200, json=bundle_json())

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        await cache.refresh()
        assert cache.last_error
        await cache.refresh()
        return cache

    assert asyncio.run(go()).last_error == ""


def test_a_policy_of_only_redact_rules_is_not_enforcement():
    """The state a real tenant was actually in: one rule, action=redact.

    v1 cannot rewrite bodies, so that rule resolves to pass and nothing can
    fire. Reporting it as enforcement tells an operator they are protected
    when they are not, which is the worst thing a security status line can do.
    """
    bundle = compile_bundle(bundle_json(rules=[EMAIL_RULE]), redact_fallback="pass")

    assert len(bundle.rules) == 1, "the rule is loaded"
    assert bundle.blocking_rules == 0, "but it cannot block"
    assert bundle.can_block is False
    assert bundle.empty is False, "a loaded-but-inert policy is not an empty one"


def test_redact_fallback_block_makes_it_enforcement():
    bundle = compile_bundle(bundle_json(rules=[EMAIL_RULE]), redact_fallback="block")
    assert bundle.blocking_rules == 1
    assert bundle.can_block is True


def test_blocklists_alone_count_as_enforcement():
    bundle = compile_bundle(bundle_json(rules=[], blocklists=["project titan"]))
    assert bundle.blocking_rules == 0
    assert bundle.can_block is True


# ── which tenant is this deployment actually governing ───────────────────────


def test_bundle_carries_the_tenant_it_came_from():
    """An operator must be able to SEE the tenant, not infer it from which key
    file they believe is mounted."""
    bundle = compile_bundle(bundle_json())
    assert bundle.tenant_id == "acme"


def test_wrong_tenant_is_refused_not_applied():
    """Policy differs per tenant, so loading the wrong one governs a fleet by
    another organisation's rules. No policy is a visible failure; the wrong
    policy is an invisible one."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=bundle_json())      # tenant "acme"

    async def go():
        cache = PolicyCache(cfg(expect_tenant="bankco"), transport(handler))
        loaded = await cache.refresh()
        return loaded, cache

    loaded, cache = asyncio.run(go())

    assert loaded is False
    assert cache.bundle.empty, "a mismatched policy must not be applied"
    assert "tenant mismatch" in cache.last_error
    assert "acme" in cache.last_error and "bankco" in cache.last_error


def test_matching_tenant_loads_normally():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=bundle_json())

    async def go():
        cache = PolicyCache(cfg(expect_tenant="acme"), transport(handler))
        await cache.refresh()
        return cache

    cache = asyncio.run(go())
    assert cache.bundle.tenant_id == "acme"
    assert cache.last_error == ""


def test_no_expectation_declared_accepts_whatever_the_key_resolves_to():
    """The check is opt-in. Without it the adapter behaves exactly as before,
    because the key has always been the thing that selects the tenant."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=bundle_json())

    async def go():
        cache = PolicyCache(cfg(), transport(handler))
        await cache.refresh()
        return cache

    assert asyncio.run(go()).bundle.tenant_id == "acme"


def test_tenant_mismatch_also_drops_the_cached_policy():
    """Unlike a fetch failure, which keeps the last known good bundle.

    A failed fetch means "cannot refresh, keep what is right". A tenant
    mismatch means the key is not the one this deployment is for, so the
    cached policy is no longer trustworthy either. Enforcing nothing is
    visible; enforcing another organisation's rules is not.
    """
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(200, json=bundle_json("v1"))          # acme
        return httpx.Response(200, json={**bundle_json("v2"), "tenant_id": "other"})

    async def go():
        cache = PolicyCache(cfg(expect_tenant="acme"), transport(handler))
        await cache.refresh()
        assert cache.bundle.rules, "first load is the right tenant"
        await cache.refresh()
        return cache

    cache = asyncio.run(go())
    assert cache.bundle.empty, "the stale policy must not survive a tenant mismatch"
    assert "tenant mismatch" in cache.last_error
