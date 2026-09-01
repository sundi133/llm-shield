"""Tier 2 screen and telemetry tests (task 4 of docs/spec-swg-icap-adapter.md).

The property that matters most here is negative: in the default configuration,
nothing Shield does -- slow, down, or blocking -- may delay or break the
employee's request. Tier 2 buys visibility, not inline enforcement.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx
import pytest

from icap.config import IcapConfig
from icap.policy import PolicyCache, Tier1Screener, compile_bundle
from icap.server import IcapRequest, Verdict
from icap.shield import SCREEN_PATH, ScreenPipeline, ShieldClient

from tests.test_icap_policy import AWS_RULE, bundle_json


def cfg(**kw) -> IcapConfig:
    base = dict(api_key="tenant-key", api_base="https://shield.test", version="build-1")
    base.update(kw)
    return IcapConfig(**base)


def make_request(text: str = "what is the weather", host: str = "api.anthropic.com", **headers):
    body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode()
    return IcapRequest(
        method="REQMOD", service="/screen", headers=headers, body=body,
        http_headers={"host": host},
    )


def transport(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def blocked_response() -> dict:
    return {
        "safe": False,
        "action": "block",
        "guardrail_results": [
            {"guardrail": "prompt-injection", "passed": False, "message": "override attempt"},
            {"guardrail": "toxicity", "passed": True},
        ],
    }


PASS = {"safe": True, "action": "pass", "guardrail_results": []}


# ── test 12: attribution headers ─────────────────────────────────────────────


def test_screen_request_shape_and_headers():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PASS)

    async def go():
        client = ShieldClient(cfg(proxy_token="rp-token"), transport(handler))
        req = make_request("hello there", **{"x-authenticated-user": "alice@corp.example"})
        await client.screen_sync(req)
        return req

    req = asyncio.run(go())

    assert str(seen[0].url) == "https://shield.test" + SCREEN_PATH
    assert seen[0].headers["X-API-Key"] == "tenant-key"
    assert seen[0].headers["Authorization"] == "Bearer rp-token"
    assert seen[0].headers["X-Shield-Destination"] == "api.anthropic.com"
    assert seen[0].headers["X-Device-Id"] == "alice@corp.example"
    # Lets telemetry tell this tap apart from the browser extension when a
    # fleet runs both.
    assert seen[0].headers["X-Shield-Source"] == "icap"

    body = json.loads(seen[0].content)
    assert body == {"message": "hello there", "session_id": req.txn_id}


def test_device_id_omitted_when_the_swg_forwards_no_user():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PASS)

    asyncio.run(ShieldClient(cfg(), transport(handler)).screen_sync(make_request()))
    assert "X-Device-Id" not in seen[0].headers


def test_message_is_the_turn_being_sent():
    """/guardrails/input is shaped for the user turn, not the whole transcript."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PASS)

    body = json.dumps(
        {
            "messages": [
                {"role": "user", "content": "old question"},
                {"role": "assistant", "content": "old answer"},
                {"role": "user", "content": "current question"},
            ]
        }
    ).encode()
    req = IcapRequest(
        method="REQMOD", service="/screen", headers={}, body=body,
        http_headers={"host": "api.openai.com"},
    )
    asyncio.run(ShieldClient(cfg(), transport(handler)).screen_sync(req))

    assert json.loads(seen[0].content)["message"] == "current question"


# ── verdict mapping ──────────────────────────────────────────────────────────


def test_block_verdict_carries_the_guardrail_names():
    verdict = ShieldClient.to_verdict(blocked_response())

    assert verdict.block is True
    assert verdict.rule_id == "prompt-injection"
    assert verdict.payload["guardrails"] == ["prompt-injection"]
    assert "override attempt" in verdict.payload["reason"]


@pytest.mark.parametrize("action", ["pass", "log", "warn", "redact"])
def test_non_block_actions_allow(action):
    assert ShieldClient.to_verdict({"action": action}).block is False


# ── test 8: sync mode and the fail-open switch ───────────────────────────────


def slow_handler(delay: float):
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(delay)
        return httpx.Response(200, json=PASS)

    return handler


@pytest.mark.parametrize(
    "fail_open, expect_block",
    [(False, True), (True, False)],
    ids=["fail_closed", "fail_open"],
)
def test_sync_timeout_honours_fail_open(fail_open, expect_block):
    """A timeout is not an approval; the configured posture decides."""

    async def go():
        client = ShieldClient(
            cfg(fail_open=fail_open, screen_timeout_s=0.05),
            transport(slow_handler(0.5)),
        )
        return await client.screen_sync(make_request())

    verdict = asyncio.run(go())
    assert verdict.block is expect_block
    if expect_block:
        assert verdict.rule_id == "shield_unavailable"


@pytest.mark.parametrize(
    "fail_open, expect_block", [(False, True), (True, False)], ids=["fail_closed", "fail_open"]
)
def test_sync_5xx_honours_fail_open(fail_open, expect_block):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def go():
        client = ShieldClient(cfg(fail_open=fail_open), transport(handler))
        return await client.screen_sync(make_request())

    assert asyncio.run(go()).block is expect_block


def test_sync_mode_blocks_on_a_shield_verdict():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=blocked_response())

    async def go():
        client = ShieldClient(cfg(sync_screen=True), transport(handler))
        pipeline = ScreenPipeline(_allow_tier1, client, cfg(sync_screen=True))
        return await pipeline(make_request())

    verdict = asyncio.run(go())
    assert verdict.block is True
    assert verdict.rule_id == "prompt-injection"


async def _allow_tier1(_req: IcapRequest) -> Verdict:
    return Verdict()


# ── the default: async, and never on the request path ────────────────────────


def test_async_mode_does_not_wait_for_shield():
    """The property this whole tier is arranged around. A 14-20s screen must
    not become 14-20s of latency on an employee's prompt."""

    async def go():
        client = ShieldClient(cfg(), transport(slow_handler(2.0)))
        client.start()
        pipeline = ScreenPipeline(_allow_tier1, client, cfg())
        started = time.monotonic()
        verdict = await pipeline(make_request())
        elapsed = time.monotonic() - started
        await client.aclose()
        return verdict, elapsed

    verdict, elapsed = asyncio.run(go())
    assert verdict.block is False
    assert elapsed < 0.2, "the transaction must not wait on Tier 2"


def test_async_mode_still_screens_in_the_background():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PASS)

    async def go():
        client = ShieldClient(cfg(), transport(handler))
        client.start()
        pipeline = ScreenPipeline(_allow_tier1, client, cfg())
        await pipeline(make_request())
        await client.drain()
        await client.aclose()

    asyncio.run(go())
    assert len(seen) == 1, "forwarding the request must not mean skipping the screen"


def test_shield_down_never_breaks_browsing_in_async_mode():
    """Availability is not allowed to become an outage in the default config."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async def go():
        client = ShieldClient(cfg(fail_open=False), transport(handler))
        client.start()
        pipeline = ScreenPipeline(_allow_tier1, client, cfg(fail_open=False))
        verdict = await pipeline(make_request())
        await client.drain()
        await client.aclose()
        return verdict

    assert asyncio.run(go()).block is False


def test_tier1_block_is_still_reported():
    """A local block that never reaches telemetry is a block the tenant's
    console cannot show anyone."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PASS)

    async def go():
        config = cfg(mode="enforce")
        cache = PolicyCache(config)
        cache._bundle = compile_bundle(bundle_json())
        client = ShieldClient(config, transport(handler))
        client.start()
        pipeline = ScreenPipeline(Tier1Screener(cache, config), client, config)
        verdict = await pipeline(make_request("key AKIAIOSFODNN7EXAMPLE"))
        await client.drain()
        await client.aclose()
        return verdict

    verdict = asyncio.run(go())
    assert verdict.block is True
    assert len(seen) == 1


def test_unparsed_body_skips_tier2():
    """Spec §7: an unknown shape still feeds Tier 1 DLP but is not screened."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PASS)

    async def go():
        client = ShieldClient(cfg(), transport(handler))
        client.start()
        req = IcapRequest(
            method="REQMOD", service="/screen", headers={},
            body=b"key=value&x=1", http_headers={"host": "api.openai.com"},
        )
        assert client.screenable(req) is False
        await ScreenPipeline(_allow_tier1, client, cfg())(req)
        await client.drain()
        await client.aclose()

    asyncio.run(go())
    assert seen == []


def test_missing_api_key_makes_nothing_screenable():
    async def go():
        client = ShieldClient(cfg(api_key=""))
        return client.screenable(make_request())

    assert asyncio.run(go()) is False


# ── backpressure ─────────────────────────────────────────────────────────────


def test_full_queue_drops_rather_than_blocking(caplog):
    """Telemetry is worth a lot, but not worth holding a browser tab open."""

    async def go():
        client = ShieldClient(cfg(telemetry_queue=2), transport(slow_handler(5)))
        # No workers started, so nothing drains the queue.
        started = time.monotonic()
        for _ in range(50):
            client.submit(make_request())
        return client, time.monotonic() - started

    with caplog.at_level(logging.WARNING, logger="shield.icap"):
        client, elapsed = asyncio.run(go())

    assert elapsed < 0.5, "submit must never block the request path"
    assert client.submitted == 2
    assert client.dropped == 48
    assert "telemetry queue full" in caplog.text


def test_worker_survives_a_failing_screen():
    """One bad screen must not kill the worker and silently end telemetry."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("transient")
        return httpx.Response(200, json=PASS)

    async def go():
        client = ShieldClient(cfg(telemetry_workers=1), transport(handler))
        client.start()
        client.submit(make_request())
        await client.drain()
        client.submit(make_request())
        await client.drain()
        await client.aclose()

    asyncio.run(go())
    assert calls["n"] == 2
