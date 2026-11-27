"""device_dlp_blocked webhook alerts (R2, task 1).

Spec: docs/specs/device-block-and-stop-alerts.md, sections 1, 3, 4, 5, 7.
"""
import asyncio
import hashlib
import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from core.dlp import device_alerts as da
from core.dlp import devices as dv

T, D = "acme", "dev_1"
NOW = 1_800_000_000.0


def deny(cat="credentials", rh=None, at=NOW, **detail):
    return {"kind": "dlp", "decision": "deny", "at": at,
            "detail": {"category": cat, "record_hash": rh or uuid.uuid4().hex, "destination": "chatgpt.com",
                       "app": "Chrome", "rule_ids": ["builtin:card_number"], "mode": "enforce",
                       "prompt_sha256": "ab" * 32, "prompt_len": 42, **detail}}


@pytest.fixture(autouse=True)
def _mem(monkeypatch):
    dv.reset_memory()
    monkeypatch.setattr(dv, "_redis", lambda: None)
    monkeypatch.setattr(da, "_policy_alerts", lambda tid: {})
    dv._hset(dv._devices_key(T), D, {"hostname": "ana-mbp", "fleet": "eng"})
    yield
    dv.reset_memory()


def test_one_alert_per_device_and_category_per_window():
    ps = da.block_payloads(T, D, [deny(), deny(), deny("customer_data")], now=NOW)
    assert [p["category"] for p in ps] == ["credentials", "customer_data"]
    p = ps[0]
    assert (p["hostname"], p["fleet"], p["device_id"], p["window_s"]) == ("ana-mbp", "eng", D, 300)
    assert da.block_payloads(T, D, [deny()], now=NOW + 10) == []            # same window: counted only
    assert len(da.block_payloads(T, D, [deny()], now=NOW + 400)) == 1       # next window alerts again


def test_a_block_pushed_twice_alerts_once():
    ev = deny(rh="h1")
    assert len(da.block_payloads(T, D, [ev], now=NOW)) == 1
    assert da.block_payloads(T, "dev_2", [ev], now=NOW + 1000) == []        # same record, any device


def test_tenant_cap_rolls_overflow_into_one_summary(monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_DLP_ALERTS_PER_MINUTE", "2")
    ps = da.block_payloads(T, D, [deny(f"c{i}") for i in range(5)], now=NOW)
    assert len(ps) == 3 and ps[-1] == {"reason": "more", "count": 3, "device_id": D,
                                       "hostname": "ana-mbp", "at": NOW}


def test_payload_never_carries_the_prompt_and_marks_delays():
    ev = deny(at=NOW - 3600, prompt="my password is hunter2")
    p = da.block_payloads(T, D, [ev], now=NOW)[0]
    assert "hunter2" not in json.dumps(p) and p["delayed"] is True and p["prompt_len"] == 42
    assert "excerpt" not in p
    q = da.block_payloads(T, D, [deny("x", excerpt="my password is *******")], now=NOW)[0]
    assert q["excerpt"] == "my password is *******" and q["delayed"] is False


def test_only_blocks_and_the_policy_switch(monkeypatch):
    allow = {**deny(), "decision": "audit"}
    other = {**deny(), "kind": "file"}
    assert da.block_payloads(T, D, [allow, other], now=NOW) == []
    monkeypatch.setattr(da, "_policy_alerts", lambda tid: {"dlp_blocks": False})
    assert da.block_payloads(T, D, [deny()], now=NOW) == []


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_ALERTS", "off")
    assert da.enabled() is False
    assert asyncio.run(da.on_device_events(T, D, [deny()])) == 0


def test_dispatch_and_failures_never_raise(monkeypatch):
    sent = []

    async def fake(tid, event, payload):
        sent.append((tid, event, payload["category"]))
    monkeypatch.setattr(da, "enabled", lambda: True)
    with patch("core.webhook_dispatcher.dispatch_event", fake):
        assert asyncio.run(da.on_device_events(T, D, [deny()])) == 1
    assert sent == [(T, "device_dlp_blocked", "credentials")]
    monkeypatch.setattr(da, "block_payloads", lambda *a, **k: 1 / 0)
    assert asyncio.run(da.on_device_events(T, D, [deny()])) == 0


def test_registered_for_webhooks_and_in_the_portal():
    from api.routes_webhooks import VALID_EVENTS
    assert "device_dlp_blocked" in VALID_EVENTS
    html = (Path(__file__).resolve().parents[1] / "static" / "tenant.html").read_text()
    assert 'value="device_dlp_blocked"' in html


# ── over HTTP: only a device key raises device alerts ─────────────────

@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def test_device_batch_raises_the_alert_and_a_tenant_key_does_not(app, monkeypatch):
    from starlette.testclient import TestClient
    from core.runtime_policy import bundle as rt_bundle
    from storage import tenant_store as ts
    monkeypatch.undo()                                  # real Redis helper (memory under the app patch)
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    rt_bundle.reset_signer_cache_for_tests()
    monkeypatch.setattr(da, "enabled", lambda: True)
    tid, key = "ba" + uuid.uuid4().hex[:10], "sk-ba-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    tenant = TestClient(app, headers={"X-API-Key": key})
    tok = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": "eng"}).json()
    laptop = {"hostname": "ba-mbp", "os": "macos", "os_version": "15.1", "agent_version": "1.0.0",
              "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    dev = TestClient(app).post("/v1/devices/enroll", json=laptop,
                               headers={"X-Enrollment-Token": tok["enrollment_token"]}).json()
    sent = []

    async def fake(t, event, payload):
        sent.append((t, event, payload.get("hostname")))
    event = {"source": "custom", "kind": "dlp", "decision": "deny", "severity": "high",
             "agent_id": "x", "at": NOW, "detail": {"verdict": "block", "action": "block",
                                                     "category": "credentials", "record_hash": uuid.uuid4().hex}}
    with patch("core.webhook_dispatcher.dispatch_event", fake):
        r = TestClient(app, headers={"X-API-Key": dev["api_key"]}).post(
            "/v1/shield/runtime/events", json={"events": [event]})
        assert r.status_code == 202 and r.json()["rejected"] == [], r.text
        assert sent == [(tid, "device_dlp_blocked", "ba-mbp")]
        r = tenant.post("/v1/shield/runtime/events", json={"events": [{**event, "detail": {
            **event["detail"], "category": "other", "record_hash": uuid.uuid4().hex}}]})
        assert r.json()["rejected"] == []
    assert len(sent) == 1                                # a tenant key never raises device alerts
    rt_bundle.reset_signer_cache_for_tests()
