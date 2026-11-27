"""device_agent_alert: stopped, restarted without a reboot, capture lost, silent
(opt-in), and returned (R2, task 3).

Spec: docs/specs/device-block-and-stop-alerts.md, sections 3, 4, 5, 7. Built
deviation: `stopped` is decided when the device comes back (its heartbeat shows
whether the machine rebooted), not by a sweep while it is quiet, so a laptop
shut down for the night never raises it.
"""
import asyncio
import hashlib
import uuid
from unittest.mock import patch

import pytest

from core.dlp import device_alerts as da
from core.dlp import device_watch as dw
from core.dlp import devices as dv
from core.dlp.device_policy import PolicyError, policy_hash, validate_policy

REC = {"hostname": "ana-mbp", "fleet": "eng"}
T0 = 1_800_000_000


def hb(at, started, booted, version="1.0.0", stop=False, capture=None):
    s = {"at": at, "agent_started_at": started, "booted_at": booted, "agent_version": version}
    if stop:
        s["last_stop"] = {"at": at, "reason": "signal"}
    if capture:
        s["capture"] = {"state": capture, "kind": "pac", "effective": "http://x/y.pac", "since": at}
    return s


def reasons(prev, seen, **pa):
    return [a["reason"] for a in da.classify_heartbeat("dev_1", REC, prev, seen, pa)]


# ── classification on heartbeat ───────────────────────────────────────

def test_killed_and_relaunched_without_a_reboot():
    prev = hb(T0, T0 - 3600, T0 - 86400)
    seen = hb(T0 + 300, T0 + 250, T0 - 86400)
    out = da.classify_heartbeat("dev_1", REC, prev, seen, {})
    assert [a["reason"] for a in out] == ["restarted_without_reboot"]
    assert (out[0]["hostname"], out[0]["fleet"], out[0]["since"]) == ("ana-mbp", "eng", T0)


@pytest.mark.parametrize("seen,why", [
    (hb(T0 + 300, T0 + 250, T0 + 200), "rebooted"),
    (hb(T0 + 300, T0 + 250, T0 - 86400, version="1.1.0"), "upgraded"),
    (hb(T0 + 300, T0 - 3600, T0 - 86400), "same agent process (slept or just quiet)"),
])
def test_no_alert(seen, why):
    assert reasons(hb(T0, T0 - 3600, T0 - 86400), seen) == [], why


def test_clean_stop_then_long_outage_on_the_same_boot_is_stopped_then_returned():
    stop = hb(T0, T0 - 3600, T0 - 86400, stop=True)
    assert reasons(hb(T0 - 300, T0 - 3600, T0 - 86400), stop) == []     # the stop itself: decide later
    back = hb(T0 + 2000, T0 + 1900, T0 - 86400)
    out = da.classify_heartbeat("dev_1", REC, stop, back, {})
    assert [a["reason"] for a in out] == ["stopped", "returned"] and "1900 s" in out[0]["detail"]


@pytest.mark.parametrize("back,why", [
    (hb(T0 + 40000, T0 + 39000, T0 + 38900), "shut down for the night, rebooted"),
    (hb(T0 + 300, T0 + 200, T0 - 86400), "restarted within the grace period"),
])
def test_clean_stop_is_not_an_alert_when(back, why):
    assert reasons(hb(T0, T0 - 3600, T0 - 86400, stop=True), back) == [], why


def test_capture_lost_then_restored():
    prev = hb(T0, T0 - 3600, T0 - 86400, capture="ok")
    lost = hb(T0 + 60, T0 - 3600, T0 - 86400, capture="overridden")
    out = da.classify_heartbeat("dev_1", REC, prev, lost, {})
    assert [a["reason"] for a in out] == ["capture_disabled"] and "overridden" in out[0]["detail"]
    assert lost["health"]["reason"] == "capture_disabled"
    still = hb(T0 + 120, T0 - 3600, T0 - 86400, capture="overridden")
    assert reasons(lost, still) == []                                    # one alert per episode
    ok = hb(T0 + 180, T0 - 3600, T0 - 86400, capture="ok")
    assert reasons(still, ok) == ["returned"] and ok["health"] is None


def test_old_agents_without_capture_or_uptime_raise_nothing():
    assert reasons({"at": T0}, {"at": T0 + 300}) == []
    assert reasons(None, hb(T0, T0 - 10, T0 - 100)) == []


def test_tamper_off_silences_everything_but_a_return():
    prev = hb(T0, T0 - 3600, T0 - 86400, capture="ok")
    lost = hb(T0 + 60, T0 + 30, T0 - 86400, capture="missing")
    assert reasons(prev, lost, tamper=False) == []
    prev2 = {**hb(T0, T0 - 3600, T0 - 86400), "health": {"reason": "silent", "since": T0}}
    assert reasons(prev2, hb(T0 + 60, T0 - 3600, T0 - 86400), tamper=False) == ["returned"]


# ── policy ────────────────────────────────────────────────────────────

def test_alerts_section():
    p = validate_policy({"alerts": {"silent_after_s": 3600, "dlp_blocks": False}})
    assert p["alerts"] == {"dlp_blocks": False, "tamper": True, "silent_after_s": 3600}
    for bad in ({"silent_after_s": 60}, {"tamper": "yes"}, {"page": True}):
        with pytest.raises(PolicyError):
            validate_policy({"alerts": bad})
    q = validate_policy({"mode": "enforce"})
    assert "alerts" not in q and policy_hash(validate_policy(q)) == policy_hash(q)


# ── silence sweep (opt-in) ────────────────────────────────────────────

@pytest.fixture
def mem(monkeypatch):
    dv.reset_memory()
    monkeypatch.setattr(dv, "_redis", lambda: None)
    yield
    dv.reset_memory()


def _silent_tenant(monkeypatch, tid, devices, after=3600):
    from core.dlp import device_store
    pol = validate_policy({"alerts": {"silent_after_s": after}})
    monkeypatch.setattr(device_store, "get_policy", lambda t: pol)
    dw.note_policy(tid, pol)
    for did, at in devices:
        dv._hset(dv._devices_key(tid), did, {"hostname": did + "-mbp", "fleet": "eng"})
        dv._hset(dv._seen_key(tid), did, {"at": at})


def test_sweep_alerts_once_per_silent_spell(mem, monkeypatch):
    _silent_tenant(monkeypatch, "acme", [("d1", T0 - 7200), ("d2", T0 - 60)])
    out = dw.sweep_tenant("acme", T0)
    assert [(a["device_id"], a["reason"]) for a in out] == [("d1", "silent")]
    assert dv._hget(dv._seen_key("acme"), "d1")["health"]["reason"] == "silent"
    assert dw.sweep_tenant("acme", T0 + 60) == []                        # same spell: once
    prev = dv._hget(dv._seen_key("acme"), "d1")
    assert reasons(prev, {"at": T0 + 100}) == ["returned"]


def test_sweep_summarises_a_mass_outage_and_respects_the_lock(mem, monkeypatch):
    _silent_tenant(monkeypatch, "acme", [(f"d{i}", T0 - 7200) for i in range(60)])
    out = dw.sweep_tenant("acme", T0)
    assert len(out) == 1 and out[0]["summary"] and out[0]["count"] == 60
    sent = []
    monkeypatch.setattr(da, "deliver", lambda t, e, ps: asyncio.sleep(0, result=sent.append(ps) or len(ps)))
    _silent_tenant(monkeypatch, "beta", [("x1", T0 - 7200)])
    assert dw.sweep(T0 + 120) >= 1
    assert dw.sweep(T0 + 125) == 0                                       # this minute is taken


def test_note_policy_keeps_the_tenant_set(mem):
    from core.dlp import device_index as dix
    dw.note_policy("acme", {"alerts": {"silent_after_s": 3600}})
    assert "acme" in dix._smembers(dw.TENANTS_KEY)
    dw.note_policy("acme", {"alerts": {"silent_after_s": 0}})
    assert "acme" not in dix._smembers(dw.TENANTS_KEY)


def test_watch_switches(monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_WATCH", "off")
    assert dw.enabled() is False and dw.start() is False


def test_event_registered():
    from api.routes_webhooks import VALID_EVENTS
    assert "device_agent_alert" in VALID_EVENTS


# ── over HTTP ─────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def test_heartbeats_raise_alerts_and_the_fleet_row_shows_the_episode(app, monkeypatch):
    from starlette.testclient import TestClient
    from core.runtime_policy import bundle as rt_bundle
    from storage import tenant_store as ts
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    rt_bundle.reset_signer_cache_for_tests()
    monkeypatch.setattr(da, "enabled", lambda: True)
    tid, key = "ha" + uuid.uuid4().hex[:10], "sk-ha-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    tenant = TestClient(app, headers={"X-API-Key": key})
    tok = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": "eng"}).json()
    laptop = {"hostname": "ha-mbp", "os": "macos", "os_version": "15.1", "agent_version": "1.0.0",
              "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    dev = TestClient(app).post("/v1/devices/enroll", json=laptop,
                               headers={"X-Enrollment-Token": tok["enrollment_token"]}).json()
    agent = TestClient(app, headers={"X-API-Key": dev["api_key"]})
    sent = []

    async def fake(t, event, payload):
        sent.append((event, payload["reason"]))
    cap = lambda s: {"state": s, "kind": "pac", "effective": "", "since": 1}  # noqa: E731
    base = {"state": "ok", "agent_version": "1.0.0", "system_uptime_s": 86400}
    with patch("core.webhook_dispatcher.dispatch_event", fake):
        assert agent.post("/v1/devices/heartbeat", json={**base, "agent_uptime_s": 3600,
                                                         "capture": cap("ok")}).status_code == 204
        assert agent.post("/v1/devices/heartbeat", json={**base, "agent_uptime_s": 3601,
                                                         "capture": cap("missing")}).status_code == 204
        row = tenant.get("/v1/tenant/me/devices").json()["devices"][0]
        assert row["health"]["reason"] == "capture_disabled"
        assert agent.post("/v1/devices/heartbeat", json={**base, "agent_uptime_s": 5,
                                                         "capture": cap("ok")}).status_code == 204
        # bad values are dropped, never a reason to refuse the heartbeat
        assert agent.post("/v1/devices/heartbeat", json={"state": "ok", "agent_uptime_s": "x",
                                                         "lifecycle": "weird"}).status_code == 204
    assert ("device_agent_alert", "capture_disabled") in sent
    assert ("device_agent_alert", "restarted_without_reboot") in sent and ("device_agent_alert", "returned") in sent
    assert "health" not in tenant.get("/v1/tenant/me/devices").json()["devices"][0]
    rt_bundle.reset_signer_cache_for_tests()
