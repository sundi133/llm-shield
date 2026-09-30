"""Device DLP agent, task 3: enrollment, device keys, heartbeat, revoke, fleet view.
Spec: docs/specs/device-dlp-agent.md §5.2, §6, §7."""

import hashlib
import os
import sys
import time
import uuid
from unittest.mock import patch

import pytest

from core.dlp import devices as dv

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PKG = os.path.join(ROOT, "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

TOKENS = "/v1/tenant/me/devices/enrollment-tokens"
DEVICES = "/v1/tenant/me/devices"
LAPTOP = {"hostname": "ana-mbp", "os": "macos", "os_version": "14.5", "agent_version": "0.1.0",
          "serial_hash": hashlib.sha256(b"C02XK0AAJG5H").hexdigest()}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    dv.reset_memory()
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    rt_bundle.reset_signer_cache_for_tests()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _client(app, key):
    from starlette.testclient import TestClient
    return TestClient(app, headers={"X-API-Key": key} if key else {})


@pytest.fixture
def admin(app):
    from storage import tenant_store as ts
    tid = "dv" + uuid.uuid4().hex[:10]
    key = "sk-dv-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = _client(app, key)
    c.tenant_id = tid
    return c


def _token(admin, fleet="sales", **kw):
    r = admin.post(TOKENS, json={"fleet": fleet, **kw})
    assert r.status_code == 200, r.text
    return r.json()["enrollment_token"]


def _enroll(app, token, body=None):
    from starlette.testclient import TestClient
    return TestClient(app).post("/v1/devices/enroll", json=body or LAPTOP,
                                headers={"X-Enrollment-Token": token})


# ── enrollment ───────────────────────────────────────────────────────


def test_enroll_returns_a_device_key_and_the_pinned_key(app, admin):
    from core.embodied import bundle as edge_bundle
    token = _token(admin)
    assert token.startswith(f"vde.{admin.tenant_id}.")
    r = _enroll(app, token)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["api_key"].startswith("vdk_") and out["device_id"].startswith("dev_")
    assert out["fleet"] == "sales" and out["tenant_id"] == admin.tenant_id
    assert out["pinned_public_key"] == edge_bundle.public_key_hex()
    from storage.tenant_store import key_scope
    assert key_scope(out["api_key"]) == "device"
    listed = admin.get(DEVICES).json()
    assert listed["summary"]["devices"] == 1
    row = listed["devices"][0]
    assert row["hostname"] == "ana-mbp" and row["state"] == "never_seen"
    assert "key_hash" not in row                                    # never shown


def test_tokens_run_out_expire_and_are_stored_hashed(app, admin):
    from storage.tenant_store import _fallback_store
    token = _token(admin, uses=1)
    secret = token.rsplit(".", 1)[1]
    assert not any(secret in str(v) for v in _fallback_store.values())
    assert _enroll(app, token).status_code == 200
    again = _enroll(app, token, {**LAPTOP, "serial_hash": ""})
    assert again.status_code == 401 and "no uses left" in again.text
    listed = admin.get(TOKENS).json()["tokens"]
    assert listed[0]["uses_left"] == 0 and "enrollment_token" not in listed[0]
    # Expired: the record's own deadline governs, whatever the store's TTL does.
    t2 = _token(admin)
    with patch("time.time", return_value=time.time() + 8 * 86400):
        assert _enroll(app, t2).status_code == 401


@pytest.mark.parametrize("token", ["", "garbage", "vde.nobody.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                                   "vde..abc"])
def test_bad_tokens_get_one_answer(app, token):
    r = _enroll(app, token)
    assert r.status_code == 401 and "invalid or expired enrollment token" in r.text


def test_a_token_for_one_tenant_cannot_enroll_into_another(app, admin):
    token = _token(admin)
    tid, secret = token[4:].rsplit(".", 1)
    assert _enroll(app, f"vde.someone-else.{secret}").status_code == 401


def test_enroll_validates_the_body_before_taking_a_use(app, admin):
    token = _token(admin, uses=1)
    assert _enroll(app, token, {**LAPTOP, "os": "linux"}).status_code == 400
    assert _enroll(app, token, {**LAPTOP, "serial_hash": "C02XK0AAJG5H"}).status_code == 400
    assert _enroll(app, token).status_code == 200                   # the use was still there


def test_no_signing_key_no_enrollment(app, admin, monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    token = _token(admin, uses=1)
    monkeypatch.delenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY")
    rt_bundle.reset_signer_cache_for_tests()
    assert _enroll(app, token).status_code == 503
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    rt_bundle.reset_signer_cache_for_tests()
    assert _enroll(app, token).status_code == 200                   # no use was burnt


def test_claiming_a_live_devices_serial_is_refused_and_raised(app, admin):
    """The serial is printed in About This Mac and the token is readable on any
    enrolled laptop: claiming a colleague's serial must not knock their laptop
    off the fleet (spec: docs/specs/device-rollout-kit.md §5, point 1)."""
    token = _token(admin, uses=5)
    first = _enroll(app, token).json()
    victim = _client(app, first["api_key"])
    assert victim.post("/v1/devices/heartbeat", json={}).status_code == 204
    with patch("core.runtime_policy.events.ingest") as ingest:
        r = _enroll(app, token, {**LAPTOP, "hostname": "attacker-box"})
    assert r.status_code == 409 and "still reporting" in r.text
    assert victim.post("/v1/devices/heartbeat", json={}).status_code == 204   # untouched
    ev = ingest.call_args.args[1][0]
    assert (ev["kind"], ev["severity"], ev["detail"]["event"]) == ("dlp", "high", "enrollment_refused")
    assert ev["detail"]["device_id"] == first["device_id"]
    assert ev["detail"]["hostname_claimed"] == "attacker-box"
    tokens = admin.get(TOKENS).json()["tokens"]
    assert tokens[0]["uses_left"] == 4                                  # the refusal spent no use


def test_a_silent_devices_serial_can_be_reinstalled(app, admin):
    token = _token(admin)
    first = _enroll(app, token).json()
    later = time.time() + dv.LIVE_WINDOW_S + 60                         # silent for over 24 h
    with patch("time.time", return_value=later):
        second = _enroll(app, token).json()
    assert second["device_id"] == first["device_id"]
    assert admin.get(DEVICES).json()["summary"]["devices"] == 1
    assert _client(app, first["api_key"]).post("/v1/devices/heartbeat", json={}).status_code == 401
    assert _client(app, second["api_key"]).post("/v1/devices/heartbeat", json={}).status_code == 204


def test_revoking_the_old_install_unblocks_a_reinstall(app, admin):
    token = _token(admin)
    first = _enroll(app, token).json()
    assert _enroll(app, token).status_code == 409
    admin.delete(f"{DEVICES}/{first['device_id']}")
    assert _enroll(app, token).status_code == 200


def test_escape_hatch_restores_replacement(app, admin, monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_REENROLL_LIVE", "replace")
    token = _token(admin)
    first = _enroll(app, token).json()
    second = _enroll(app, token).json()
    assert second["device_id"] == first["device_id"]
    assert _client(app, first["api_key"]).post("/v1/devices/heartbeat", json={}).status_code == 401


def test_token_validation_and_revocation(app, admin):
    assert admin.post(TOKENS, json={"fleet": "Sales Team"}).status_code == 400
    assert admin.post(TOKENS, json={"fleet": "s", "uses": 0}).status_code == 400
    assert admin.post(TOKENS, json={"fleet": "s", "expires_in_days": 365}).status_code == 400
    r = admin.post(TOKENS, json={"fleet": "sales"}).json()
    assert admin.delete(f"{TOKENS}/{r['token_id']}").json()["revoked"] is True
    assert _enroll(app, r["enrollment_token"]).status_code == 401
    assert admin.delete(f"{TOKENS}/{r['token_id']}").status_code == 404


def test_feature_flag_turns_enrollment_off(app, admin, monkeypatch):
    token = _token(admin)
    monkeypatch.setenv("SHIELD_DEVICE_AGENT", "off")
    assert _enroll(app, token).status_code == 404


# ── what a device key can reach ──────────────────────────────────────


@pytest.fixture
def device(app, admin):
    out = _enroll(app, _token(admin)).json()
    c = _client(app, out["api_key"])
    c.device_id, c.tenant_id, c.key = out["device_id"], out["tenant_id"], out["api_key"]
    return c


@pytest.mark.parametrize("method, path", [
    ("POST", "/guardrails/input"),
    ("PUT", "/v1/tenant/me/dlp-policy"),
    ("GET", "/v1/tenant/me/dlp-policy"),
    ("GET", "/v1/tenant/me/devices"),
    ("POST", "/v1/tenant/me/devices/enrollment-tokens"),
    ("GET", "/v1/edge/policy-bundle"),
    ("POST", "/v1/agents/registry"),
    ("GET", "/v1/devices/heartbeat"),
])
def test_a_device_key_reaches_nothing_else(device, method, path):
    r = device.request(method, path, json={})
    assert r.status_code == 403 and r.json()["error"] == "device_key_scope"


def test_the_limit_holds_in_any_header(app, device):
    from starlette.testclient import TestClient
    for headers in ({"X-Tenant-Key": device.key}, {"Authorization": f"Bearer {device.key}"}):
        r = TestClient(app, headers=headers).put("/v1/tenant/me/dlp-policy", json={})
        assert r.status_code == 403, headers


def test_device_scope_needs_a_device_key():
    from storage.tenant_store import set_key_scope
    with pytest.raises(ValueError, match="device enrollment"):
        set_key_scope("sk-ordinary-" + uuid.uuid4().hex, "device")


def test_heartbeat_and_fleet_view(admin, device):
    from core.dlp.device_policy import DEFAULT_MODEL
    r = device.post("/v1/devices/heartbeat", json={
        "bundle_version": 1790000000, "model_digest": DEFAULT_MODEL["digest"], "mode": "monitor",
        "state": "ok", "counters": {"blocked": 2, "justified": 1}, "agent_version": "0.1.1",
        "future_field": True})
    assert r.status_code == 204, r.text
    row = admin.get(DEVICES).json()["devices"][0]
    assert (row["state"], row["mode"], row["model_ok"], row["stale"]) == ("ok", "monitor", True, False)
    assert row["counters"] == {"blocked": 2, "justified": 1} and row["agent_version"] == "0.1.1"
    device.post("/v1/devices/heartbeat", json={"model_digest": "sha256:" + "0" * 64,
                                               "state": "model_mismatch"})
    row = admin.get(DEVICES).json()["devices"][0]
    assert row["model_ok"] is False and row["state"] == "model_mismatch"


@pytest.mark.parametrize("body", [{"state": "happy"}, {"bundle_version": -1},
                                  {"model_digest": "d45e875d63fe"}, {"mode": "strict"},
                                  {"counters": {"x": -1}}, {"counters": {"x": "1"}}])
def test_heartbeat_validation(device, body):
    assert device.post("/v1/devices/heartbeat", json=body).status_code == 400


def test_a_silent_device_goes_stale(admin, device, monkeypatch):
    device.post("/v1/devices/heartbeat", json={})
    monkeypatch.setenv("SHIELD_DEVICE_STALE_S", "60")
    with patch("time.time", return_value=time.time() + 120):
        d = admin.get(DEVICES).json()
    assert d["devices"][0]["stale"] is True and d["summary"]["stale"] == 1


def test_only_device_keys_send_heartbeats(admin):
    assert admin.post("/v1/devices/heartbeat", json={}).status_code == 403


def test_device_gets_only_its_own_fleets_bundle(admin, device):
    from shield_mavlink.bundle import verify_bundle
    from core.embodied import bundle as edge_bundle
    admin.put("/v1/tenant/me/dlp-policy", json={"fleet_modes": {"finance": "enforce"}})
    r = device.get("/v1/edge/dlp-bundle?fleet=sales")
    assert r.status_code == 200, r.text
    policy = verify_bundle(r.json(), public_key_hex=edge_bundle.public_key_hex(),
                           expect_tenant=device.tenant_id, expect_fleet="sales")
    assert policy["mode"] == "monitor"
    assert device.get("/v1/edge/dlp-bundle?fleet=finance").status_code == 403


def test_events_carry_the_devices_own_identity(device):
    ev = {"kind": "dlp", "decision": "deny", "detail": {
        "verdict": "block", "category": "credentials", "destination": "claude.ai",
        "device_id": "dev_someoneelse00000", "prompt_sha256": "ab" * 32, "prompt_len": 10}}
    with patch("core.runtime_policy.events.ingest") as ingest:
        r = device.post("/v1/shield/runtime/events", json={"events": [ev]})
    assert r.status_code == 202 and r.json()["accepted"] == 1, r.text
    tenant_id, accepted = ingest.call_args.args[:2]
    assert tenant_id == device.tenant_id
    assert accepted[0]["detail"]["device_id"] == device.device_id
    assert accepted[0]["agent_instance_id"] == device.device_id


def test_revoke_stops_the_key_everywhere_at_once(app, admin, device):
    assert device.post("/v1/devices/heartbeat", json={}).status_code == 204
    r = admin.delete(f"{DEVICES}/{device.device_id}")
    assert r.status_code == 200 and r.json()["revoked"] is True
    assert device.post("/v1/devices/heartbeat", json={}).status_code == 401
    assert device.get("/v1/edge/dlp-bundle?fleet=sales").status_code == 401
    assert device.post("/v1/shield/runtime/events",
                       json={"events": [{"kind": "dlp", "decision": "allow",
                                         "detail": {"verdict": "allow"}}]}).status_code == 401
    assert admin.get(DEVICES).json()["summary"]["devices"] == 0
    assert admin.delete(f"{DEVICES}/{device.device_id}").status_code == 404
    assert admin.delete(f"{DEVICES}/not-an-id").status_code == 404


def test_writes_follow_the_registry_write_gate(app, admin, monkeypatch):
    from storage import tenant_store as ts
    runtime_key = "sk-dvr-" + uuid.uuid4().hex
    ts.add_api_key(admin.tenant_id, runtime_key, scope="runtime")
    rt = _client(app, runtime_key)
    token = _token(admin)
    dev = _enroll(app, token).json()
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert rt.post(TOKENS, json={"fleet": "sales"}).status_code == 403
    assert rt.delete(f"{DEVICES}/{dev['device_id']}").status_code == 403
    assert rt.get(DEVICES).status_code == 200


def test_tenants_are_isolated(app, admin, device):
    from storage import tenant_store as ts
    key = "sk-dv-" + uuid.uuid4().hex
    ts.create_tenant("dv" + uuid.uuid4().hex[:10], {"name": "o", "plan": "enterprise"},
                     api_keys=[key])
    other = _client(app, key)
    assert other.get(DEVICES).json()["summary"]["devices"] == 0
    assert other.delete(f"{DEVICES}/{device.device_id}").status_code == 404
    assert other.get(TOKENS).json()["tokens"] == []


def test_enrollment_passes_auth_when_auth_is_on(app, admin):
    """/v1/devices/enroll carries a token, not an API key; the route checks it."""
    from core import auth
    assert "/v1/devices/enroll" in auth._SELF_AUTHENTICATED_PATHS
    assert "/v1/devices/heartbeat" not in auth._SELF_AUTHENTICATED_PATHS


def test_planes_and_packaging():
    admin_src = open(os.path.join(ROOT, "admin_app.py")).read()
    assert "from api.routes_devices import tenant_router as devices_router\n" in admin_src
    assert "device_agent_router" not in admin_src               # enroll/heartbeat: data plane
    assert "COPY api/routes_devices.py api/" in open(os.path.join(ROOT, "Dockerfile.admin")).read()
