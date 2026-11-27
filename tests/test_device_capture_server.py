"""The capture self-check on the server (R5, task 2): heartbeat validation, the
fleet row and summary, the capture filter, and capture.allowed_pac_urls in the
device policy and the signed bundle.

Spec: docs/specs/device-agent-vpn-validation.md, sections 3, 4.2, 5, 7, 8.
"""
import hashlib
import uuid
from unittest.mock import patch

import pytest

from core.dlp import devices as dv
from core.dlp.device_policy import PolicyError, for_fleet, policy_hash, validate_policy

OK = {"state": "ok", "kind": "pac", "effective": "http://127.0.0.1:47823/proxy.pac", "since": 1795700000}
GP = {"state": "overridden", "kind": "pac", "effective": "http://pac.corp.example.com/vpn.pac",
      "since": 1795700100}


# ── validation (pure) ─────────────────────────────────────────────────

def test_capture_object_is_validated_strictly():
    assert dv._capture_state(OK) == OK
    assert dv._capture_state({"state": "missing"}) == {"state": "missing", "kind": "none",
                                                      "effective": "", "since": 0}
    long = dv._capture_state({**GP, "effective": "http://h/" + "a" * 500})
    assert len(long["effective"]) == 200
    for bad, needle in (({"state": "broken"}, "capture.state"), ({**OK, "token": "x"}, "unknown field"),
                        ({**OK, "kind": "socks"}, "capture.kind"), ({**OK, "effective": 5}, "capture.effective"),
                        ({**OK, "since": -1}, "capture.since"), ("ok", "capture.state")):
        with pytest.raises(dv.DeviceError) as e:
            dv._capture_state(bad)
        assert needle in str(e.value)


def test_policy_allowed_pac_urls():
    p = validate_policy({"capture": {"allowed_pac_urls": ["http://pac.corp.example.com/vpn.pac"]}})
    assert p["capture"]["allowed_pac_urls"] == ["http://pac.corp.example.com/vpn.pac"]
    assert for_fleet(p, "eng")["capture"] == p["capture"]                  # travels in the bundle
    with pytest.raises(PolicyError) as e:
        validate_policy({"capture": {"allowed_pac_urls": ["ftp://x/y", "http://h/p?u=1"] + ["http://h/a"] * 9}})
    assert any("at most 10" in x for x in e.value.errors)
    with pytest.raises(PolicyError) as e:
        validate_policy({"capture": {"allowed_pac_urls": ["ftp://x/y"], "auto_fix": True}})
    assert "capture.auto_fix: unknown field" in e.value.errors


def test_section_absent_keeps_the_policy_hash():
    p = validate_policy({"mode": "enforce"})
    assert "capture" not in p and policy_hash(validate_policy(p)) == policy_hash(p)


# ── over HTTP ─────────────────────────────────────────────────────────

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


@pytest.fixture
def tenant(app):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid, key = "cp" + uuid.uuid4().hex[:10], "sk-cp-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


def _laptop(app, tenant, hostname):
    from starlette.testclient import TestClient
    tok = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": "eng"}).json()
    body = {"hostname": hostname, "os": "macos", "os_version": "15.1", "agent_version": "1.0.0",
            "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    dev = TestClient(app).post("/v1/devices/enroll", json=body,
                               headers={"X-Enrollment-Token": tok["enrollment_token"]}).json()
    return TestClient(app, headers={"X-API-Key": dev["api_key"]})


def test_heartbeat_stores_capture_and_leaves_state_alone(app, tenant):
    hb = _laptop(app, tenant, "a-mbp")
    assert hb.post("/v1/devices/heartbeat", json={"state": "ok", "capture": GP}).status_code == 204
    row = tenant.get("/v1/tenant/me/devices").json()["devices"][0]
    assert row["capture"] == GP and row["state"] == "ok"
    r = hb.post("/v1/devices/heartbeat", json={"state": "ok", "capture": {"state": "nope"}})
    assert r.status_code == 400 and "capture.state" in r.text


def test_rows_and_filter(app, tenant):
    """No by_capture count in the summary: the indexed summary is counts only
    and must equal the full read (test_device_fleet_list), so the portal filters
    instead."""
    _laptop(app, tenant, "a-mbp").post("/v1/devices/heartbeat", json={"state": "ok", "capture": OK})
    _laptop(app, tenant, "b-mbp").post("/v1/devices/heartbeat", json={"state": "ok", "capture": GP})
    _laptop(app, tenant, "c-mbp").post("/v1/devices/heartbeat", json={"state": "ok"})   # older agent
    full = tenant.get("/v1/tenant/me/devices").json()
    assert "by_capture" not in full["summary"]
    assert {d["hostname"]: (d.get("capture") or {}).get("state") for d in full["devices"]} == {
        "a-mbp": "ok", "b-mbp": "overridden", "c-mbp": None}
    for value, hosts in (("overridden", ["b-mbp"]), ("ok", ["a-mbp"]), ("not_reported", ["c-mbp"])):
        page = tenant.get(f"/v1/tenant/me/devices?limit=50&capture={value}").json()
        assert [d["hostname"] for d in page["devices"]] == hosts, value
        assert page["filtered"]["capture"] == value and page["indexed"] is True


def test_filter_validation_and_cursor_binding(app, tenant):
    for i in range(3):
        _laptop(app, tenant, f"h{i}").post("/v1/devices/heartbeat", json={"state": "ok", "capture": GP})
    assert tenant.get("/v1/tenant/me/devices?limit=5&capture=sideways").status_code == 400
    assert tenant.get("/v1/tenant/me/devices?capture=ok").status_code == 400      # limit required
    first = tenant.get("/v1/tenant/me/devices?limit=2&capture=overridden").json()
    assert len(first["devices"]) == 2 and first["next_cursor"]
    nxt = tenant.get(f"/v1/tenant/me/devices?limit=2&capture=overridden&cursor={first['next_cursor']}").json()
    assert [d["hostname"] for d in nxt["devices"]] == ["h2"]
    # a cursor is only accepted back with the filters it was issued for
    assert tenant.get(f"/v1/tenant/me/devices?limit=2&cursor={first['next_cursor']}").status_code == 400


def test_full_read_path_filters_the_same(app, tenant, monkeypatch):
    from core.dlp import device_index
    _laptop(app, tenant, "a-mbp").post("/v1/devices/heartbeat", json={"state": "ok", "capture": OK})
    _laptop(app, tenant, "b-mbp").post("/v1/devices/heartbeat", json={"state": "ok", "capture": GP})
    monkeypatch.setattr(device_index, "_usable", lambda tid: False)
    page = tenant.get("/v1/tenant/me/devices?limit=50&capture=overridden").json()
    assert page["indexed"] is False and [d["hostname"] for d in page["devices"]] == ["b-mbp"]


def test_signed_bundle_carries_allowed_pacs(tenant):
    from api.routes_device_dlp import bundle_policy
    r = tenant.put("/v1/tenant/me/dlp-policy",
                   json={"capture": {"allowed_pac_urls": ["http://pac.corp.example.com/vpn.pac"]}})
    assert r.status_code == 200, r.text
    assert bundle_policy(tenant.tenant_id, "eng")["capture"]["allowed_pac_urls"] == [
        "http://pac.corp.example.com/vpn.pac"]
