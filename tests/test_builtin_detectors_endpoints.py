"""Built-in detectors on the endpoints (R3, task 2): the edge bundle, the rule
engine shared by ICAP and the device agent, the device engine, the fallback,
the device policy and the heartbeat.

Spec: docs/specs/builtin-financial-patterns-decoded-pii.md, sections 3, 4, 5, 7, 8.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import sys
import uuid
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (os.path.join(ROOT, "packages", "votal-device-agent"), os.path.join(ROOT, "packages", "shield-mavlink")):
    if p not in sys.path:
        sys.path.insert(0, p)

from core.dlp import detectors as core_detectors  # noqa: E402
from core.dlp import devices as dv  # noqa: E402
from core.dlp.device_policy import (BUILTIN_DETECTOR_IDS, PolicyError, default_policy,  # noqa: E402
                                    detectors_bundle, for_fleet, policy_hash, validate_policy)
from icap.config import IcapConfig  # noqa: E402
from icap.policy import PolicyCache, Tier1Screener  # noqa: E402
from icap.rules import compile_bundle, evaluate, observe, redact  # noqa: E402
from icap.server import IcapRequest  # noqa: E402
from votal_device_agent.engine import Engine  # noqa: E402
from votal_device_agent.trust import BUILTIN_FALLBACK, REQUIRED, Trust  # noqa: E402

CARD = "4556737586899855"                     # valid Visa, not a published test value
CARD_SPACED = "4556 7375 8689 9855"


def det_bundle(**actions):
    """A bundle `detectors` key with every detector at monitor unless given."""
    st = {d: actions.get(d, "monitor") for d in BUILTIN_DETECTOR_IDS}
    return detectors_bundle({"builtin_detectors": validate_policy({"builtin_detectors": st})["builtin_detectors"]})


# ── ids stay in step ──────────────────────────────────────────────────

def test_policy_ids_mirror_the_detector_module():
    assert BUILTIN_DETECTOR_IDS == core_detectors.DETECTORS


# ── compile_bundle ────────────────────────────────────────────────────

def test_old_bundle_without_detectors_compiles_as_before():
    b = compile_bundle({"rules": [], "blocklists": []})
    assert b.detectors == () and b.empty


def test_detectors_make_a_bundle_non_empty_and_off_is_dropped():
    b = compile_bundle({"rules": [], "detectors": det_bundle(swift_bic="off", card_number="block")})
    assert not b.empty and b.can_block
    assert "swift_bic" not in {d.id for d in b.detectors}


def test_malformed_and_unknown_detectors_are_never_fatal(caplog):
    caplog.set_level(logging.INFO)
    rule = {"id": "r1", "regex": "secret", "action": "block"}
    for bad in ("nope", {"items": "x"}, ["x"]):
        b = compile_bundle({"rules": [rule], "detectors": bad})
        assert b.detectors == () and len(b.rules) == 1
    b = compile_bundle({"detectors": {"schema": 9, "items": [
        {"id": "future_id", "action": "block"}, {"id": "iban", "action": "explode"},
        {"id": "card_number", "action": "block"}]}})
    assert [d.id for d in b.detectors] == ["card_number"]


@pytest.mark.parametrize("fallback,expected", [("pass", "monitor"), ("block", "block")])
def test_icap_redact_detector_resolves_through_redact_fallback(fallback, expected):
    b = compile_bundle({"detectors": det_bundle(card_number="redact")}, redact_fallback=fallback)
    assert {d.id: d.action for d in b.detectors}["card_number"] == expected
    kept = compile_bundle({"detectors": det_bundle(card_number="redact")}, keep_redact=True)
    assert {d.id: d.action for d in kept.detectors}["card_number"] == "redact"


# ── evaluate / redact / observe ───────────────────────────────────────

def test_block_detector_hit():
    b = compile_bundle({"detectors": det_bundle(card_number="block")})
    hit = evaluate(b, f"charge {CARD_SPACED}")
    assert hit.kind == "detector" and hit.rule_id == "builtin:card_number" and hit.severity == "high"
    assert evaluate(b, "nothing here") is None


def test_block_detector_finds_encoded_values():
    b = compile_bundle({"detectors": det_bundle(card_number="block")})
    enc = base64.b64encode(f"card {CARD}".encode()).decode()
    assert evaluate(b, f"see {enc}").rule_id == "builtin:card_number"


def test_monitor_detectors_never_block_but_are_observed():
    b = compile_bundle({"detectors": det_bundle()})
    assert evaluate(b, f"card {CARD}") is None
    assert [h.rule_id for h in observe(b, f"card {CARD} and SSN 219-09-9999")] == [
        "builtin:card_number", "builtin:us_ssn"]


def test_redact_detector_rewrites_plain_and_encoded():
    b = compile_bundle({"detectors": det_bundle(card_number="redact")}, keep_redact=True)
    enc = base64.b64encode(f"card {CARD}".encode()).decode()
    out, hits = redact(b, f"pay {CARD_SPACED} or {enc}")
    assert out == "pay [REDACTED:card_number] or [REDACTED:card_number]"
    assert [h.rule_id for h in hits] == ["builtin:card_number"]


def test_test_values_follow_the_bundle_switch():
    data = det_bundle(card_number="block")
    assert evaluate(compile_bundle({"detectors": data}), "4111 1111 1111 1111") is not None
    data["ignore_test_values"] = True
    assert evaluate(compile_bundle({"detectors": data}), "4111 1111 1111 1111") is None


def test_detector_timeout_raises_like_rules():
    b = compile_bundle({"detectors": det_bundle(card_number="block")})
    with pytest.raises(TimeoutError):
        evaluate(b, "x " * 1000, timeout_s=0)


def test_observe_never_raises():
    b = compile_bundle({"detectors": det_bundle()})
    assert observe(b, f"card {CARD}", timeout_s=0) == []


# ── device policy ─────────────────────────────────────────────────────

def test_section_absent_keeps_the_policy_hash():
    """Stored only when set: re-validating an untouched policy never adds the
    section, so its hash (and every laptop's bundle) is unchanged."""
    p = validate_policy({"mode": "enforce"})
    assert "builtin_detectors" not in p and "builtin_detectors" not in default_policy()
    assert policy_hash(validate_policy(p)) == policy_hash(p)


def test_section_is_validated_strictly():
    ok = validate_policy({"builtin_detectors": {"card_number": "block", "decode": False}})
    assert ok["builtin_detectors"]["card_number"] == "block"
    assert ok["builtin_detectors"]["iban"] == "monitor" and ok["builtin_detectors"]["decode"] is False
    with pytest.raises(PolicyError) as e:
        validate_policy({"builtin_detectors": {"cvv": "block", "iban": "shout", "decode": "yes"}})
    errs = " ".join(e.value.errors)
    assert "builtin_detectors.cvv: unknown field" in errs
    assert "builtin_detectors.iban" in errs and "builtin_detectors.decode" in errs


def test_detectors_bundle_defaults_and_kill_switch(monkeypatch):
    d = detectors_bundle(None)
    assert d["schema"] == core_detectors.SCHEMA and d["decode"] is True
    assert [(i["id"], i["action"]) for i in d["items"]] == [(x, "monitor") for x in BUILTIN_DETECTOR_IDS]
    monkeypatch.setenv("SHIELD_BUILTIN_DETECTORS", "off")
    assert detectors_bundle(None) is None


# ── device fallback and the device engine ─────────────────────────────

def test_fallback_runs_every_detector_in_monitor():
    assert [(i["id"], i["action"]) for i in BUILTIN_FALLBACK["detectors"]["items"]] == [
        (x, "monitor") for x in BUILTIN_DETECTOR_IDS]
    assert "detectors" not in REQUIRED        # older agents still verify the bundle


class _Audit:
    def __init__(self):
        self.records = []

    def record(self, d):
        self.records.append(d)


def _engine(mode="enforce", **actions):
    policy = {**for_fleet(validate_policy({"mode": mode}), "eng"), "rules": [], "blocklists": [],
              "detectors": det_bundle(**actions)}
    audit = _Audit()
    return Engine(Trust("verified", policy, "", {"bundle_version": 7}), None, audit=audit), audit


def test_engine_records_monitor_hits_without_acting():
    eng, audit = _engine()
    d = eng.check(f"my card {CARD}", "chatgpt.com")
    assert d.action == "allow" and d.verdict == "monitor"
    assert d.rule_ids == ["builtin:card_number"] and audit.records


def test_engine_blocks_and_redacts_when_set():
    eng, _ = _engine(card_number="block")
    assert eng.check(f"my card {CARD}", "chatgpt.com").action == "block"
    eng, _ = _engine(card_number="redact")
    d = eng.check(f"my card {CARD_SPACED}", "chatgpt.com")
    assert d.action == "redact" and d.text == "my card [REDACTED:card_number]"


def test_fleet_in_monitor_mode_never_blocks():
    eng, audit = _engine(mode="monitor", card_number="block")
    d = eng.check(f"my card {CARD}", "chatgpt.com")
    assert d.action == "allow" and d.verdict == "block" and audit.records


def test_engine_ignores_non_ai_hosts():
    eng, audit = _engine(card_number="block")
    assert eng.check(f"card {CARD}", "example.com").action == "allow" and not audit.records


# ── ICAP screener ─────────────────────────────────────────────────────

def _req(text):
    body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode()
    return IcapRequest(method="REQMOD", service="/screen", headers={}, body=body,
                       http_headers={"host": "api.openai.com"})


def _screen(bundle, text):
    cfg = IcapConfig(api_key="k", api_base="https://shield.test", version="b1")
    cache = PolicyCache(cfg)
    cache._bundle = bundle
    return asyncio.run(Tier1Screener(cache, cfg)(_req(text)))


def test_icap_blocks_on_a_detector_only_bundle():
    v = _screen(compile_bundle({"detectors": det_bundle(card_number="block")}), f"card {CARD}")
    assert v.block and v.rule_id == "builtin:card_number"
    assert "data matching policy: builtin:card_number" in v.payload["reason"]


def test_icap_logs_monitor_detectors_without_the_value(caplog):
    caplog.set_level(logging.INFO, logger="shield.icap")
    v = _screen(compile_bundle({"detectors": det_bundle()}), f"card {CARD}")
    assert not v.block
    assert "detectors=builtin:card_number" in caplog.text and CARD not in caplog.text


# ── bundles and heartbeat over HTTP ───────────────────────────────────

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
    tid = "bd" + uuid.uuid4().hex[:10]
    key = "sk-bd-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


def test_edge_bundle_carries_detectors_and_follows_the_policy(tenant, monkeypatch):
    b = tenant.get("/v1/edge/policy-bundle").json()
    assert {i["id"]: i["action"] for i in b["detectors"]["items"]}["card_number"] == "monitor"
    r = tenant.put("/v1/tenant/me/dlp-policy", json={"builtin_detectors": {"card_number": "block",
                                                                           "iban": "off"}})
    assert r.status_code == 200, r.text
    b2 = tenant.get("/v1/edge/policy-bundle").json()
    items = {i["id"]: i["action"] for i in b2["detectors"]["items"]}
    assert items["card_number"] == "block" and "iban" not in items
    assert b2["version"] != b["version"]
    monkeypatch.setenv("SHIELD_BUILTIN_DETECTORS", "off")
    assert "detectors" not in tenant.get("/v1/edge/policy-bundle").json()


def test_dlp_policy_put_rejects_unknown_detector(tenant):
    r = tenant.put("/v1/tenant/me/dlp-policy", json={"builtin_detectors": {"cvv": "block"}})
    assert r.status_code == 422
    assert any("builtin_detectors.cvv" in e for e in r.json()["detail"]["errors"])


def test_signed_device_bundle_carries_detectors(tenant):
    from api.routes_device_dlp import bundle_policy
    out = bundle_policy(tenant.tenant_id, "eng")
    assert out["detectors"]["schema"] == core_detectors.SCHEMA
    assert all(k in out for k in REQUIRED)


def test_heartbeat_stores_detectors_schema(app, tenant):
    from starlette.testclient import TestClient
    tok = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": "eng"}).json()
    laptop = {"hostname": "bd-mbp", "os": "macos", "os_version": "15.1", "agent_version": "1.0.0",
              "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    dev = TestClient(app).post("/v1/devices/enroll", json=laptop,
                               headers={"X-Enrollment-Token": tok["enrollment_token"]}).json()
    hb = TestClient(app, headers={"X-API-Key": dev["api_key"]})
    assert hb.post("/v1/devices/heartbeat", json={"state": "ok", "detectors_schema": 1}).status_code == 204
    row = tenant.get("/v1/tenant/me/devices").json()["devices"][0]
    assert row["detectors_schema"] == 1
    # a bad value is dropped, never a reason to refuse the heartbeat
    assert hb.post("/v1/devices/heartbeat", json={"state": "ok", "detectors_schema": "x"}).status_code == 204
    assert "detectors_schema" not in tenant.get("/v1/tenant/me/devices").json()["devices"][0]
