"""Device DLP agent, task 2: the server side.
Spec: docs/specs/device-dlp-agent.md §3.2, §5.1, §6.

- the rule engine shared by ICAP and the agent (icap/rules.py)
- the tenant's DLP policy: defaults from task 1, strict validation, API
- the signed /v1/edge/dlp-bundle, verified with the edge devices' own verifier
- runtime events of kind "dlp", which never carry prompt text
"""

import copy
import json
import os
import sys
import uuid
from unittest.mock import patch

import pytest

from core.dlp import device_policy as dp

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PKG = os.path.join(ROOT, "packages", "shield-mavlink")
if PKG not in sys.path:
    sys.path.insert(0, PKG)

BASE = "/v1/tenant/me/dlp-policy"
BUNDLE = "/v1/edge/dlp-bundle"


# ── the shared rule engine ───────────────────────────────────────────


RULES = {"rules": [
    {"id": "ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "action": "redact", "severity": "high",
     "replacement": "[SSN]"},
    {"id": "akia", "regex": r"AKIA[0-9A-Z]{16}", "action": "block", "severity": "critical"},
    {"id": "email", "regex": r"[\w.]+@example\.com", "action": "redact", "severity": "medium"},
], "blocklists": ["project-atlas"]}


def test_icap_keeps_its_names_and_behaviour():
    from icap import policy, rules
    for name in ("Bundle", "Rule", "Hit", "EMPTY", "compile_bundle", "evaluate"):
        assert getattr(policy, name) is getattr(rules, name)
    b = rules.compile_bundle(RULES)                                  # ICAP: redact -> pass
    assert [r.action for r in b.rules] == ["pass", "block", "pass"]
    assert rules.compile_bundle(RULES, redact_fallback="block").blocking_rules == 3


def test_the_agent_keeps_redact_rules_and_can_rewrite():
    from icap.rules import compile_bundle, evaluate, redact
    b = compile_bundle(RULES, keep_redact=True)
    assert [r.action for r in b.rules] == ["redact", "block", "redact"]
    text, hits = redact(b, "ssn 123-45-6789, mail ana@example.com, ssn 987-65-4321")
    assert text == "ssn [SSN], mail [REDACTED], ssn [SSN]"
    assert [h.rule_id for h in hits] == ["ssn", "email"]
    assert evaluate(b, "no hits here 123-45-6789") is None           # redact rules never block
    assert evaluate(b, "key AKIAIOSFODNN7EXAMPLE").rule_id == "akia"
    assert evaluate(b, "Project-Atlas numbers").kind == "blocklist"
    assert redact(b, "") == ("", [])


def test_redact_shares_one_deadline():
    from icap.rules import compile_bundle, redact
    import time
    slow = [{"id": f"redos-{i}", "regex": r"(a|a)*$", "action": "redact"} for i in range(10)]
    b = compile_bundle({"rules": slow}, keep_redact=True)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        redact(b, "a" * 40 + "!", timeout_s=0.1)
    assert time.monotonic() - started < 0.5


# ── the policy model ─────────────────────────────────────────────────


def test_defaults_are_what_task_1_measured():
    from icap.config import DEFAULT_AI_HOSTS
    assert tuple(dp.DEFAULT_AI_HOSTS) == tuple(DEFAULT_AI_HOSTS)
    q2 = json.load(open(os.path.join(ROOT, "dlp-bench", "questions_v2.json")))
    assert dp.DEFAULT_QUESTIONS == q2["questions"]
    report = json.load(open(os.path.join(
        ROOT, "dlp-bench", "reports", "tev1-0.8b-apple_silicon-q2-actual-data.json")))
    assert dp.DEFAULT_THRESHOLDS == report["thresholds_calibrated"]
    assert report["model"] == dp.DEFAULT_MODEL["name"]
    p = dp.validate_policy({})
    assert p["mode"] == "monitor" and p["fail_mode"] == "allow"
    assert p["privacy"] == {"capture_excerpt": False, "server_screen": False}
    # The categories Tev1 0.8B missed in task 1 cannot enforce by default.
    assert {k for k, v in p["enforcement"].items() if v == "monitor"} == \
        {"source_code", "financial", "exfil_intent"}
    assert p == dp.validate_policy(p)                                 # normalizing is idempotent


@pytest.mark.parametrize("patch_, needle", [
    ({"turbo": True}, "turbo: unknown field"),
    ({"mode": "strict"}, "mode: one of"),
    ({"ai_hosts": ["chatgpt.com", "not a host"]}, "not a hostname"),
    ({"ai_hosts": []}, "ai_hosts: a list"),
    ({"thresholds": {"block_categories": ["source_code"]}}, "monitor-only"),
    ({"thresholds": {"block_categories": ["weather"]}}, "not a category the questions ask"),
    ({"thresholds": {"justify_p": 0.9, "block_p": 0.5}}, "must not be above block_p"),
    ({"thresholds": {"block_p": 1.5}}, "block_p: a number from 0 to 1"),
    ({"enforcement": {"health": "block"}}, "enforcement.health: one of"),
    ({"enforcement": {"weather": "monitor"}}, "weather: unknown field"),
    ({"model": {"name": "tev1:0.8b", "digest": "d45e875d63fe"}}, "model.digest"),
    ({"model": {"name": "tev1:0.8b", "min_ollama": "latest"}}, "min_ollama"),
    ({"fleet_modes": {"Sales Team": "enforce"}}, "fleet id"),
    ({"model_timeout_ms": 50}, "model_timeout_ms"),
    ({"privacy": {"capture_excerpt": "yes"}}, "privacy.capture_excerpt"),
    ({"pinned_host_action": {"default": "ignore"}}, "pinned_host_action.default"),
])
def test_strict_validation(patch_, needle):
    with pytest.raises(dp.PolicyError) as e:
        dp.validate_policy(patch_)
    assert any(needle in err for err in e.value.errors), e.value.errors


def test_questions_must_keep_none_and_known_categories():
    q = copy.deepcopy(dp.DEFAULT_QUESTIONS)
    del q["category"]["criteria"]["none"]
    q["category"]["criteria"]["weather"] = "Weather reports"
    q["category"]["instructions"] = "x" * 2000
    with pytest.raises(dp.PolicyError) as e:
        dp.validate_policy({"questions": q})
    errs = " | ".join(e.value.errors)
    assert "criteria.none: required" in errs and "unknown category" in errs
    assert "at most 1000 characters" in errs


def test_every_error_is_reported_at_once():
    with pytest.raises(dp.PolicyError) as e:
        dp.validate_policy({"mode": "x", "fail_mode": "maybe", "grace_s": -1})
    assert len(e.value.errors) == 3


def test_hosts_are_normalized_and_fleets_resolved():
    p = dp.validate_policy({"ai_hosts": ["ChatGPT.com.", "claude.ai", "chatgpt.com"],
                            "fleet_modes": {"finance": "enforce"}})
    assert p["ai_hosts"] == ["chatgpt.com", "claude.ai"]
    assert dp.for_fleet(p, "finance")["mode"] == "enforce"
    assert dp.for_fleet(p, "sales")["mode"] == "monitor"
    assert "fleet_modes" not in dp.for_fleet(p, "finance")      # a device sees only its own


# ── the API ──────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _tenant(app, scope=None):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid = "dlp" + uuid.uuid4().hex[:10]
    key = "sk-dlp-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    if scope:
        ts.set_key_scope(key, scope)
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id, c.key = tid, key
    return c


@pytest.fixture
def client(app):
    return _tenant(app)


def test_get_put_validate(client):
    got = client.get(BASE).json()
    assert got["stored"] is False and got["policy"] == dp.default_policy()
    r = client.put(BASE, json={"mode": "enforce", "fleet_modes": {"sales": "monitor"}})
    assert r.status_code == 200, r.text
    got = client.get(BASE).json()
    assert got["stored"] is True and got["policy"]["mode"] == "enforce"
    assert got["hash"] == r.json()["hash"] and got["updated_by"].startswith("tenant:")
    bad = client.put(BASE, json={"mode": "x", "turbo": 1})
    assert bad.status_code == 422 and len(bad.json()["detail"]["errors"]) == 2
    assert client.get(BASE).json()["policy"]["mode"] == "enforce"   # a bad PUT changes nothing
    assert client.post(f"{BASE}/validate", json={"mode": "x"}).json()["valid"] is False
    assert client.post(f"{BASE}/validate", json={}).json()["valid"] is True


def test_writes_follow_the_registry_write_gate(app, monkeypatch):
    from storage import tenant_store as ts
    admin = _tenant(app, scope="admin")
    device_key = "sk-dlpd-" + uuid.uuid4().hex
    ts.add_api_key(admin.tenant_id, device_key, scope="runtime")
    from starlette.testclient import TestClient
    device = TestClient(app, headers={"X-API-Key": device_key})
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert device.put(BASE, json={"mode": "monitor"}).status_code == 403
    assert device.get(BASE).status_code == 200
    assert admin.put(BASE, json={"mode": "enforce"}).status_code == 200


def test_tenants_are_isolated(app, client):
    client.put(BASE, json={"mode": "enforce"})
    assert _tenant(app).get(BASE).json()["stored"] is False


def test_corrupt_stored_policy_is_reported_not_shipped(client):
    from storage.tenant_store import kv_set
    kv_set(f"dlp_policy:{client.tenant_id}", {"policy": {"mode": "off"}})
    assert client.get(BASE).status_code == 409
    assert client.get(f"{BASE.replace('/tenant/me/dlp-policy', '/edge/dlp-bundle')}"
                      "?fleet=sales").status_code == 409


# ── the signed bundle ────────────────────────────────────────────────


@pytest.fixture
def signing(monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    rt_bundle.reset_signer_cache_for_tests()
    yield rt_bundle.get_signer().public_key_bytes().hex()
    rt_bundle.reset_signer_cache_for_tests()


@pytest.fixture
def tenant_rules(monkeypatch):
    import api.routes_edge as edge
    monkeypatch.setattr(edge, "_load_all", lambda t: {"crm": {"sanitization_rules": [
        {"pattern_id": "ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "severity": "high",
         "replacement": "[SSN]", "enabled": True}]}})


def test_no_signing_key_no_bundle(client, monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    monkeypatch.delenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", raising=False)
    rt_bundle.reset_signer_cache_for_tests()
    r = client.get(f"{BUNDLE}?fleet=sales")
    assert r.status_code == 503 and "signed" in r.text
    rt_bundle.reset_signer_cache_for_tests()


def test_bundle_is_signed_bound_and_carries_the_rules(client, signing, tenant_rules):
    from shield_mavlink.bundle import BundleError, verify_bundle
    from icap.rules import compile_bundle, redact
    client.put(BASE, json={"fleet_modes": {"finance": "enforce"}})
    r = client.get(f"{BUNDLE}?fleet=finance")
    assert r.status_code == 200, r.text
    signed = r.json()
    policy = verify_bundle(signed, public_key_hex=signing, expect_tenant=client.tenant_id,
                           expect_fleet="finance")
    assert policy["mode"] == "enforce" and "fleet_modes" not in policy
    assert policy["questions"] == dp.DEFAULT_QUESTIONS and policy["rules_version"]
    assert signed["header"]["expires_at"] - signed["header"]["issued_at"] == 86400
    # What the agent will do with it: the same engine, keeping redact rules.
    text, hits = redact(compile_bundle(policy, keep_redact=True), "ssn 123-45-6789")
    assert text == "ssn [SSN]" and hits[0].rule_id == "ssn"
    with pytest.raises(BundleError):                                  # bound to its fleet
        verify_bundle(signed, public_key_hex=signing, expect_tenant=client.tenant_id,
                      expect_fleet="sales")
    tampered = copy.deepcopy(signed)
    tampered["policy"]["mode"] = "monitor"
    with pytest.raises(BundleError):
        verify_bundle(tampered, public_key_hex=signing, expect_tenant=client.tenant_id,
                      expect_fleet="finance")
    other = client.get(f"{BUNDLE}?fleet=sales").json()
    assert other["policy"]["mode"] == "monitor"


def test_bundle_etag_and_fleet_names(client, signing, tenant_rules):
    first = client.get(f"{BUNDLE}?fleet=sales")
    etag = first.headers["ETag"]
    assert client.get(f"{BUNDLE}?fleet=sales", headers={"If-None-Match": etag}).status_code == 304
    client.put(BASE, json={"mode": "enforce"})
    assert client.get(f"{BUNDLE}?fleet=sales",
                      headers={"If-None-Match": etag}).status_code == 200  # policy changed
    assert client.get(f"{BUNDLE}?fleet=Sales%20Team").status_code == 400
    assert client.get(BUNDLE).status_code == 422


def test_signed_validity_is_configurable(client, signing, monkeypatch):
    monkeypatch.setenv("SHIELD_DLP_BUNDLE_VALID_S", "3600")
    h = client.get(f"{BUNDLE}?fleet=sales").json()["header"]
    assert h["expires_at"] - h["issued_at"] == 3600


def test_planes():
    """Policy API on both planes; the bundle on the data plane only (spec §6)."""
    admin = open(os.path.join(ROOT, "admin_app.py")).read()
    assert "from api.routes_device_dlp import router as device_dlp_router\n" in admin
    assert "edge_router as device_dlp" not in admin
    assert "COPY api/routes_device_dlp.py api/" in open(os.path.join(ROOT, "Dockerfile.admin")).read()


# ── events of kind "dlp" ─────────────────────────────────────────────


DLP_EVENT = {"source": "custom", "kind": "dlp", "decision": "deny", "severity": "high",
             "detail": {"verdict": "block", "category": "credentials", "destination": "chatgpt.com",
                        "app": "Google Chrome", "device_id": "dev-1", "prompt_sha256": "ab" * 32,
                        "prompt_len": 412, "probabilities": {"credentials": 0.91, "none": 0.05}}}


def test_dlp_events_normalize_summarize_and_map():
    from core.runtime_policy import events as ev
    n = ev.normalize(DLP_EVENT)
    assert ev.summary(n) == "dlp block credentials to chatgpt.com from dev-1"
    t = ev.telemetry_fields(n)
    assert t["destination.domain"] == "chatgpt.com" and t["votal.dlp.verdict"] == "block"
    assert t["votal.dlp.category"] == "credentials"
    ok = copy.deepcopy(DLP_EVENT)
    ok["detail"]["excerpt"] = "my key is [REDACTED]"
    ev.normalize(ok)


@pytest.mark.parametrize("change, needle", [
    ({"prompt": "the whole prompt"}, "carry no prompt text"),
    ({"text": "the whole prompt"}, "carry no prompt text"),
    ({"excerpt": "x" * 201}, "at most 200"),
    ({"verdict": "shrug"}, "detail.verdict"),
])
def test_dlp_events_never_carry_the_prompt(change, needle):
    from core.runtime_policy import events as ev
    bad = copy.deepcopy(DLP_EVENT)
    bad["detail"].update(change)
    with pytest.raises(ev.EventError, match=needle):
        ev.normalize(bad)


def test_file_events_may_still_say_text():
    """The no-text rule is for dlp events only."""
    from core.runtime_policy import events as ev
    ev.normalize({"kind": "file", "decision": "allow", "detail": {"path": "/x", "text": "y"}})
