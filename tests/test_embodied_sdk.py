"""Embodied action guard, task 4: the robot SDK, signed bundles, audit upload.
Spec: docs/specs/embodied-action-guard.md §5.2, §7, §8, §11."""

import base64
import copy
import filecmp
import json
import os
import sys
import time
import uuid
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK = os.path.join(ROOT, "packages", "shield-embodied")
if SDK not in sys.path:
    sys.path.insert(0, SDK)

from shield_embodied import Guard, facts, sync  # noqa: E402
from shield_embodied.guard import OfflineAuditChain, verify_bundle  # noqa: E402

from core.embodied import cache as em_cache  # noqa: E402
from core.embodied import store as em_store  # noqa: E402
from core.embodied.evaluator import evaluate  # noqa: E402
from core.embodied.model import validate_profile  # noqa: E402
from core.runtime_policy import bundle as rt_bundle  # noqa: E402

BENCH = os.path.join(ROOT, "embodied-bench")
CASES = [json.loads(l) for l in open(os.path.join(BENCH, "embodied_guardrail_bench.jsonl"))
         if l.strip()]
PROFILE = json.load(open(os.path.join(BENCH, "shield_profile.json")))
KEY_HEX = "5c" * 32


# ── parity by construction ───────────────────────────────────────────


@pytest.mark.parametrize("name", ["evaluator.py", "model.py"])
def test_robot_copy_is_byte_identical_to_the_server(name):
    assert filecmp.cmp(os.path.join(ROOT, "core", "embodied", name),
                       os.path.join(SDK, "shield_embodied", name), shallow=False), \
        f"packages/shield-embodied/shield_embodied/{name} drifted from core/embodied/{name}"


# ── server: signed bundles ───────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", KEY_HEX)
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_KID", "edge-test")
    rt_bundle.reset_signer_cache_for_tests()
    em_store.reset_memory()
    em_cache.invalidate()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    em_store.reset_memory()
    em_cache.invalidate()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant
    tid = "es" + uuid.uuid4().hex[:10]
    key = "sk-es-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    c.put("/v1/tenant/me/embodied-profiles/bench", json=PROFILE)
    return c


def _pubkey(client):
    return client.get("/v1/edge/embodied-bundle/pubkey").json()["public_key_hex"]


def _bundle(client, fleet="hospital-east"):
    r = client.get(f"/v1/edge/embodied-bundle?profile=bench&fleet={fleet}")
    assert r.status_code == 200, r.text
    return r


def test_server_bundle_verifies_with_the_mavlink_verifier(client):
    b = _bundle(client).json()
    policy = verify_bundle(b, public_key_hex=_pubkey(client), expect_tenant=client.tenant_id,
                           expect_fleet="hospital-east")
    assert validate_profile(policy) == validate_profile(PROFILE)
    assert b["header"]["kid"] == "edge-test" and b["profile_hash"].startswith("sha256:")


def test_bundle_endpoint_etag_and_errors(client, monkeypatch):
    r = _bundle(client)
    again = client.get("/v1/edge/embodied-bundle?profile=bench&fleet=hospital-east",
                       headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304
    other_fleet = client.get("/v1/edge/embodied-bundle?profile=bench&fleet=warehouse-2",
                             headers={"If-None-Match": r.headers["etag"]})
    assert other_fleet.status_code == 200                                   # bound per fleet
    assert client.get("/v1/edge/embodied-bundle?profile=nope&fleet=f").status_code == 404
    assert client.get("/v1/edge/embodied-bundle?profile=bench&fleet=Bad Fleet").status_code == 400
    monkeypatch.delenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY")
    rt_bundle.reset_signer_cache_for_tests()
    assert client.get("/v1/edge/embodied-bundle?profile=bench&fleet=f").status_code == 503
    assert client.get("/v1/edge/embodied-bundle/pubkey").status_code == 503


# ── the robot ────────────────────────────────────────────────────────


@pytest.fixture
def robot(client, tmp_path):
    """A robot provisioned with the server's bundle and pinned key."""
    path = tmp_path / "embodied.bundle"
    path.write_text(json.dumps(_bundle(client).json()))
    keyfile = tmp_path / "fleet.pub"
    keyfile.write_text(_pubkey(client))
    return {"bundle": str(path), "key": str(keyfile), "tenant": client.tenant_id,
            "fleet": "hospital-east", "dir": tmp_path}


def _guard(robot, **kw):
    return Guard.from_bundle(robot["bundle"], pinned_key=robot["key"], tenant=robot["tenant"],
                             fleet=robot["fleet"], **kw)


def test_robot_and_server_decide_identically(client, robot):
    g = _guard(robot)
    assert g.mode == "normal"
    for c in CASES:
        local = g.check_event(c["event"])
        server = client.post("/v1/shield/embodied/check?profile=bench", json=c["event"]).json()
        assert (local.verdict, local.rail, local.reasons) == \
            (server["verdict"], server["rail"], server["reasons"]), c["id"]
        assert local.profile_hash == server["profile_hash"]


def test_check_builds_the_event_from_action_and_state(robot):
    g = _guard(robot)
    d = g.check(action={"tool": "base_push", "params": {"velocity_mps": 1.4, "force_n": 210}},
                state={"nearest_human_m": 1.1}, run_id="r1", step=7)
    assert (d.verdict, d.rail) == ("block", "envelope_guard") and not d.allowed


@pytest.mark.parametrize("attack", ["tampered", "foreign_fleet", "self_signed", "missing",
                                    "garbage"])
def test_an_untrustworthy_bundle_means_degraded_not_permissive(robot, attack):
    path = robot["bundle"]
    b = json.loads(open(path).read())
    fleet = robot["fleet"]
    if attack == "tampered":
        b["policy"]["envelope"]["max_velocity_near_human_mps"] = 9.0
    elif attack == "foreign_fleet":
        fleet = "someone-elses-fleet"
    elif attack == "self_signed":
        from shield_mavlink.bundle import sign_bundle
        b = sign_bundle(b["policy"], private_key_hex="11" * 32, tenant_id=robot["tenant"],
                        fleet_id=fleet, bundle_version=99, valid_for_s=3600)
    if attack == "missing":
        os.remove(path)
    elif attack == "garbage":
        open(path, "w").write("{not json")
    else:
        open(path, "w").write(json.dumps(b))
    g = Guard.from_bundle(path, pinned_key=robot["key"], tenant=robot["tenant"], fleet=fleet)
    assert g.mode == "degraded_unverified" and g.profile is None
    assert g.check(action={"tool": "navigate", "params": {}}).rail == "degraded_mode"
    assert g.check(action={"tool": "stop", "params": {}}).verdict == "pass"
    assert g.check(action={"tool": "return_to_base",
                           "params": {"velocity_mps": 1.0}}).reasons == ["degraded_speed_cap"]


def test_an_expired_bundle_uses_its_own_degraded_rules(robot):
    later = int(time.time()) + 3 * 86400
    g = _guard(robot, now=later)
    assert g.mode == "degraded_expired" and "expired" in g.mode_reason
    assert g.check(action={"tool": "navigate", "params": {}}).verdict == "block"
    assert g.check(action={"tool": "dock", "params": {"velocity_mps": 0.2}}).verdict == "pass"


def test_decisions_are_chained_and_unrecordable_ones_refused(robot):
    audit_dir = robot["dir"] / "audit"
    g = _guard(robot, audit_dir=str(audit_dir))
    for c in CASES:
        g.check_event(c["event"])
    chain = OfflineAuditChain(str(audit_dir))
    records = list(chain.records())
    assert len(records) == 18                         # the non-pass verdicts only (EBG-016 passes)
    assert chain.verify().intact
    with patch.object(OfflineAuditChain, "append", side_effect=OSError("disk full")):
        d = g.check(action={"tool": "base_push", "params": {"velocity_mps": 9}})
    assert (d.verdict, d.rail) == ("block", "audit_unavailable")


def test_audit_passes_records_everything(robot):
    g = _guard(robot, audit_dir=str(robot["dir"] / "all"), audit_passes=True)
    for c in CASES:
        g.check_event(c["event"])
    assert len(list(OfflineAuditChain(str(robot["dir"] / "all")).records())) == 26


def test_robot_latency_p99_under_one_millisecond(robot):
    g = _guard(robot)
    samples = []
    for _ in range(40):
        for c in CASES:
            samples.append(g.check_event(c["event"]).evaluated_us)
    samples.sort()
    assert samples[int(len(samples) * 0.99)] < 1000


# ── facts from real signed tokens ────────────────────────────────────


def _jwt(claims, key_hex):
    from core.jwt_utils import encode_jwt
    from core.signers import LocalEd25519Signer
    return encode_jwt(claims, LocalEd25519Signer(kid="cap", private_key_hex=key_hex))


def _pub(key_hex):
    from core.signers import LocalEd25519Signer
    return LocalEd25519Signer(kid="cap", private_key_hex=key_hex).public_key_bytes().hex()


def test_capability_facts_and_replay():
    now = time.time()
    token = _jwt({"tenant_id": "t1", "tool": "teleop_execute", "resource": "traj-88a",
                  "nonce": "n-1", "iat": int(now) - 10, "exp": int(now) + 110}, "22" * 32)
    cache = facts.NonceCache()
    f = facts.capability_facts(token, public_key_hex=_pub("22" * 32), nonce_cache=cache,
                               tenant="t1", now=now)
    assert f["nonce_seen_before"] is False and 9 <= f["issued_s_ago"] <= 11 and f["ttl_s"] == 120
    again = facts.capability_facts(token, public_key_hex=_pub("22" * 32), nonce_cache=cache,
                                   tenant="t1", now=now)
    assert again["nonce_seen_before"] is True                                 # replay
    assert facts.capability_facts(token, public_key_hex=_pub("33" * 32), nonce_cache=cache) is None
    assert facts.capability_facts(token, public_key_hex=_pub("22" * 32), nonce_cache=cache,
                                  tenant="t2") is None
    assert facts.capability_facts("not.a.jwt", public_key_hex=_pub("22" * 32),
                                  nonce_cache=cache) is None


def test_zone_tokens_feed_the_scope_rail(robot):
    now = time.time()
    good = _jwt({"tenant_id": "t1", "tool": "navigate", "resource": "zone:ward_b", "nonce": "z1",
                 "iat": int(now), "exp": int(now) + 300}, "22" * 32)
    forged = _jwt({"tenant_id": "t1", "tool": "navigate", "resource": "zone:ward_b",
                   "nonce": "z2", "iat": int(now), "exp": int(now) + 300}, "44" * 32)
    cache = facts.NonceCache()
    g = _guard(robot)
    action = {"tool": "navigate", "params": {"target_zone": "ward_b"}}
    ok_tokens = facts.zone_tokens([good], public_key_hex=_pub("22" * 32), nonce_cache=cache,
                                  tenant="t1", now=now)
    assert g.check(action=action, state={"role": "logistics",
                                         "capability_tokens": ok_tokens}).verdict == "pass"
    forged_tokens = facts.zone_tokens([forged], public_key_hex=_pub("22" * 32),
                                      nonce_cache=cache, tenant="t1", now=now)
    assert forged_tokens == []
    assert g.check(action=action, state={"role": "logistics",
                                         "capability_tokens": forged_tokens}).rail == \
        "scope_boundaries"


def test_peer_state_facts():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw().hex()
    payload = b'{"map":"floor2","v":7}'
    sig = base64.b64encode(sk.sign(payload)).decode()
    now = time.time()
    assert facts.peer_state_facts(payload, sig, peer_public_key_hex=pub, signed_at=now - 40,
                                  now=now) == {"peer_attestation": "verified",
                                               "peer_last_verified_s": pytest.approx(40)}
    assert facts.peer_state_facts(payload + b" ", sig, peer_public_key_hex=pub,
                                  signed_at=now, now=now)["peer_attestation"] is None
    assert facts.peer_state_facts(payload, None, peer_public_key_hex=pub, signed_at=now,
                                  now=now)["peer_attestation"] is None


# ── sync ─────────────────────────────────────────────────────────────


def _http_via(client):
    def http(method, url, headers, body):
        path = url.split("://", 1)[-1].split("/", 1)[1]
        r = client.request(method, "/" + path, headers=headers, content=body)
        return r.status_code, dict(r.headers), r.content
    return http


def test_pull_bundle_verifies_before_writing(client, tmp_path):
    path = str(tmp_path / "b.json")
    kw = dict(profile="bench", fleet="hospital-east", tenant=client.tenant_id, bundle_path=path,
              pinned_key_hex=_pubkey(client), http=_http_via(client))
    assert sync.pull_bundle("https://shield.test", client.headers["X-API-Key"], **kw) == "updated"
    good = open(path).read()
    assert sync.pull_bundle("https://shield.test", client.headers["X-API-Key"], **kw) == "unchanged"
    evil = json.loads(good)
    evil["policy"]["envelope"]["max_velocity_near_human_mps"] = 9.0

    def tampering_http(method, url, headers, body):
        return 200, {"ETag": '"x"'}, json.dumps(evil).encode()
    os.remove(path + ".etag")
    out = sync.pull_bundle("https://shield.test", client.headers["X-API-Key"], **{**kw, "http": tampering_http})
    assert out.startswith("refused") and open(path).read() == good          # never written


def test_push_audit_lands_in_the_decision_audit_and_resumes(client, robot):
    from storage.decision_audit import query_decisions
    audit_dir = str(robot["dir"] / "audit")
    g = _guard(robot, audit_dir=audit_dir)
    for cid in ("EBG-002", "EBG-012", "EBG-021"):
        g.check_event(next(c for c in CASES if c["id"] == cid)["event"])
    http = _http_via(client)
    assert sync.push_audit("https://shield.test", client.headers["X-API-Key"], audit_dir=audit_dir, robot_id="hx-0042",
                           profile="bench", http=http) == 2
    assert sync.push_audit("https://shield.test", client.headers["X-API-Key"], audit_dir=audit_dir, robot_id="hx-0042",
                           profile="bench", http=http) == 0                   # resumable
    rows = query_decisions(tenant_id=client.tenant_id, guardrail="runtime_boundary", limit=10)
    reasons = " | ".join(r.get("reason", "") for r in rows)
    assert "deny action base_push by envelope_guard" in reasons
    assert "deny action capture_image by capture_guard" in reasons
