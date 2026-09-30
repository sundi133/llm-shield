"""Device DLP agent, task 4: the agent core.
Spec: docs/specs/device-dlp-agent.md §3.2, §3.3, §7, §9, §10.

Bundles are really signed (shield-mavlink's format); the model is a fake
/v1/systemone behind the agent's real HTTP client; the loopback API is the real
server on a free port; the end-to-end test runs the agent against Shield's own
app (enroll, bundle, audit upload, heartbeat, revoke).
"""

import base64
import copy
import hashlib
import http.client
import itertools
import json
import os
import sys
import time
import uuid
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
for sub in ("packages/votal-device-agent", "packages/shield-mavlink"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from shield_mavlink.bundle import BundleError, sign_bundle  # noqa: E402
from votal_device_agent import model as vmodel  # noqa: E402
from votal_device_agent import sync as vsync  # noqa: E402
from votal_device_agent.agent import Agent  # noqa: E402
from votal_device_agent.audit import AuditLog, to_event  # noqa: E402
from votal_device_agent.engine import Engine  # noqa: E402
from votal_device_agent.local_api import LocalApi  # noqa: E402
from votal_device_agent.trust import DEFAULT_AI_HOSTS, Trust, TrustStore  # noqa: E402

from core.dlp.device_policy import DEFAULT_MODEL, for_fleet, validate_policy  # noqa: E402

SK = "3a" * 32
OTHER_SK = "5c" * 32


def pub(sk: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk)).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()


RULES = [
    {"id": "ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "action": "block", "severity": "critical"},
    {"id": "aws-key", "regex": r"AKIA[0-9A-Z]{16}", "action": "redact", "severity": "critical",
     "replacement": "[AWS_KEY]"},
]


def make_policy(**over) -> dict:
    p = for_fleet(validate_policy({"mode": "enforce", **over}), "sales")
    p.update(rules=copy.deepcopy(RULES), blocklists=["project-atlas"], rules_version="r1")
    return p


def signed(policy, *, version=100, now=None, valid=86400, tenant="acme", fleet="sales", sk=SK):
    return sign_bundle(policy, private_key_hex=sk, tenant_id=tenant, fleet_id=fleet,
                       bundle_version=version, valid_for_s=valid, now=now)


# ── a fake /v1/systemone ─────────────────────────────────────────────

# Scripted answers by marker word in the judged text: category -> (p away from
# none, confidence, exfil). Unmarked text is judged benign.
SCRIPT = {"CREDS": ("credentials", 0.95, 0.9, 0.0), "HEALTH": ("health", 0.5, 0.9, 0.0),
          "CODE": ("source_code", 0.9, 0.9, 0.0), "LEAVING": ("none", 0.0, 0.9, 0.9),
          "UNSURE": ("customer_data", 0.95, 0.1, 0.0)}


class FakeOllama:
    def __init__(self):
        self.seen, self.mode = [], "ok"
        self.version, self.digest = "0.35.0", DEFAULT_MODEL["digest"]

    def __call__(self, method, url, headers, body, timeout):
        if url.endswith("/api/version"):
            return 200, json.dumps({"version": self.version}).encode()
        if url.endswith("/api/tags"):
            return 200, json.dumps({"models": [{"name": "tev1:0.8b",
                                                "digest": self.digest.removeprefix("sha256:")}]}).encode()
        if self.mode == "down":
            raise OSError("connection refused")
        if self.mode == "old":
            return 404, b"404 page not found"
        req = json.loads(body)
        text = req["state"]["prompt"]
        self.seen.append(text)
        cat, p, conf, exfil = next((v for k, v in SCRIPT.items() if k in text),
                                   ("none", 0.02, 0.9, 0.01))
        probs = {"none": round(1 - p, 4)}
        if cat != "none":
            probs[cat] = p
        return 200, json.dumps({"model": req["model"], "answers": {
            "category": {"type": "choice", "choice": max(probs, key=probs.get),
                         "probabilities": probs, "confidence": conf},
            "exfil_intent": {"type": "noul", "noul": exfil}}}).encode()


@pytest.fixture
def ollama():
    return FakeOllama()


def engine_for(policy, ollama, *, status="verified", inline="always", audit=None, clock=time.time):
    m = vmodel.DecisionModel(http=ollama, gate=vmodel.LatencyGate(override=inline))
    return Engine(Trust(status, policy, "", {"bundle_version": 100}), m, audit=audit, clock=clock)


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit", device_id="dev_0123456789abcdef")


# ── the decision table (spec §3.2) ───────────────────────────────────


def test_non_ai_hosts_pass_untouched(ollama, audit):
    e = engine_for(make_policy(), ollama, audit=audit)
    d = e.check("ssn 123-45-6789", "example.com")
    assert (d.action, d.verdict) == ("allow", "allow") and ollama.seen == []
    assert list(audit.records()) == []
    assert e.is_ai_host("ws.chatgpt.com:443") and not e.is_ai_host("notchatgpt.com")


def test_a_block_rule_blocks_without_asking_the_model(ollama, audit):
    d = engine_for(make_policy(), ollama, audit=audit).check("my ssn is 123-45-6789", "chatgpt.com")
    assert (d.action, d.rule_ids, d.model_state) == ("block", ["ssn"], "not_run")
    assert "rule ssn" in d.notice and ollama.seen == []
    assert d.text is None


def test_a_blocked_term_blocks(ollama):
    d = engine_for(make_policy(), ollama).check("numbers for Project-Atlas", "claude.ai")
    assert d.action == "block" and d.rule_ids == ["project-atlas"]


def test_redact_sends_the_redacted_text_and_the_model_judges_that(ollama):
    d = engine_for(make_policy(), ollama).check("deploy with AKIAIOSFODNN7EXAMPLE please",
                                                "api.openai.com")
    assert (d.action, d.text) == ("redact", "deploy with [AWS_KEY] please")
    assert ollama.seen and all("AKIA" not in s for s in ollama.seen)


def test_model_block_for_a_blocking_category(ollama):
    d = engine_for(make_policy(), ollama).check("here: CREDS", "chatgpt.com")
    assert (d.action, d.verdict, d.category) == ("block", "block", "credentials")
    assert d.p_category == 0.95 and d.model_state == "ok"
    assert "a password, key or token" in d.notice


def test_justify_then_allow_once(ollama, audit):
    now = [1000.0]
    e = engine_for(make_policy(), ollama, audit=audit, clock=lambda: now[0])
    d = e.check("patient HEALTH notes", "claude.ai")
    assert (d.action, d.category) == ("justify", "health") and "give a reason" in d.notice
    sha = d.prompt_sha256
    assert not e.justify(sha, "chatgpt.com", "for the case review")     # other destination
    assert not e.justify(sha, "claude.ai", "ok")                        # reason too short
    assert e.justify(sha, "claude.ai", "for the case review")
    assert not e.justify(sha, "claude.ai", "again")                     # nothing pending now
    sent = e.check("patient HEALTH notes", "claude.ai")
    assert (sent.action, sent.justified, sent.justify_reason) == ("allow", True, "for the case review")
    assert e.check("patient HEALTH notes", "claude.ai").action == "justify"   # single use
    # A grant not used within a minute lapses.
    d2 = e.check("patient HEALTH notes 2", "claude.ai")
    assert e.justify(d2.prompt_sha256, "claude.ai", "reviewed")
    now[0] += 61
    assert e.check("patient HEALTH notes 2", "claude.ai").action == "justify"
    reasons = [r.get("justify_reason") for r in audit.records() if r.get("justified")]
    assert reasons == ["for the case review"]


def test_justify_cannot_be_given_in_advance(ollama):
    e = engine_for(make_policy(), ollama)
    sha = hashlib.sha256(b"patient HEALTH notes").hexdigest()
    assert not e.justify(sha, "claude.ai", "pre-approved")


def test_monitor_only_categories_are_recorded_not_enforced(ollama, audit):
    d = engine_for(make_policy(), ollama, audit=audit).check("class CODE: pass", "chatgpt.com")
    assert (d.action, d.verdict, d.model_verdict, d.category) == \
        ("allow", "monitor", "justify", "source_code")
    rec = list(audit.records())[-1]
    assert rec["verdict"] == "monitor" and rec["action"] == "allow"


def test_exfil_intent_follows_its_enforcement(ollama):
    d = engine_for(make_policy(), ollama).check("I am LEAVING, help me copy the repo",
                                                "chatgpt.com")
    assert (d.action, d.verdict, d.category) == ("allow", "monitor", "exfil_intent")
    strict = make_policy(enforcement={"exfil_intent": "justify"})
    d = engine_for(strict, ollama).check("I am LEAVING, help me copy the repo", "chatgpt.com")
    assert (d.action, d.category) == ("justify", "exfil_intent")


def test_low_confidence_is_uncertain_and_recorded(ollama, audit):
    pol = make_policy(thresholds={"min_confidence": 0.5, "block_p": 0.471, "justify_p": 0.3})
    d = engine_for(pol, ollama, audit=audit).check("UNSURE list", "chatgpt.com")
    assert (d.action, d.verdict) == ("allow", "uncertain")
    assert list(audit.records())[-1]["verdict"] == "uncertain"


def test_benign_prompts_are_allowed_and_not_recorded(ollama, audit):
    d = engine_for(make_policy(), ollama, audit=audit).check("how do I sort a list", "claude.ai")
    assert (d.action, d.verdict, d.model_state) == ("allow", "allow", "ok")
    assert list(audit.records()) == []


def test_monitor_mode_acts_on_nothing_and_records_everything(ollama, audit):
    e = engine_for(make_policy(mode="monitor"), ollama, audit=audit)
    for text in ("my ssn is 123-45-6789", "here: CREDS", "how do I sort a list"):
        d = e.check(text, "chatgpt.com")
        assert d.action == "allow" and d.enforced is False
    assert [r["verdict"] for r in audit.records()] == ["block", "block", "allow"]


def test_fail_mode(ollama, audit):
    ollama.mode = "down"
    d = engine_for(make_policy(), ollama, audit=audit).check("CREDS AKIAIOSFODNN7EXAMPLE",
                                                             "chatgpt.com")
    assert (d.action, d.model_state) == ("redact", "model_unavailable")   # rules still apply
    assert list(audit.records())[-1]["model_state"] == "model_unavailable"
    d = engine_for(make_policy(fail_mode="block"), ollama).check("anything", "chatgpt.com")
    assert d.action == "block" and "fail_mode is block" in d.reason


def test_an_old_ollama_is_named(ollama):
    ollama.mode = "old"
    d = engine_for(make_policy(), ollama).check("anything", "chatgpt.com")
    assert d.model_state == "model_unsupported" and d.action == "allow"


def test_slow_hardware_runs_the_model_after_sending(ollama, audit):
    e = engine_for(make_policy(), ollama, audit=audit, inline="never")
    d = e.check("here: CREDS", "chatgpt.com")
    assert (d.action, d.model_state) == ("allow", "after_send")          # not held
    e.drain()
    rec = list(audit.records())[-1]
    assert (rec["verdict"], rec["action"], rec["model_state"]) == ("block", "allow", "after_send")
    assert d.verdict == "allow"                                          # the caller's copy


def test_benign_decisions_carry_no_category(ollama):
    d = engine_for(make_policy(), ollama).check("how do I sort a list", "claude.ai")
    assert d.category is None and d.p_category is not None


def test_a_model_that_stops_answering_shows_in_the_state(tmp_path, ollama):
    cfg = vsync.AgentConfig(shield_url="https://s.invalid", tenant_id="acme", fleet="sales",
                            pinned_public_key=pub(SK), state_dir=str(tmp_path / "a"),
                            model_inline="always")
    agent = Agent(cfg, http=lambda *a: (_ for _ in ()).throw(OSError("offline")),
                  model_http=ollama)
    agent.store.accept(signed(make_policy()))
    agent.reload()
    assert agent.check_model() == "ok" and agent.state() == "ok"
    ollama.mode = "down"
    agent.engine.check("anything", "chatgpt.com")
    assert agent.state() == "model_unavailable"
    assert agent.heartbeat_payload()["state"] == "model_unavailable"
    ollama.mode = "ok"
    agent.engine.check("anything", "chatgpt.com")
    assert agent.state() == "ok"
    agent.creds = vsync.Credentials("dev_0123456789abcdef", "vdk_x", "acme", "sales")
    out = agent.sync_once()                                              # offline is fine
    assert out["bundle"].startswith("refused: shield unreachable") and out["heartbeat"] == 0
    assert agent.engine.trust.status == "verified" and not agent.revoked


def test_warm_up_loads_the_model_off_the_send_path(ollama):
    calls = []

    def http(method, url, headers, body, timeout):
        calls.append((url.rsplit("/", 1)[-1], timeout))
        if url.endswith("/api/generate"):
            return 200, b"{}"
        return ollama(method, url, headers, body, timeout)

    m = vmodel.DecisionModel(http=http, gate=vmodel.LatencyGate(min_samples=3))
    assert m.load("tev1:0.8b") and calls[-1] == ("generate", 120.0)


def test_latency_gate():
    g = vmodel.LatencyGate(gate_ms=300, min_samples=5)
    assert not g.inline()                                                # unmeasured: after send
    for ms in (100, 120, 110, 130, 140):
        g.observe(ms)
    assert g.inline()
    for ms in (900,) * 5:
        g.observe(ms)
    assert not g.inline()


def test_the_last_turn_is_judged_first_and_chunks_are_capped(ollama):
    e = engine_for(make_policy(), ollama)
    history = "".join(f"older turn {i} " + "x" * 3000 for i in range(8))
    e.check(history + " latest question", "chatgpt.com", last_user="latest question")
    assert ollama.seen[0] == "latest question" and len(ollama.seen) == 4
    ollama.seen.clear()
    e.check("CREDS " + "y" * 9000, "chatgpt.com", last_user="CREDS now")
    assert len(ollama.seen) == 1                                         # stops at a block


def test_decision_rule_matches_what_task_1_calibrated():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "run_dlp_bench", os.path.join(ROOT, "dlp-bench", "run_dlp_bench.py"))
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    t = make_policy()["thresholds"]
    for cat, pc, conf, ex in itertools.product(("credentials", "health", "none", None),
                                               (0.0, 0.2, 0.3, 0.47, 0.5, 0.95),
                                               (0.0, 0.05, 0.5), (0.0, 0.25, 0.9)):
        p = {"category": cat, "p_category": pc, "confidence": conf, "exfil": ex}
        assert vmodel.model_verdict(p, t) == bench.decide(p, t), p
    resp = {"answers": {"category": {"choice": "none", "confidence": 0.4, "probabilities":
                                     {"none": 0.6, "credentials": 0.3, "health": 0.1}},
                        "exfil_intent": {"noul": 0.2}}}
    assert vmodel.parse(resp) == bench.parse(resp)


def test_rules_match_the_icap_adapter():
    """Parity (spec §10): for blocking rules, the agent and ICAP decide alike."""
    from icap.rules import compile_bundle, evaluate
    icap_bundle = compile_bundle({"rules": RULES, "blocklists": ["project-atlas"]},
                                 redact_fallback="pass")
    e = engine_for(make_policy(), FakeOllama())
    for text in ("ssn 123-45-6789", "AKIAIOSFODNN7EXAMPLE", "Project-Atlas", "nothing here"):
        icap_hit = evaluate(icap_bundle, text)
        d = e.check(text, "chatgpt.com")
        assert (d.action == "block") == (icap_hit is not None), text
    from icap.config import DEFAULT_AI_HOSTS as ICAP_HOSTS
    assert tuple(DEFAULT_AI_HOSTS) == tuple(ICAP_HOSTS)


# ── privacy (spec §3.3) ──────────────────────────────────────────────


SECRET_PROMPT = "customer Jane Roe ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE Project-Atlas CREDS"


def test_records_and_events_carry_no_prompt_text(ollama, audit):
    from core.runtime_policy import events as server_events
    e = engine_for(make_policy(mode="monitor"), ollama, audit=audit)
    e.check(SECRET_PROMPT, "chatgpt.com")
    e.check("patient HEALTH notes for Jane Roe", "claude.ai")
    raw = (audit.dir / "pending.jsonl").read_text()
    for fragment in ("Jane Roe", "123-45-6789", "AKIAIOSFODNN7EXAMPLE", "Project-Atlas", "patient"):
        assert fragment not in raw, fragment
    for r in audit.records():
        assert "excerpt" not in r
        ev = server_events.normalize(to_event(r))                        # Shield accepts it
        assert ev["kind"] == "dlp" and ev["detail"]["prompt_sha256"] == r["prompt_sha256"]


def test_excerpts_are_opt_in_and_mask_every_rule(ollama, audit):
    pol = make_policy(privacy={"capture_excerpt": True, "server_screen": False})
    e = engine_for(pol, ollama, audit=audit)
    d = e.check(SECRET_PROMPT, "chatgpt.com")
    assert d.action == "block"
    rec = list(audit.records())[-1]
    assert rec["excerpt"].startswith("customer Jane Roe ssn [REDACTED] key [REDACTED]")
    for fragment in ("123-45-6789", "AKIAIOSFODNN7EXAMPLE", "Project-Atlas"):
        assert fragment not in rec["excerpt"]
    assert "excerpt" not in d.public() and "text" not in d.public()


def test_the_audit_chain_detects_tampering(ollama, audit):
    e = engine_for(make_policy(mode="monitor"), ollama, audit=audit)
    for i in range(3):
        e.check(f"prompt {i}", "chatgpt.com")
    assert audit.verify().intact
    path = audit.dir / "pending.jsonl"
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["verdict"] = "allow" if rec["verdict"] != "allow" else "block"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    v = audit.verify()
    assert not v.intact and v.broken_at == 2


# ── bundle trust (spec §7) ───────────────────────────────────────────


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "state", tenant_id="acme", fleet="sales", pinned_key_hex=pub(SK))


def _write(store, bundle):
    store.bundle_path.write_text(json.dumps(bundle))


def test_a_verified_bundle_is_enforced(store):
    store.accept(signed(make_policy()))
    t = store.load()
    assert (t.status, t.state, t.bundle_version) == ("verified", "ok", 100)


@pytest.mark.parametrize("attack", ["tampered", "foreign_fleet", "foreign_tenant", "self_signed",
                                    "no_signature"])
def test_bundle_attacks_fall_back(store, attack):
    b = signed(make_policy())
    if attack == "tampered":
        b["policy"]["mode"] = "monitor"
    elif attack == "foreign_fleet":
        b = signed(make_policy(), fleet="finance")
    elif attack == "foreign_tenant":
        b = signed(make_policy(), tenant="other")
    elif attack == "self_signed":
        b = signed(make_policy(), sk=OTHER_SK)
    else:
        del b["signature"]
    with pytest.raises(BundleError):
        store.accept(b)
    assert not store.bundle_path.exists()                                # never written
    _write(store, b)                                                     # planted on disk
    t = store.load()
    assert t.status == "fallback" and t.state == "no_bundle" and "refused" in t.reason


def test_expired_bundles_get_their_grace_then_fall_back(store):
    now = int(time.time())
    store.accept(signed(make_policy(), now=now - 2 * 86400, valid=86400))   # expired a day ago
    t = store.load()
    assert (t.status, t.state) == ("grace", "stale_bundle") and t.policy["mode"] == "enforce"
    store.accept(signed(make_policy(), version=101, now=now - 10 * 86400, valid=86400))
    t = store.load()
    assert t.status == "fallback" and "past its" in t.reason


def test_never_an_older_bundle(store):
    store.accept(signed(make_policy(mode="enforce"), version=200))
    with pytest.raises(BundleError, match="rollback"):
        store.accept(signed(make_policy(mode="monitor"), version=150))
    _write(store, signed(make_policy(mode="monitor"), version=150))      # replayed onto disk
    assert store.load().status == "fallback"


def test_winding_the_clock_back_does_not_extend_a_bundle(store):
    now = int(time.time())
    store.accept(signed(make_policy(grace_s=0), now=now - 3600, valid=7200))
    assert store.load().status == "verified"
    store.observe_server_time(now + 2 * 3600)                            # Shield saw a later time
    assert store.load().status == "fallback"


def test_fallback_redacts_known_secrets_and_skips_the_model(tmp_path, ollama):
    store = TrustStore(tmp_path / "s", tenant_id="acme", fleet="sales", pinned_key_hex=pub(SK))
    t = store.load()
    assert t.status == "fallback" and "built-in" in t.reason
    m = vmodel.DecisionModel(http=ollama, gate=vmodel.LatencyGate(override="always"))
    d = Engine(t, m).check("key AKIAIOSFODNN7EXAMPLE and CREDS", "chatgpt.com")
    assert d.action == "redact" and "AKIA" not in d.text and ollama.seen == []
    (tmp_path / "s" / "fallback.json").write_text(json.dumps(
        {"rules": [{"id": "corp-token", "regex": "CORP-[0-9]{6}", "action": "block"}]}))
    t = store.load()
    assert "MDM fallback" in t.reason
    assert Engine(t, m).check("CORP-123456", "chatgpt.com").action == "block"


def test_model_health(ollama):
    m = vmodel.DecisionModel(http=ollama)
    assert m.health("tev1:0.8b", DEFAULT_MODEL["digest"], "0.35.0") == "ok"
    ollama.digest = "sha256:" + "0" * 64
    assert m.health("tev1:0.8b", DEFAULT_MODEL["digest"], "0.35.0") == "model_mismatch"
    ollama.version = "0.33.2"
    assert m.health("tev1:0.8b", DEFAULT_MODEL["digest"], "0.35.0") == "model_unsupported"
    assert m.health("tev1:4b", "", "0.1.0") == "model_unavailable"       # not pulled
    # A model that failed its check is not called.
    e = engine_for(make_policy(), ollama)
    e.model.state = "model_mismatch"
    d = e.check("CREDS", "chatgpt.com")
    assert d.model_state == "model_mismatch" and "CREDS" not in "".join(ollama.seen)


# ── the loopback API ─────────────────────────────────────────────────


class _Agent:
    def __init__(self, engine):
        self.engine = engine

    def status(self):
        return {"state": "ok"}


@pytest.fixture
def local(ollama):
    api = LocalApi(_Agent(engine_for(make_policy(), ollama)), secret="s" * 43, port=0)
    port = api.start()
    yield port
    api.stop()


def _req(port, method, path, body=None, headers=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": host or f"127.0.0.1:{port}", "X-Votal-Local-Secret": "s" * 43,
         "Content-Type": "application/json", **(headers or {})}
    h = {k: v for k, v in h.items() if v is not None}
    c.request(method, path, body=json.dumps(body).encode() if body is not None else None,
              headers=h)
    r = c.getresponse()
    out = (r.status, json.loads(r.read() or b"{}"))
    c.close()
    return out


def test_loopback_check_and_justify(local):
    s, d = _req(local, "POST", "/v1/local/check", {"text": "deploy AKIAIOSFODNN7EXAMPLE",
                                                   "destination": "chatgpt.com"},
                headers={"Origin": "chrome-extension://abcdefghijklmnop"})
    assert s == 200 and d["action"] == "redact" and d["text"] == "deploy [AWS_KEY]"
    s, d = _req(local, "POST", "/v1/local/check", {"text": "patient HEALTH", "destination": "claude.ai"})
    assert d["action"] == "justify" and "text" not in d and "excerpt" not in d
    s, g = _req(local, "POST", "/v1/local/justify", {"prompt_sha256": d["prompt_sha256"],
                                                     "destination": "claude.ai", "reason": "case 42"})
    assert s == 200 and g["granted"] is True
    s, d = _req(local, "POST", "/v1/local/check", {"text": "patient HEALTH", "destination": "claude.ai"})
    assert d["action"] == "allow" and d["justified"] is True
    assert _req(local, "GET", "/v1/local/status")[1] == {"state": "ok"}


@pytest.mark.parametrize("headers, host, status", [
    ({"X-Votal-Local-Secret": None}, None, 401),
    ({"X-Votal-Local-Secret": "wrong"}, None, 401),
    ({}, "evil.example:47823", 403),                         # DNS rebinding
    ({"Origin": "https://evil.example"}, None, 403),         # a web page, even with the secret
    ({"Origin": "null"}, None, 403),
])
def test_loopback_refuses_everyone_else(local, headers, host, status):
    s, _ = _req(local, "POST", "/v1/local/check", {"text": "x", "destination": "chatgpt.com"},
                headers=headers, host=host)
    assert s == status


def test_loopback_input_limits(local):
    assert _req(local, "POST", "/v1/local/check", {"text": "x"})[0] == 400
    c = http.client.HTTPConnection("127.0.0.1", local, timeout=5)
    c.putrequest("POST", "/v1/local/check", skip_host=True)
    for k, v in {"Host": f"127.0.0.1:{local}", "X-Votal-Local-Secret": "s" * 43,
                 "Content-Length": str(2 << 20)}.items():
        c.putheader(k, v)
    c.endheaders()
    assert c.getresponse().status == 413
    c.close()


def test_the_local_api_binds_loopback_only():
    src = open(os.path.join(ROOT, "packages", "votal-device-agent", "votal_device_agent",
                            "local_api.py")).read()
    assert 'ThreadingHTTPServer(("127.0.0.1", self.port)' in src


# ── end to end against Shield ────────────────────────────────────────


@pytest.fixture(scope="module")
def shield_app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def shield(shield_app, monkeypatch):
    from starlette.testclient import TestClient
    from core.dlp import devices as dv
    from core.runtime_policy import bundle as rt_bundle
    from storage import tenant_store as ts
    dv.reset_memory()
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", SK)
    rt_bundle.reset_signer_cache_for_tests()
    tid = "ag" + uuid.uuid4().hex[:10]
    key = "sk-ag-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    admin = TestClient(shield_app, headers={"X-API-Key": key})
    admin.tenant_id = tid
    raw = TestClient(shield_app)

    def http(method, url, headers, body):
        path = url.split("://", 1)[1]
        path = path[path.index("/"):]
        r = raw.request(method, path, headers=headers, content=body)
        return r.status_code, dict(r.headers), r.content

    admin.http = http
    yield admin
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()


def _agent(tmp_path, shield, ollama, pinned=None):
    cfg = vsync.AgentConfig(shield_url="https://shield.test", tenant_id=shield.tenant_id,
                            fleet="sales", pinned_public_key=pinned or pub(SK),
                            state_dir=str(tmp_path / "agent"), model_inline="always")
    return Agent(cfg, http=shield.http, model_http=ollama)


LAPTOP = {"hostname": "ana-mbp", "os": "macos", "os_version": "14.5",
          "serial_hash": hashlib.sha256(b"serial").hexdigest()}


def test_end_to_end(tmp_path, shield, ollama):
    shield.put("/v1/tenant/me/dlp-policy", json={"fleet_modes": {"sales": "enforce"}})
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    agent = _agent(tmp_path, shield, ollama)
    assert agent.engine.trust.status == "fallback"                       # before the first sync
    creds = agent.enroll_if_needed(token, LAPTOP)
    assert creds.api_key.startswith("vdk_")
    assert oct(os.stat(tmp_path / "agent" / "credentials.json").st_mode & 0o777) == "0o600"
    out = agent.sync_once()
    assert out["bundle"] == "updated" and out["heartbeat"] == 204, out
    assert out["model"] == "ok"
    assert agent.engine.trust.status == "verified" and agent.engine.policy["mode"] == "enforce"

    d = agent.engine.check("here: CREDS", "chatgpt.com", app="Google Chrome")
    assert d.action == "block" and d.category == "credentials"
    with patch("core.runtime_policy.events.ingest") as ingest:
        out = agent.sync_once()
    assert out["bundle"] == "unchanged" and out["audit"] == 1
    tenant_id, events = ingest.call_args.args[:2]
    assert tenant_id == shield.tenant_id
    assert events[0]["detail"]["device_id"] == creds.device_id
    assert events[0]["detail"]["verdict"] == "block" and "CREDS" not in json.dumps(events)
    assert agent.sync_once()["audit"] == 0                               # nothing sent twice

    row = shield.get("/v1/tenant/me/devices").json()["devices"][0]
    assert (row["state"], row["mode"], row["model_ok"]) == ("ok", "enforce", True)
    assert row["counters"]["blocked"] == 1

    shield.delete(f"/v1/tenant/me/devices/{creds.device_id}")
    out = agent.sync_once()
    assert agent.revoked and out["bundle"] == "revoked"
    assert agent.engine.check("again: CREDS", "chatgpt.com").action == "block"   # still enforcing


def test_enrollment_refuses_a_shield_with_another_key(tmp_path, shield, ollama):
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    agent = _agent(tmp_path, shield, ollama, pinned=pub(OTHER_SK))
    with pytest.raises(vsync.SyncError, match="not the key your MDM pinned"):
        agent.enroll_if_needed(token, LAPTOP)
    assert agent.credentials.load() is None


def test_a_bad_download_never_replaces_a_good_bundle(tmp_path, shield, ollama):
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    agent = _agent(tmp_path, shield, ollama)
    agent.enroll_if_needed(token, LAPTOP)
    agent.sync_once()
    good = agent.store.bundle_path.read_text()

    def tampering(method, url, headers, body):
        status, h, b = shield.http(method, url, {k: v for k, v in headers.items()
                                                  if k != "If-None-Match"}, body)
        if "/dlp-bundle" in url and status == 200:
            doc = json.loads(b)
            doc["policy"]["thresholds"]["block_p"] = 0.99       # loosen it in transit
            b = json.dumps(doc).encode()
        return status, h, b

    agent.http = tampering
    assert agent.sync_once()["bundle"].startswith("refused: bundle signature is invalid")
    assert agent.store.bundle_path.read_text() == good


def test_config_requires_a_pinned_key(tmp_path):
    p = tmp_path / "agent.json"
    p.write_text(json.dumps({"shield_url": "https://s", "tenant_id": "t", "fleet": "f",
                             "pinned_public_key": "abc", "state_dir": str(tmp_path)}))
    with pytest.raises(ValueError, match="pinned_public_key"):
        vsync.AgentConfig.load(p)


def test_a_refused_enrollment_is_reported_and_retried(tmp_path, shield, ollama):
    """The old install of this laptop still reporting: 409, the reason shows in
    status (and so in verify), and the hourly retry enrolls once it is revoked."""
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "sales"}).json()["enrollment_token"]
    old = _agent(tmp_path / "old", shield, ollama)
    old.enroll_if_needed(token, LAPTOP)
    old.sync_once()                                                   # a heartbeat: it is live
    new = _agent(tmp_path / "new", shield, ollama)
    with pytest.raises(vsync.SyncError, match="409"):
        new.enroll_if_needed(token, LAPTOP)
    assert "still reporting" in new.status()["enroll_error"]
    assert new.sync_once()["skipped"] == "not enrolled"               # no retry within the hour
    shield.delete(f"/v1/tenant/me/devices/{old.creds.device_id}")
    new._enroll_tried -= new.ENROLL_RETRY_S + 1                       # an hour later
    new.sync_once()
    assert new.creds is not None and new.status()["enroll_error"] == ""
