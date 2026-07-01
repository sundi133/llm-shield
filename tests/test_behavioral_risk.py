"""Behavioral risk: baseline + deviation scoring + enforcement gate.

Spec: docs/specs/behavioral-risk-blocking.md
Detection on the governance plane; enforcement is a dict read on the
registry entry cap-mint already loads (SHIELD_BEHAVIORAL_RISK=enforce only;
default `monitor` leaves the hot path untouched).
"""
import copy
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_governance as gov
import guardrails.agentic.rbac_guard as rbac_guard
from api.routes_agent_auth import CapMintRequest, _decide_authz
from core import behavioral_risk as risk
from core.identity import IdentityTuple

NOW = int(time.time())

REGISTERED = {
    "billing-agent": {
        "name": "Billing Agent", "status": "active",
        "tools": ["get_invoice", "send_email"],
        "role_permissions": {}, "allowed_resources": [],
    },
}

# 48 baseline events (>= default min 20), one every 30 min across the last
# 24 h: covers EVERY hour bucket (odd_hours can never fire from wall-clock
# drift) and yields a steady 2/h rate. All events are >900 s old, so the
# default evaluation window sees none of them — signal isolation is exact.
BASELINE_EVENTS = [
    {"agent_id": "billing-agent", "tool": "get_invoice", "resource": f"acct/{i}",
     "ts": NOW - (i + 1) * 1800, "event": "cap_minted"}
    for i in range(48)
]


@pytest.fixture
def store(monkeypatch):
    kv = {"agents:acme": copy.deepcopy(REGISTERED)}
    monkeypatch.setattr(gov, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(gov, "get_redis_data", lambda k: kv.get(k))
    monkeypatch.setattr(gov, "kv_get", lambda k: kv.get(k))
    monkeypatch.setattr(gov, "kv_set", lambda k, v: kv.__setitem__(k, v))
    monkeypatch.setattr(gov, "_save_agents",
                        lambda t, agents: kv.__setitem__(f"agents:{t}", agents))
    monkeypatch.setattr(gov.stats, "get_recent",
                        lambda t, limit=50: list(BASELINE_EVENTS))
    for var in ("SHIELD_BEHAVIORAL_RISK", "SHIELD_RISK_MIN_BASELINE_EVENTS",
                "SHIELD_RISK_RATE_MULTIPLIER", "SHIELD_RISK_WINDOW_SECONDS",
                "SHIELD_RISK_FLAG_TTL_SECONDS"):
        monkeypatch.delenv(var, raising=False)
    return kv


@pytest.fixture
def client(store):
    app = FastAPI()
    app.include_router(gov.router)
    return TestClient(app)


# ── pure scoring logic ───────────────────────────────────────────────────


class TestBaseline:
    def test_aggregates_tools_resources_hours_rate(self):
        b = risk.build_baseline(BASELINE_EVENTS, NOW)
        assert b["tools"] == {"get_invoice": 48}
        assert b["events_analyzed"] == 48
        assert len(b["resources"]) == 48
        assert b["rate_per_hour"] == 2.0          # 48 events / 24 h
        assert len(b["hours"]) == 24              # every bucket covered
        assert sum(b["hours"].values()) == 48

    def test_empty_events(self):
        b = risk.build_baseline([], NOW)
        assert b["events_analyzed"] == 0 and b["tools"] == {}


class TestScoring:
    def _baseline(self):
        return risk.build_baseline(BASELINE_EVENTS, NOW)

    def test_known_tool_scores_low(self):
        cur = [{"agent_id": "a", "tool": "get_invoice", "resource": "acct/1",
                "ts": NOW - 10, "event": "cap_minted"}]
        v = risk.score_activity(cur, self._baseline(), NOW)
        assert v["level"] == "low" and v["score"] < risk.LEVEL_MEDIUM_AT

    def test_new_tool_fires_medium(self):
        # known resource + covered hours + calm rate → ONLY new_tool fires
        cur = [{"agent_id": "a", "tool": "wire_transfer", "resource": "acct/1",
                "ts": NOW - 10, "event": "cap_minted"}]
        v = risk.score_activity(cur, self._baseline(), NOW)
        assert v["signals"] == ["new_tool:wire_transfer"]
        assert v["score"] == risk.WEIGHT_NEW_TOOL
        assert v["level"] == "medium"          # 40 = step-up threshold

    def test_odd_hours_fires_deterministically(self):
        import time as _t
        cur_hour = _t.gmtime(NOW - 10).tm_hour
        base = {
            "tools": {"get_invoice": 30}, "resources": {"acct/1": 30},
            # baseline active ONLY in a different hour bucket than "now"
            "hours": {str((cur_hour + 1) % 24): 30},
            "rate_per_hour": 100.0, "events_analyzed": 30, "computed_at": NOW,
        }
        cur = [{"agent_id": "a", "tool": "get_invoice", "resource": "acct/1",
                "ts": NOW - 10, "event": "cap_minted"}]
        v = risk.score_activity(cur, base, NOW)
        assert v["signals"] == [f"odd_hours:{cur_hour}"]
        assert v["score"] == risk.WEIGHT_ODD_HOURS

    def test_rate_spike_fires(self, monkeypatch):
        monkeypatch.setenv("SHIELD_RISK_WINDOW_SECONDS", "3600")
        base = self._baseline()                # ~12/h baseline
        cur = [{"agent_id": "a", "tool": "get_invoice", "resource": f"acct/{i}",
                "ts": NOW - 5, "event": "cap_minted"} for i in range(200)]
        v = risk.score_activity(cur, base, NOW)
        assert any(s.startswith("rate_spike:") for s in v["signals"])

    def test_combined_signals_reach_high(self, monkeypatch):
        monkeypatch.setenv("SHIELD_RISK_WINDOW_SECONDS", "3600")
        base = self._baseline()
        cur = [{"agent_id": "a", "tool": "wire_transfer", "resource": f"new/{i}",
                "ts": NOW - 5, "event": "cap_minted"} for i in range(200)]
        v = risk.score_activity(cur, base, NOW)
        # new_tool(40) + rate_spike(30) + new_resource(15) >= 70
        assert v["score"] >= risk.LEVEL_HIGH_AT and v["level"] == "high"

    def test_thin_baseline_never_scores(self):
        thin = risk.build_baseline(BASELINE_EVENTS[:5], NOW)  # < 20 events
        cur = [{"agent_id": "a", "tool": "wire_transfer", "resource": "x",
                "ts": NOW - 5, "event": "cap_minted"}]
        v = risk.score_activity(cur, thin, NOW)
        assert v["level"] == "insufficient_baseline" and v["score"] == 0

    def test_missing_baseline_never_scores(self):
        v = risk.score_activity([{"tool": "x", "ts": NOW}], None, NOW)
        assert v["level"] == "insufficient_baseline"

    def test_quiet_window_scores_low(self):
        v = risk.score_activity([], self._baseline(), NOW)
        assert v["level"] == "low" and v["signals"] == []


# ── governance endpoints ─────────────────────────────────────────────────


def _flag_agent(client, store, monkeypatch):
    """rebuild baseline from steady history, then evaluate with a new tool."""
    assert client.post("/v1/governance/risk/baselines/rebuild").json()["rebuilt"]
    monkeypatch.setattr(gov.stats, "get_recent", lambda t, limit=50:
                        list(BASELINE_EVENTS) + [
                            {"agent_id": "billing-agent", "tool": "wire_transfer",
                             "resource": "acct/1", "ts": int(time.time()) - 5,
                             "event": "cap_minted"}])
    return client.post("/v1/governance/risk/evaluate").json()


class TestEndpoints:
    def test_rebuild_and_get_baselines(self, client):
        r = client.post("/v1/governance/risk/baselines/rebuild")
        assert r.status_code == 200 and r.json()["agents"] == {"billing-agent": 48}
        got = client.get("/v1/governance/risk/baselines").json()["baselines"]
        assert got["billing-agent"]["tools"] == {"get_invoice": 48}

    def test_evaluate_flags_medium_and_get_risk(self, client, store, monkeypatch):
        report = _flag_agent(client, store, monkeypatch)
        assert report["results"]["billing-agent"]["level"] == "medium"
        entry = store["agents:acme"]["billing-agent"]
        assert entry["behavioral_risk"]["level"] == "medium"
        assert entry["behavioral_risk"]["expires_at"] > int(time.time())
        flags = client.get("/v1/governance/risk").json()["flags"]
        assert "billing-agent" in flags

    def test_deescalation_clears_flag(self, client, store, monkeypatch):
        _flag_agent(client, store, monkeypatch)
        assert "behavioral_risk" in store["agents:acme"]["billing-agent"]
        # activity returns to normal → next evaluation clears
        monkeypatch.setattr(gov.stats, "get_recent",
                            lambda t, limit=50: list(BASELINE_EVENTS))
        client.post("/v1/governance/risk/evaluate")
        assert "behavioral_risk" not in store["agents:acme"]["billing-agent"]

    def test_off_mode_is_noop(self, client, store, monkeypatch):
        monkeypatch.setenv("SHIELD_BEHAVIORAL_RISK", "off")
        assert client.post("/v1/governance/risk/baselines/rebuild").json() == \
            {"mode": "off", "rebuilt": False}
        assert client.post("/v1/governance/risk/evaluate").json() == \
            {"mode": "off", "evaluated": False}

    def test_clear_endpoint_step_up(self, client, store, monkeypatch):
        _flag_agent(client, store, monkeypatch)
        r = client.post("/v1/governance/risk/billing-agent/clear")
        assert r.status_code == 200
        assert "behavioral_risk" not in store["agents:acme"]["billing-agent"]
        # second clear → 404 (no flag)
        assert client.post("/v1/governance/risk/billing-agent/clear").status_code == 404
        assert client.post("/v1/governance/risk/ghost/clear").status_code == 404


# ── hot-path enforcement gate (_decide_authz) ────────────────────────────


def _identity():
    return IdentityTuple(
        user_sub="u", agent_id="billing-agent", agent_instance_id="i",
        tenant_id="acme", build_hash="b", model_version="m", session_id="s")


def _entry_with_flag(level, expires_delta=600):
    return {
        "status": "active", "tools": ["get_invoice"], "role_permissions": {},
        "behavioral_risk": {
            "score": 80 if level == "high" else 40, "level": level,
            "signals": ["new_tool:wire_transfer"],
            "evaluated_at": NOW, "expires_at": int(time.time()) + expires_delta,
        },
    }


def _patch_registry(monkeypatch, entry):
    monkeypatch.setattr(rbac_guard, "_load_agent_entry", lambda a, t: entry)
    monkeypatch.setattr(rbac_guard, "_registry_agent_status", lambda a, t: "active")
    monkeypatch.setattr(rbac_guard, "_tenant_has_registry", lambda t: True)


BODY = CapMintRequest(tool="get_invoice", resource="acct/1")


class TestEnforcementGate:
    def test_monitor_default_never_blocks(self, monkeypatch):
        monkeypatch.delenv("SHIELD_BEHAVIORAL_RISK", raising=False)
        _patch_registry(monkeypatch, _entry_with_flag("high"))
        assert _decide_authz(_identity(), BODY)["allowed"] is True

    def test_enforce_high_blocks_with_signals(self, monkeypatch):
        monkeypatch.setenv("SHIELD_BEHAVIORAL_RISK", "enforce")
        _patch_registry(monkeypatch, _entry_with_flag("high"))
        d = _decide_authz(_identity(), BODY)
        assert d["allowed"] is False
        assert any("behavioral risk block (high)" in r for r in d["reasons"])
        assert any("new_tool:wire_transfer" in r for r in d["reasons"])

    def test_enforce_medium_requires_step_up(self, monkeypatch):
        monkeypatch.setenv("SHIELD_BEHAVIORAL_RISK", "enforce")
        _patch_registry(monkeypatch, _entry_with_flag("medium"))
        d = _decide_authz(_identity(), BODY)
        assert d["allowed"] is False
        assert any("step-up approval required" in r for r in d["reasons"])

    def test_expired_flag_fails_safe_to_allow(self, monkeypatch):
        monkeypatch.setenv("SHIELD_BEHAVIORAL_RISK", "enforce")
        _patch_registry(monkeypatch, _entry_with_flag("high", expires_delta=-10))
        assert _decide_authz(_identity(), BODY)["allowed"] is True

    def test_enforce_without_flag_allows(self, monkeypatch):
        monkeypatch.setenv("SHIELD_BEHAVIORAL_RISK", "enforce")
        entry = {"status": "active", "tools": ["get_invoice"], "role_permissions": {}}
        _patch_registry(monkeypatch, entry)
        assert _decide_authz(_identity(), BODY)["allowed"] is True


class TestModeParsing:
    def test_default_monitor(self, monkeypatch):
        monkeypatch.delenv("SHIELD_BEHAVIORAL_RISK", raising=False)
        assert risk.behavioral_risk_mode() == "monitor"

    def test_invalid_falls_back(self, monkeypatch):
        monkeypatch.setenv("SHIELD_BEHAVIORAL_RISK", "chaos")
        assert risk.behavioral_risk_mode() == "monitor"
