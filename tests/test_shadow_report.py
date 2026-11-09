"""GET /v1/tenant/me/shadow-report: what Shield would have stopped.

Spec: docs/specs/shadow-mode-report.md, task 2. The test that carries the
weight is the end-to-end one (spec section 1's success condition): real
prompts through /guardrails/input on the data plane, then the report read back
from what the guard path actually wrote (metrics hashes and audit rows), in
monitor mode and again after switching to enforce.
"""

import asyncio
import fnmatch
import json
import time
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from config.schema import GuardrailConfig, ShieldConfig

BAD = "shadow_report_bad"
MARKER = "SECRET-PROMPT-MARKER-7f3a"
TENANT = "shadow-report-tenant"
KEY = "shadow-report-key-aaaaaaaaaaaa"
REPORT = "/v1/tenant/me/shadow-report"


class FakeRedis:
    """Upstash-like: direct ops only (pipeline() raises), hashes, strings and
    sorted sets, enough for the metrics store and the audit log."""

    def __init__(self):
        self.hashes, self.strings, self.zsets = {}, {}, {}

    # hashes
    def hincrby(self, key, field, n=1):
        h = self.hashes.setdefault(key, {})
        h[field] = int(h.get(field, 0)) + n
        return h[field]

    def hincrbyfloat(self, key, field, n):
        h = self.hashes.setdefault(key, {})
        h[field] = float(h.get(field, 0)) + n
        return h[field]

    def hgetall(self, key):
        return {k: str(v) for k, v in self.hashes.get(key, {}).items()}

    def scan(self, cursor=0, match="*", count=100):
        return 0, [k for k in self.hashes if fnmatch.fnmatch(k, match)]

    # strings
    def set(self, key, value, nx=False):
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True

    def get(self, key):
        return self.strings.get(key)

    # sorted sets
    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)

    def zrevrangebyscore(self, key, max_score, min_score, offset=None, count=None,
                         start=None, num=None):
        lo = float("-inf") if min_score == "-inf" else float(min_score)
        hi = float("inf") if max_score == "+inf" else float(max_score)
        items = sorted(((m, s) for m, s in self.zsets.get(key, {}).items() if lo <= s <= hi),
                       key=lambda x: -x[1])
        first = offset if offset is not None else (start or 0)
        n = count if count is not None else num
        items = items[first:first + n] if n is not None else items[first:]
        return [m for m, _ in items]

    def zremrangebyscore(self, key, lo, hi):
        return 0

    def zcard(self, key):
        return len(self.zsets.get(key, {}))

    def expire(self, key, ttl):
        return True

    def pipeline(self, *args, **kwargs):
        raise TypeError("Upstash pipeline API differs; use direct calls")


@pytest.fixture
def redis(monkeypatch):
    """One fake behind the metrics store and the audit log; the tenant store
    keeps its in-process fallback. Writes happen synchronously."""
    from storage import audit_log, guardrail_metrics as gm
    r = FakeRedis()
    monkeypatch.setattr(gm, "_get_redis", lambda: r)
    monkeypatch.setattr(gm, "_split_marked", False)
    monkeypatch.setattr(audit_log, "_get_redis", lambda: r)

    async def log_now(self, entry):
        self._write_sync(entry)
    monkeypatch.setattr(audit_log.AuditLogger, "log", log_now)
    monkeypatch.setenv("SHIELD_METRICS_INLINE", "1")
    monkeypatch.setenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", "off")
    monkeypatch.delenv("SHIELD_METRICS_SPLIT_WOULD_BLOCK", raising=False)
    return r


@pytest.fixture
def tenants(monkeypatch):
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(tenant_store, "_fallback_store", {})
    monkeypatch.setattr(tenant_store, "_cache", {})
    return tenant_store


@pytest.fixture
def report_client():
    """The router on its own app, with the tenant taken from a test header the
    way the portal session or API key middleware would set it."""
    from api.routes_shadow_report import router
    app = FastAPI()

    @app.middleware("http")
    async def tenant(request: Request, call_next):
        tid = request.headers.get("x-test-tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)
    app.include_router(router)
    c = TestClient(app)

    def get(tenant=TENANT, **params):
        headers = {"x-test-tenant": tenant} if tenant else {}
        return c.get(REPORT, params=params, headers=headers)
    return get


@pytest.fixture
def guard(redis, tenants):
    """A data-plane app whose tenant blocks BAD; switch its mode with .mode()."""
    import config.schema as cs
    from guardrails import registry as reg

    cfg = ShieldConfig(guardrails={
        "keyword_blocklist": GuardrailConfig(
            enabled=True, action="block",
            settings={"keywords": [BAD], "case_insensitive": True}),
    })
    original = cs.config
    cs.config = cfg
    reg._registry.clear()
    reg._discovered = False
    tenants.create_tenant(TENANT, {"tenant_id": TENANT, "name": "Shadow Co",
                                   "policy_mode": "monitor",
                                   "quota": {"max_requests_per_minute": 100_000}})
    tenants.add_api_key(TENANT, KEY, scope="admin")
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    p = patch("core.middleware._get_cached_tenant",
              side_effect=lambda key: (TENANT, tenants.get_tenant(TENANT)))
    p.start()
    client = TestClient(app)

    def send(message):
        return client.post("/guardrails/input", json={"message": message},
                           headers={"x-api-key": KEY}).json()

    def mode(m):
        tenants.update_tenant(TENANT, {"policy_mode": m})
    send.mode = mode
    yield send
    p.stop()
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


def _audit_row(r, tenant, *, action, guardrails=(), team=None, meta_tenant=None,
               ts=None, text="hello"):
    """An audit row as the guard routes write it."""
    ts = ts or time.time()
    rec = {"timestamp": datetime.utcfromtimestamp(ts).isoformat(), "ts": ts,
           "agent_key": "bot", "input_text": text, "action_taken": action,
           "metadata": {"kind": "agent_chat_telemetry",
                        "tenant_id": meta_tenant or tenant, "stage": "input",
                        "input_guardrails": [
                            {"guardrail": g, "passed": False, "action": "block",
                             "message": f"{g} matched"} for g in guardrails],
                        "policy_scope": {"rule": team, "value": "x", "header": "x-org"}
                        if team else None}}
    r.zadd(f"audit:{tenant}", {json.dumps(rec): ts})


# ── the success condition (spec section 1) ──────────────────────────────────

def test_end_to_end_monitor_then_enforce(guard, report_client):
    for i in range(3):
        assert guard(f"prompt {i} with {BAD} and {MARKER}")["action"] == "monitor"
    for i in range(2):
        assert guard(f"clean prompt {i}")["action"] == "pass"

    body = report_client(days=7).json()
    assert body["policy_mode"] == "monitor" and body["counts_from"] == "metrics"
    assert (body["checked_total"], body["would_block_total"], body["blocked_total"]) == (5, 3, 0)
    assert body["would_block_rate_pct"] == 60.0 and body["would_block_requests"] == 3
    assert body["by_guardrail"] == [{"guardrail": "keyword_blocklist", "would_blocked": 3}]
    today = body["daily"][-1]
    assert (today["checked"], today["would_blocked"], today["blocked"]) == (5, 3, 0)
    assert len(body["daily"]) == 7
    assert body["by_team"] == [{"team": None, "would_blocked": 3}]
    assert len(body["examples"]) == 3
    ex = body["examples"][0]
    assert ex["guardrails"] == ["keyword_blocklist"] and ex["source"] == "chat"
    assert body["exact_since"] == datetime.utcnow().strftime("%Y-%m-%d")
    assert body["degraded"] is False and body["sampled"] is False

    guard.mode("enforce")
    for i in range(3):
        assert guard(f"again {i} {BAD}")["action"] == "block"
    body = report_client(days=7).json()
    assert body["policy_mode"] == "enforce"
    assert (body["would_block_total"], body["blocked_total"], body["checked_total"]) == (3, 3, 8)


def test_no_prompt_text_anywhere_in_the_report(guard, report_client):
    guard(f"{BAD} {MARKER}")
    raw = report_client().text
    assert MARKER not in raw and "input_text" not in raw


# ── isolation ───────────────────────────────────────────────────────────────

def test_another_tenants_would_blocks_never_appear(redis, tenants, report_client):
    from storage import guardrail_metrics as gm
    gm.record_result("other", "pii", passed=False, action="block", enforced=False)
    _audit_row(redis, "other", action="monitor", guardrails=["pii"])
    # A row filed under this tenant's key but recorded for another tenant.
    _audit_row(redis, TENANT, action="monitor", guardrails=["pii"], meta_tenant="other")
    body = report_client().json()
    assert body["would_block_total"] == 0 and body["checked_total"] == 0
    assert body["examples"] == [] and body["by_guardrail"] == []
    assert report_client(tenant="other").json()["would_block_total"] == 1


def test_needs_a_tenant(report_client):
    assert report_client(tenant=None).status_code == 401


# ── the team filter ─────────────────────────────────────────────────────────

def test_team_filter_counts_from_audit(redis, tenants, report_client):
    _audit_row(redis, TENANT, action="monitor", guardrails=["pii", "keyword_blocklist"], team="sales")
    _audit_row(redis, TENANT, action="monitor", guardrails=["pii"], team="sales")
    _audit_row(redis, TENANT, action="block", guardrails=["pii"], team="sales")
    _audit_row(redis, TENANT, action="pass", team="sales")
    _audit_row(redis, TENANT, action="monitor", guardrails=["pii"], team="eng")
    _audit_row(redis, TENANT, action="monitor", guardrails=["pii"])

    body = report_client(team="sales").json()
    assert body["counts_from"] == "audit" and body["team"] == "sales"
    assert (body["checked_total"], body["would_block_total"], body["blocked_total"]) == (4, 3, 1)
    # Requests, not checks: the first row tripped two guardrails but is one request.
    assert body["would_block_requests"] == 2
    assert body["by_guardrail"] == [{"guardrail": "pii", "would_blocked": 2},
                                    {"guardrail": "keyword_blocklist", "would_blocked": 1}]
    assert body["by_team"] == [{"team": "sales", "would_blocked": 2}]
    assert body["would_block_rate_pct"] == 50.0

    everyone = report_client().json()
    assert {t["team"]: t["would_blocked"] for t in everyone["by_team"]} == \
        {"sales": 2, "eng": 1, None: 1}
    assert report_client(team="(none)").json()["checked_total"] == 1


@pytest.mark.parametrize("params", [{"team": "Bad Team!"}, {"team": "x" * 65},
                                    {"days": 0}, {"days": 31}])
def test_bad_parameters_are_422(report_client, redis, params):
    assert report_client(**params).status_code == 422


# ── coding agents ───────────────────────────────────────────────────────────

def test_coding_agent_monitor_decisions_join_examples(redis, tenants, report_client, monkeypatch):
    import api.routes_tenant_self as rts
    seen = {}

    def rows(tenant_id, **kw):
        seen.update(kw, tenant_id=tenant_id)
        return [{"timestamp": "2099-01-01T00:00:00Z", "agent_key": "claude-code",
                 "message": "coding-agent tool monitor: no-secrets", "stage": "tool"}]
    monkeypatch.setattr(rts, "_coding_agent_rows", rows)
    monkeypatch.setenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", "on")

    body = report_client().json()
    assert seen["status"] == "monitor" and seen["tenant_id"] == TENANT
    assert body["examples"][0]["source"] == "coding-agent"
    assert body["by_team"] == [{"team": None, "would_blocked": 1}]
    assert report_client(team="(none)").json()["examples"][0]["source"] == "coding-agent"
    assert report_client(team="sales").json()["examples"] == []


# ── failure modes ───────────────────────────────────────────────────────────

def test_redis_down_is_degraded_not_500(monkeypatch, tenants, report_client):
    from storage import guardrail_metrics as gm
    monkeypatch.setattr(gm, "_get_redis", lambda: None)
    r = report_client()
    assert r.status_code == 200
    body = r.json()
    assert body["degraded"] is True and body["would_block_total"] == 0
    assert body["checked_total"] is None and body["would_block_rate_pct"] is None
    assert body["would_block_requests"] is None


def test_scan_cap_says_sampled(redis, tenants, report_client, monkeypatch):
    import api.routes_shadow_report as sr
    monkeypatch.setattr(sr, "MAX_SCAN", 2)
    for _ in range(3):
        _audit_row(redis, TENANT, action="monitor", guardrails=["pii"])
    body = report_client().json()
    assert body["sampled"] is True and body["checked_total"] == 2


def test_examples_are_capped_and_newest_first(redis, tenants, report_client):
    now = time.time()
    for i in range(25):
        _audit_row(redis, TENANT, action="monitor", guardrails=["pii"], ts=now - i)
    ex = report_client().json()["examples"]
    assert len(ex) == 20
    assert [e["timestamp"] for e in ex] == sorted((e["timestamp"] for e in ex), reverse=True)


def test_empty_range_is_all_zeros(redis, tenants, report_client):
    body = report_client(days=1).json()
    assert body["checked_total"] == 0 and body["would_block_rate_pct"] is None
    assert body["daily"] == [{"date": datetime.utcnow().strftime("%Y-%m-%d"),
                              "checked": 0, "would_blocked": 0, "blocked": 0}]
    assert "Output checks (/guardrails/output) still block in monitor mode." in body["not_covered"]


# ── packaging ───────────────────────────────────────────────────────────────

def test_mounted_on_the_admin_plane_and_in_the_admin_image():
    import admin_app
    from tests.route_tables import flat_routes
    paths = [path for path, _ in flat_routes(admin_app.app)]
    assert paths, "no routes found; the check is vacuous"
    assert REPORT in paths
    assert "COPY api/routes_shadow_report.py api/" in open("Dockerfile.admin").read()
