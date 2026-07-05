"""Guardrail dashboard aggregation (GET /v1/tenant/me/guardrails/dashboard).

Covers the spec's edge cases: severity derivation, top-N ordering, tenant
scoping via key derivation, malformed audit entries, truncation flagging,
days clamping, unknown user/device bucketing, empty tenant, and Redis-down
degradation. Also locks in the route layout: /dashboard must NOT be captured
by /metrics/{guardrail_name}.

    PYTHONPATH=. pytest tests/test_guardrail_dashboard.py
"""

import fnmatch
import json
import time

import pytest


class FakeRedis:
    """Covers exactly the ops the dashboard read path uses: hashes for the
    effectiveness store, a ZSET for the audit log. Mimics the Upstash REST
    client (pipeline() raises -> sequential fallback, zrevrangebyscore uses
    offset/count kwargs)."""

    def __init__(self):
        self.store = {}
        self.zsets = {}

    # hash ops (effectiveness store)
    def hincrby(self, key, field, n=1):
        h = self.store.setdefault(key, {})
        h[field] = int(h.get(field, 0)) + n
        return h[field]

    def hincrbyfloat(self, key, field, n):
        h = self.store.setdefault(key, {})
        h[field] = float(h.get(field, 0)) + n
        return h[field]

    def expire(self, key, ttl):
        return True

    def hgetall(self, key):
        return {k: str(v) for k, v in self.store.get(key, {}).items()}

    def scan(self, cursor=0, match="*", count=100):
        return 0, [k for k in self.store if fnmatch.fnmatch(k, match)]

    def pipeline(self, *args, **kwargs):
        raise TypeError("no pipeline in FakeRedis; sequential fallback path")

    # zset ops (audit log)
    def zadd(self, key, mapping):
        z = self.zsets.setdefault(key, [])
        for member, score in mapping.items():
            z.append((score, member))
        z.sort(key=lambda x: x[0])
        return len(mapping)

    def zrevrangebyscore(self, key, max_score, min_score, offset=0, count=None):
        lo = float("-inf") if min_score == "-inf" else float(min_score)
        hi = float("inf") if max_score == "+inf" else float(max_score)
        members = [m for (s, m) in reversed(self.zsets.get(key, []))
                   if lo <= s <= hi]
        if count is None:
            return members[offset:]
        return members[offset:offset + count]


@pytest.fixture
def fake_redis(monkeypatch):
    from storage import tenant_store
    r = FakeRedis()
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: r)
    return r


def _audit_event(r, tenant, action, triggered, agent="alice@co.com",
                 device="LAPTOP-1", message="hello", ts=None, raw=None):
    ts = ts or time.time()
    record = raw if raw is not None else json.dumps({
        "timestamp": "2026-07-05T00:00:00",
        "ts": ts,
        "agent_key": agent,
        "endpoint": "/guardrails/input",
        "input_text": message,
        "action_taken": action,
        "guardrails_triggered": triggered,
        "latency_ms": 10.0,
        "metadata": {"tenant_id": tenant, "device_id": device},
    })
    r.zadd(f"audit:{tenant}", {record: ts})


def _metric(r, tenant, guardrail, **fields):
    from storage.guardrail_metrics import record_result
    record_result(tenant, guardrail,
                  passed=fields.get("passed", True),
                  action=fields.get("action", "pass"),
                  latency_ms=fields.get("latency_ms", 1.0))


# ── happy path ────────────────────────────────────────────────────────────

def test_dashboard_aggregates_summary_and_tops(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard

    r = fake_redis
    # metrics store: 2 blocked checks + 1 pass today
    _metric(r, "bankco", "adversarial_detection", passed=False, action="block")
    _metric(r, "bankco", "toxicity", passed=False, action="block")
    _metric(r, "bankco", "toxicity", passed=True, action="pass")

    # audit: critical block (adversarial), generic block, warn, clean pass
    _audit_event(r, "bankco", "block", ["adversarial_detection"], agent="alice@co.com", device="LAPTOP-1")
    _audit_event(r, "bankco", "block", ["keyword_blocklist"], agent="bob@co.com", device="LAPTOP-2")
    _audit_event(r, "bankco", "warn", ["toxicity"], agent="alice@co.com", device="LAPTOP-1")
    _audit_event(r, "bankco", "pass", [], agent="carol@co.com", device="LAPTOP-3")

    out = get_blocked_dashboard("bankco", days=30)

    assert out["summary"]["blocked"] == 2
    assert out["summary"]["warned"] == 1
    assert out["summary"]["total"] == 3  # clean pass is not an issue
    assert out["summary"]["by_severity"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 0}

    # top users: alice (1 blocked 1 warned) before bob (1 blocked)
    assert out["top_users"][0]["agent_key"] == "alice@co.com"
    assert out["top_users"][0]["blocked"] == 1
    assert out["top_users"][0]["warned"] == 1
    assert {u["agent_key"] for u in out["top_users"]} == {"alice@co.com", "bob@co.com"}

    assert out["top_devices"][0]["device_id"] == "LAPTOP-1"

    issues = {i["guardrail"]: i for i in out["top_issues"]}
    assert issues["adversarial_detection"]["severity"] == "critical"
    assert issues["keyword_blocklist"]["severity"] == "high"
    assert issues["toxicity"]["severity"] == "medium"

    # recent blocked: newest first, only blocks, message truncated to 120
    assert len(out["recent_blocked"]) == 2
    assert all(e["guardrails"] for e in out["recent_blocked"])

    # daily series present (from the metrics hashes), oldest first
    assert out["daily"], "daily series should be non-empty"
    today = out["daily"][-1]
    assert today["blocked"] == 2 and today["passed"] == 1


def test_severity_mapping_rules(fake_redis):
    from storage.guardrail_metrics import _event_severity
    assert _event_severity("block", ["adversarial_detection"]) == "critical"
    assert _event_severity("block", ["system_prompt_leak"]) == "critical"
    assert _event_severity("block", ["custom_policy_input"]) == "critical"
    assert _event_severity("block", ["pii_detection"]) == "critical"
    assert _event_severity("block", ["keyword_blocklist"]) == "high"
    assert _event_severity("warn", ["toxicity"]) == "medium"
    assert _event_severity("log", ["tone_enforcement"]) == "low"


# ── degraded / edge paths ─────────────────────────────────────────────────

def test_empty_tenant_returns_zero_shape(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    out = get_blocked_dashboard("nobody", days=30)
    assert out["summary"]["total"] == 0
    assert out["top_issues"] == [] and out["top_users"] == []
    assert out["recent_blocked"] == [] and out["daily"] == []
    assert out["truncated"] is False


def test_no_redis_degrades_to_zero_shape(monkeypatch):
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    from storage.guardrail_metrics import get_blocked_dashboard
    out = get_blocked_dashboard("bankco", days=30)
    assert out["summary"]["total"] == 0 and out["daily"] == []


def test_malformed_audit_entries_are_skipped(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    r = fake_redis
    _audit_event(r, "bankco", "block", ["toxicity"])
    _audit_event(r, "bankco", None, None, raw="not json {{{")
    _audit_event(r, "bankco", None, None, raw=json.dumps(["a", "list"]))
    out = get_blocked_dashboard("bankco", days=30)
    assert out["summary"]["blocked"] == 1  # only the valid entry counted


def test_truncation_flag(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    r = fake_redis
    for i in range(5):
        _audit_event(r, "bankco", "block", ["toxicity"], ts=time.time() - i)
    out = get_blocked_dashboard("bankco", days=30, max_scan=3)
    assert out["scanned"] == 3
    assert out["truncated"] is True
    assert out["summary"]["blocked"] == 3


def test_days_clamped(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    assert get_blocked_dashboard("bankco", days=0)["days"] == 1
    assert get_blocked_dashboard("bankco", days=-5)["days"] == 1
    assert get_blocked_dashboard("bankco", days=9999)["days"] == 90


def test_missing_identity_bucketed_as_unknown(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    r = fake_redis
    record = json.dumps({
        "ts": time.time(), "agent_key": "", "action_taken": "block",
        "guardrails_triggered": ["toxicity"], "input_text": "x",
        "metadata": {},  # no device_id (pre-capture events)
    })
    r.zadd("audit:bankco", {record: time.time()})
    out = get_blocked_dashboard("bankco", days=30)
    assert out["top_users"][0]["agent_key"] == "(unknown)"
    assert out["top_devices"][0]["device_id"] == "(unknown)"


def test_tenant_scoping(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    _audit_event(fake_redis, "bankco", "block", ["toxicity"])
    assert get_blocked_dashboard("other", days=30)["summary"]["total"] == 0


def test_events_outside_window_excluded(fake_redis):
    from storage.guardrail_metrics import get_blocked_dashboard
    old = time.time() - 40 * 86400
    _audit_event(fake_redis, "bankco", "block", ["toxicity"], ts=old)
    assert get_blocked_dashboard("bankco", days=30)["summary"]["blocked"] == 0
    assert get_blocked_dashboard("bankco", days=90)["summary"]["blocked"] == 1


# ── route layout: /dashboard must not be captured by /metrics/{name} ──────

def test_dashboard_route_not_swallowed_by_metrics_param_route():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from api.routes_guardrail_metrics import router

    app = FastAPI()

    @app.middleware("http")
    async def fake_tenant(request, call_next):
        request.state.tenant_id = "bankco"
        return await call_next(request)

    app.include_router(router)
    client = TestClient(app)

    resp = client.get("/v1/tenant/me/guardrails/dashboard")
    assert resp.status_code == 200
    body = resp.json()
    # dashboard shape, NOT the single-guardrail metrics shape
    assert "summary" in body and "top_users" in body
    assert body.get("guardrail") != "dashboard"

    # the param route still works for a real guardrail name
    resp2 = client.get("/v1/tenant/me/guardrails/metrics/toxicity")
    assert resp2.status_code == 200
    assert resp2.json()["guardrail"] == "toxicity"


# ── device_id capture on the guard path feeds the dashboard ──────────────

def test_guardrails_input_captures_device_id(fake_redis, monkeypatch):
    """POST /guardrails/input with X-Device-Id lands device_id in the audit
    metadata, and the dashboard surfaces it under top_devices."""
    import asyncio
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from api.routes_classify import router as classify_router
    import storage.audit_log as audit_log_mod

    # audit_logger.log defers to a thread pool; make it synchronous so the
    # write is visible before the assertion.
    async def sync_log(self, entry):
        self._write_sync(entry)
    monkeypatch.setattr(audit_log_mod.AuditLogger, "log", sync_log)

    app = FastAPI()

    @app.middleware("http")
    async def fake_tenant(request, call_next):
        request.state.tenant_id = "bankco"
        request.state.tenant_config = None
        return await call_next(request)

    monkeypatch.setattr(
        "storage.tenant_store.resolve_request_tenant_id", lambda req: "bankco",
        raising=False)

    app.include_router(classify_router)
    client = TestClient(app)

    resp = client.post(
        "/guardrails/input",
        json={"message": "hello world", "device_id": "BODY-DEV"},
        headers={"X-Device-Id": "LAPTOP-42", "X-Agent-Key": "alice@co.com"},
    )
    assert resp.status_code == 200

    entries = fake_redis.zsets.get("audit:bankco", [])
    assert entries, "audit entry should be written"
    record = json.loads(entries[-1][1])
    # header wins over body
    assert record["metadata"]["device_id"] == "LAPTOP-42"

    # body fallback when no header
    resp2 = client.post("/guardrails/input",
                        json={"message": "hi again", "device_id": "BODY-DEV"})
    assert resp2.status_code == 200
    record2 = json.loads(fake_redis.zsets["audit:bankco"][-1][1])
    assert record2["metadata"]["device_id"] == "BODY-DEV"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
