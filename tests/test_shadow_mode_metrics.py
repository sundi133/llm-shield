"""Monitor-mode would-blocks are counted on their own, never as blocks.

Spec: docs/specs/shadow-mode-report.md, task 1. Before this, a guardrail result
that monitor mode let through kept action "block" and only gained
"enforced": False, which the metrics store ignored, so a monitor-mode tenant's
Board Report claimed blocks that never happened.

What carries the weight:
- the counting table (every row of spec section 3);
- the regression guard: an enforce-mode run writes exactly the fields it wrote
  before, and no would_blocked field at all;
- one test per guard-path writer, so a writer that stops marking monitor
  results is caught here rather than in a customer's report.
"""

import asyncio
import fnmatch
import io
from unittest.mock import patch

import pytest

from config.schema import GuardrailConfig, ShieldConfig


class FakeRedis:
    """Upstash-like: direct ops only, pipeline() raises (as in production)."""

    def __init__(self):
        self.store = {}
        self.strings = {}

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

    def set(self, key, value, nx=False):
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True

    def get(self, key):
        return self.strings.get(key)

    def pipeline(self, *args, **kwargs):
        raise TypeError("Upstash pipeline API differs; use direct calls")


@pytest.fixture
def metrics(monkeypatch):
    """A fake store behind guardrail_metrics only (the tenant store keeps its
    in-process fallback), recording synchronously."""
    from storage import guardrail_metrics as gm
    r = FakeRedis()
    monkeypatch.setattr(gm, "_get_redis", lambda: r)
    # raising=False: with the fix reverted the attribute is absent, and the
    # tests must then FAIL on their assertions, not error in the fixture.
    monkeypatch.setattr(gm, "_split_marked", False, raising=False)
    monkeypatch.setenv("SHIELD_METRICS_INLINE", "1")
    monkeypatch.delenv("SHIELD_METRICS_SPLIT_WOULD_BLOCK", raising=False)
    return r


def _fields(r, tenant, guardrail):
    """The one day's hash for (tenant, guardrail), without latency fields."""
    keys = [k for k in r.store if k.startswith(f"guardrail:metrics:{tenant}:{guardrail}:")]
    assert len(keys) == 1, keys
    return {k: v for k, v in r.store[keys[0]].items() if not k.startswith("latency")}


# ── the counting table (spec section 3) ─────────────────────────────────────

@pytest.mark.parametrize("passed,action,enforced,field", [
    (True, "pass", True, "passed"),
    (True, "pass", False, "passed"),
    (False, "block", False, "would_blocked"),
    (False, "pending_confirmation", False, "would_blocked"),
    (False, "block", True, "blocked"),
    (False, "warn", True, "warned"),
    (False, "warn", False, "warned"),
    (False, "log", True, "logged"),
    (False, "redact", False, "logged"),
    (False, "pending_confirmation", True, "logged"),
])
def test_counting_table(metrics, passed, action, enforced, field):
    from storage.guardrail_metrics import record_result
    record_result("t", "g", passed=passed, action=action, enforced=enforced)
    assert _fields(metrics, "t", "g") == {"total": 1, field: 1}


def test_enforced_is_read_from_the_result_and_from_details(metrics):
    from storage.guardrail_metrics import record_results_batch
    record_results_batch("t", [
        # core.policy_mode.apply marks the result itself
        {"guardrail": "a", "passed": False, "action": "block", "enforced": False},
        # core.tenant_pipeline marks details
        {"guardrail": "b", "passed": False, "action": "block",
         "details": {"enforced": False, "would_block": True}},
        # no mark: enforced, today's behaviour
        {"guardrail": "c", "passed": False, "action": "block"},
        {"guardrail": "d", "passed": False, "action": "block", "enforced": True},
        {"guardrail": "e", "passed": False, "action": "block", "details": None},
    ])
    assert _fields(metrics, "t", "a") == {"total": 1, "would_blocked": 1}
    assert _fields(metrics, "t", "b") == {"total": 1, "would_blocked": 1}
    for g in "cde":
        assert _fields(metrics, "t", g) == {"total": 1, "blocked": 1}


def test_escape_hatch_restores_the_old_counting(metrics, monkeypatch):
    from storage.guardrail_metrics import record_result
    monkeypatch.setenv("SHIELD_METRICS_SPLIT_WOULD_BLOCK", "off")
    record_result("t", "g", passed=False, action="block", enforced=False)
    record_result("t", "g", passed=False, action="pending_confirmation", enforced=False)
    assert _fields(metrics, "t", "g") == {"total": 2, "blocked": 1, "logged": 1}
    assert metrics.strings == {}, "no split marker when the split is off"


def test_split_since_is_marked_once_on_the_first_would_block(metrics):
    from storage import guardrail_metrics as gm
    gm.record_result("t", "g", passed=False, action="block", enforced=True)
    assert gm.get_split_since() is None, "an enforced block is not a would-block"
    gm.record_result("t", "g", passed=False, action="block", enforced=False)
    first = gm.get_split_since()
    assert first and len(first) == 10
    metrics.strings[gm._SPLIT_SINCE_KEY] = "2000-01-01"   # an earlier deploy's mark
    gm._split_marked = False                              # a new process
    gm.record_result("t", "g", passed=False, action="block", enforced=False)
    assert gm.get_split_since() == "2000-01-01", "SET NX never moves the date"


def test_the_marker_is_never_mistaken_for_a_tenant_guardrail(metrics):
    from storage import guardrail_metrics as gm
    gm.record_result("split_since", "g", passed=False, action="block", enforced=False)
    names = {row["guardrail"] for row in gm.get_all_guardrails_summary("split_since")}
    assert names == {"g"}
    assert not gm._SPLIT_SINCE_KEY.startswith(gm._METRICS_KEY_PREFIX + ":")


def test_summaries_report_would_blocks_apart(metrics):
    from storage import guardrail_metrics as gm
    for _ in range(3):
        gm.record_result("t", "g", passed=False, action="block", enforced=False)
    gm.record_result("t", "g", passed=False, action="block", enforced=True)
    gm.record_result("t", "g", passed=True, action="pass")

    [row] = gm.get_all_guardrails_summary("t", days=7)
    assert (row["total"], row["blocked"], row["would_blocked"]) == (5, 1, 3)
    assert row["block_rate"] == 0.2 and row["would_block_rate"] == 0.6

    eff = gm.get_effectiveness("t", "g", days=7)
    assert eff["daily"][-1]["would_blocked"] == 3 and eff["daily"][-1]["blocked"] == 1
    assert gm._daily_totals("t", 7)[-1]["would_blocked"] == 3


def test_an_empty_store_reports_zero_would_blocks(monkeypatch):
    from storage import guardrail_metrics as gm
    monkeypatch.setattr(gm, "_get_redis", lambda: None)
    eff = gm.get_effectiveness("t", "g", days=7)
    assert eff["would_blocked"] == 0 and eff["would_block_rate"] == 0.0
    assert gm.get_split_since() is None


# ── the guard-path writers ──────────────────────────────────────────────────

BAD = "shadow_bad_word"
TENANT = "shadow-metrics-tenant"
KEY = "shadow-metrics-key-aaaaaaaaaaaa"


@pytest.fixture
def make_client(monkeypatch, metrics):
    """A data-plane app whose tenant blocks BAD, in the given policy_mode."""
    import config.schema as cs
    from guardrails import registry as reg
    from storage import tenant_store

    cfg = ShieldConfig(guardrails={
        "keyword_blocklist": GuardrailConfig(
            enabled=True, action="block",
            settings={"keywords": [BAD], "case_insensitive": True}),
    })
    original = cs.config
    cs.config = cfg
    reg._registry.clear()
    reg._discovered = False
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    monkeypatch.setattr(tenant_store, "_fallback_store", {})
    monkeypatch.setattr(tenant_store, "_cache", {})
    patches = []

    def _make(mode):
        from starlette.testclient import TestClient
        tenant_store.create_tenant(TENANT, {
            "tenant_id": TENANT, "name": "Shadow Co", "policy_mode": mode,
            "quota": {"max_requests_per_minute": 100_000}})
        tenant_store.add_api_key(TENANT, KEY, scope="admin")
        with patch("config.schema.load_config", return_value=cfg):
            from core.app import create_app
            app = create_app()
        p = patch("core.middleware._get_cached_tenant",
                  side_effect=lambda key: (TENANT, tenant_store.get_tenant(TENANT)))
        p.start()
        patches.append(p)
        return TestClient(app)

    yield _make
    for p in patches:
        p.stop()
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


def _input(client):
    return client.post("/guardrails/input", json={"message": f"a {BAD} prompt"},
                       headers={"x-api-key": KEY}).json()


def _file(client):
    return client.post("/guardrails/file",
                       files={"file": ("n.txt", io.BytesIO(f"has {BAD}".encode()), "text/plain")},
                       headers={"x-api-key": KEY}).json()


@pytest.mark.parametrize("send", [_input, _file], ids=["input", "file"])
def test_monitor_mode_guard_routes_count_would_blocks(make_client, metrics, send):
    out = send(make_client("monitor"))
    assert out["action"] == "monitor" and "keyword_blocklist" in out["would_block"]
    assert _fields(metrics, TENANT, "keyword_blocklist") == {"total": 1, "would_blocked": 1}


@pytest.mark.parametrize("send", [_input, _file], ids=["input", "file"])
def test_regression_enforce_mode_counts_exactly_as_before(make_client, metrics, send):
    out = send(make_client("enforce"))
    assert out["action"] == "block"
    fields = _fields(metrics, TENANT, "keyword_blocklist")
    assert fields == {"total": 1, "blocked": 1}
    assert "would_blocked" not in fields
    assert metrics.strings == {}


def _tool_check(client):
    # No registry entry for the agent, so the tool allowlist blocks the call.
    return client.post("/v1/shield/tool/check",
                       json={"tool_name": "send_payment", "agent_key": "unknown-bot",
                             "user_role": "reader", "arguments": {}},
                       headers={"x-api-key": KEY}).json()


def test_monitor_mode_tool_check_counts_would_blocks(make_client, metrics):
    out = _tool_check(make_client("monitor"))
    assert out.get("would_block"), out
    recorded = {g["guardrail"]: g for g in
                __import__("storage.guardrail_metrics", fromlist=["x"]).get_all_guardrails_summary(TENANT)}
    for name in out["would_block"]:
        assert recorded[name]["would_blocked"] >= 1 and recorded[name]["blocked"] == 0, recorded


def test_monitor_mode_mcp_enforcement_counts_would_blocks(metrics):
    from core.mcp.enforcement import enforce_tool_call
    from storage.guardrail_metrics import get_all_guardrails_summary

    decision = asyncio.run(enforce_tool_call(
        "send_payment", {"amount": 9}, agent_key="mcp-agent", user_role="reader",
        tenant_id="bankco", tenant_config={"policy_mode": "monitor"}))
    assert decision["allowed"] is True and decision["would_block"], decision
    recorded = {g["guardrail"]: g for g in get_all_guardrails_summary("bankco")}
    for name in decision["would_block"]:
        assert recorded[name]["would_blocked"] == 1 and recorded[name]["blocked"] == 0


# ── the read routes ─────────────────────────────────────────────────────────

def test_board_report_keeps_would_blocks_out_of_blocked(metrics, monkeypatch):
    from types import SimpleNamespace
    from api.routes_board_report import board_report
    from storage import guardrail_metrics as gm, tenant_store

    monkeypatch.setattr(tenant_store, "get_tenant", lambda t: {"policy_mode": "monitor"})
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    for _ in range(4):
        gm.record_result("acme", "pii", passed=False, action="block", enforced=False)
    gm.record_result("acme", "pii", passed=False, action="block", enforced=True)
    gm.record_result("acme", "pii", passed=True, action="pass")

    req = SimpleNamespace(state=SimpleNamespace(tenant_id="acme"))
    out = asyncio.run(board_report(req, days=7))
    s = out["summary"]
    assert (s["total_requests"], s["blocked_count"], s["would_blocked_count"]) == (6, 1, 4)
    assert s["block_rate_pct"] == round(1 / 6 * 100, 1)
    assert [t["blocked"] for t in out["top_threats"]] == [1]
    assert out["daily_trend"][-1]["would_blocked"] == 4 and out["daily_trend"][-1]["blocked"] == 1


def test_telemetry_summary_always_has_a_monitor_count(make_client, monkeypatch):
    """by_status carries "monitor" even with no monitor rows, and counts them
    when there are some, so the portal's Would block tile never guesses."""
    import api.routes_tenant_self as rts
    client = make_client("monitor")
    rows = []

    async def query(filters=None, limit=100, offset=0, tenant_id=None):
        return list(rows)
    monkeypatch.setattr(rts.audit_logger, "query", query)
    monkeypatch.setenv("SHIELD_TELEMETRY_INCLUDE_CODING_AGENT", "off")

    def summary():
        return client.get("/v1/tenant/me/telemetry",
                          headers={"x-api-key": KEY}).json()["summary"]["by_status"]

    assert summary() == {"pass": 0, "warn": 0, "block": 0, "monitor": 0}
    for i, action in enumerate(["monitor", "monitor", "pass"]):
        rows.append({"id": f"r{i}", "timestamp": f"2026-11-08T00:00:0{i}Z",
                     "agent_key": "bot", "input_text": "x", "action_taken": action,
                     "metadata": {"kind": "agent_chat_telemetry", "tenant_id": TENANT,
                                  "stage": "input", "tool_calls": []}})
    assert summary() == {"pass": 1, "warn": 0, "block": 0, "monitor": 2}
