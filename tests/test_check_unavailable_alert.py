"""An alert and a count when a tool policy check could not run
(docs/specs/tool-policy-fail-safe.md, task 2).

Task 1 made an unchecked call visible in its own result. Nobody reads every
result: an outage has to reach the ops team (a webhook, which also fans out to
SIEM) and show up as a number (a metric), without flooding either.
"""
import asyncio
import json
import pathlib

import pytest

import core.check_alerts as ca
import core.webhook_dispatcher as wd
import guardrails.agentic.tool.payload_risk as pr
import guardrails.agentic.tool.tool_output_sanitization as tos
import storage.guardrail_metrics as gm
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

TENANT = "alert-tenant"
TOOL = "send_email"
SECRET_ARG = "acct 4111-1111-1111-1111"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ca._reset()
    for k in ("SHIELD_DLP_FAIL_CLOSED", "SHIELD_METRICS_INLINE"):
        monkeypatch.delenv(k, raising=False)
    yield
    ca._reset()


@pytest.fixture
def sent(monkeypatch):
    out = []

    async def fake_dispatch(tenant_id, event_type, payload):
        out.append((tenant_id, event_type, payload))
    monkeypatch.setattr(wd, "dispatch_event", fake_dispatch)
    return out


@pytest.fixture
def policies(monkeypatch):
    """One tool policy with rules and an intent, so both guards ask the model."""
    loaded = [{"tool_name": TOOL, "policy_source": "tool", "fail_closed": None,
               "role_policies": [{"role": "*", "action": "block",
                                  "input_rules": ["Only acme.com recipients"]}],
               "sanitization_rules": [], "sanitization_intent": "no account numbers",
               "sanitization_mode": "regex"}]
    monkeypatch.setattr(pr, "_load_data_policies", lambda tid, tool="": loaded)
    return loaded


def _model_down(monkeypatch):
    async def boom(**kw):
        raise ConnectionError(f"upstream said {SECRET_ARG}")
    monkeypatch.setattr(pr, "async_llm_call", boom)
    monkeypatch.setattr(tos, "async_llm_call", boom)


async def _drain():
    while ca._TASKS:
        await asyncio.gather(*list(ca._TASKS))


def _calls(n):
    async def run():
        g = ToolCallValidationGuardrail()
        out = [await g.check("", {"tool_name": TOOL, "tool_params": {"note": SECRET_ARG},
                                  "tenant_id": TENANT}) for _ in range(n)]
        await _drain()
        return out
    return asyncio.run(run())


# ── the window ───────────────────────────────────────────────────────────


def test_the_first_failure_alerts_and_the_rest_fold_into_the_next():
    t0 = 1000.0
    assert ca._take(TENANT, "tool_call", t0) == 1
    assert [ca._take(TENANT, "tool_call", t0 + s) for s in (1, 2, 299)] == [None] * 3
    assert ca._take(TENANT, "tool_call", t0 + 300) == 4          # 3 folded + this one
    assert ca._take(TENANT, "tool_call", t0 + 301) is None


def test_windows_are_per_tenant_and_per_side():
    assert ca._take(TENANT, "tool_call", 0.0) == 1
    assert ca._take(TENANT, "tool_result", 1.0) == 1
    assert ca._take("other-tenant", "tool_call", 2.0) == 1


def test_no_tenant_or_no_event_loop_sends_nothing_and_raises_nothing(sent):
    ca.note_unchecked("", "tool_call", TOOL, False, "TimeoutError")
    ca.note_unchecked(TENANT, "tool_call", TOOL, False, "TimeoutError")   # no loop
    assert sent == []


# ── from the guards ──────────────────────────────────────────────────────


def test_an_outage_sends_one_alert_not_one_per_call(monkeypatch, sent, policies):
    _model_down(monkeypatch)
    results = _calls(5)
    assert all(r.details["unjudged"] for r in results)
    assert len(sent) == 1
    tenant, event, payload = sent[0]
    assert (tenant, event) == (TENANT, "check_unavailable")
    assert payload == {"side": "tool_call", "tool": TOOL, "decision": "let_through",
                       "error": "ConnectionError", "count": 1, "window_seconds": 300}


def test_the_alert_says_blocked_when_the_policy_fails_closed(monkeypatch, sent, policies):
    policies[0]["fail_closed"] = True
    _model_down(monkeypatch)
    _calls(1)
    assert sent[0][2]["decision"] == "blocked"


def test_the_alert_never_carries_arguments_or_the_error_text(monkeypatch, sent, policies):
    _model_down(monkeypatch)
    _calls(1)
    assert SECRET_ARG not in json.dumps(sent)


def test_a_judged_call_sends_nothing(monkeypatch, sent, policies):
    async def fine(**kw):
        return {"choices": [{"message": {"content": "false,0.9,none,low,ok"}}]}
    monkeypatch.setattr(pr, "async_llm_call", fine)
    _calls(3)
    assert sent == []


def _result_check(inner=False):
    async def run():
        g = ToolOutputSanitizationGuardrail()
        ctx = {"tool_output": f"note: {SECRET_ARG}", "tool_name": TOOL,
               "tenant_id": TENANT, "user_role": "support"}
        r = await (g._check_inner("", ctx) if inner else g.check("", ctx))
        await _drain()
        return r
    return asyncio.run(run())


def test_a_result_check_that_fails_alerts_on_its_own_side(monkeypatch, sent, policies):
    _model_down(monkeypatch)
    r = _result_check()
    assert r.details["unjudged"] is True
    assert [(e, p["side"], p["decision"], p["error"]) for _, e, p in sent] == [
        ("check_unavailable", "tool_result", "let_through", "ConnectionError")]
    assert SECRET_ARG not in json.dumps(sent)


def test_the_editors_dry_run_never_alerts(monkeypatch, sent, policies):
    """POST /v1/data-policies/try calls _check_inner, not check()."""
    _model_down(monkeypatch)
    _result_check(inner=True)
    assert sent == []


# ── the count ────────────────────────────────────────────────────────────


class _FakeRedis:
    def __init__(self):
        self.h = {}

    def hincrby(self, k, f, n):
        self.h.setdefault(k, {}); self.h[k][f] = self.h[k].get(f, 0) + n

    def hincrbyfloat(self, k, f, n):
        self.hincrby(k, f, n)

    def expire(self, k, s):
        pass


@pytest.fixture
def metrics(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(gm, "_get_redis", lambda: r)
    return r


def _fields(r):
    (only,) = r.h.values()
    return only


def test_an_unjudged_let_through_counts_as_passed_and_unjudged(metrics):
    gm.record_results_batch(TENANT, [{"guardrail": "tool_call_validation", "passed": True,
                                      "action": "warn", "details": {"unjudged": True}}])
    assert _fields(metrics) == {"total": 1, "passed": 1, "unjudged": 1}


def test_an_unjudged_block_counts_as_blocked_and_unjudged(metrics):
    gm.record_results_batch(TENANT, [{"guardrail": "tool_call_validation", "passed": False,
                                      "action": "block", "details": {"unjudged": True}}])
    assert _fields(metrics) == {"total": 1, "blocked": 1, "unjudged": 1}


def test_a_judged_result_has_no_unjudged_field(metrics):
    """Regression guard: existing counters are unchanged."""
    gm.record_results_batch(TENANT, [{"guardrail": "tool_call_validation", "passed": True,
                                      "action": "pass"}])
    assert _fields(metrics) == {"total": 1, "passed": 1}


def test_the_guard_result_reaches_the_counter(monkeypatch, metrics, policies):
    """Through the real result shape, not a hand-built dict."""
    from core.mcp.enforcement import _result_dict
    _model_down(monkeypatch)
    r = _calls(1)[0]
    gm.record_results_batch(TENANT, [_result_dict(r)])
    assert _fields(metrics)["unjudged"] == 1


# ── subscribable ─────────────────────────────────────────────────────────


def test_tenants_can_subscribe_to_it():
    from api.routes_webhooks import VALID_EVENTS
    assert ca.EVENT == "check_unavailable" in VALID_EVENTS


def test_the_portal_offers_it():
    html = (pathlib.Path(__file__).resolve().parent.parent / "static" / "tenant.html").read_text()
    assert 'class="wh-event" value="check_unavailable"' in html
