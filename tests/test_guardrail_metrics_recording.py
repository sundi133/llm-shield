"""The agent-chat (Playground) path records guardrail effectiveness metrics.

Regression test for empty Guardrail Metrics / Board Report tabs: that path
logged telemetry (which drives the Overview's client-side counts) but never
wrote the *separate* guardrail_metrics store the two tabs read via
get_all_guardrails_summary — so they were empty while the Overview had data.

The fix records the same normalized guardrail results into guardrail_metrics.
This test exercises the real functions the fix uses (admin_app's
_summarize_guardrail_payload -> record_results_batch -> get_all_guardrails_summary)
against an in-memory fake Redis.

    PYTHONPATH=. pytest tests/test_guardrail_metrics_recording.py
"""

import fnmatch

import pytest


# ── minimal fake Redis covering exactly the ops the metrics store uses ──
class _FakePipe:
    def __init__(self, store):
        self.store = store
        self.ops = []

    def hincrby(self, key, field, n):
        self.ops.append((key, field, n)); return self

    def hincrbyfloat(self, key, field, n):
        self.ops.append((key, field, n)); return self

    def expire(self, key, ttl):
        return self

    def execute(self):
        for key, field, n in self.ops:
            h = self.store.setdefault(key, {})
            h[field] = h.get(field, 0) + n
        self.ops = []


class FakeRedis:
    def __init__(self):
        self.store = {}

    def pipeline(self, transaction=True):
        return _FakePipe(self.store)

    def hgetall(self, key):
        # decode_responses=True semantics: str keys/values
        return {k: str(v) for k, v in self.store.get(key, {}).items()}

    def scan(self, cursor=0, match="*", count=100):
        return 0, [k for k in self.store if fnmatch.fnmatch(k, match)]


@pytest.fixture
def fake_redis(monkeypatch):
    from storage import tenant_store
    r = FakeRedis()
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: r)
    return r


# the two guardrail-result shapes the agent-chat path actually produces:
# a multi-result payload (input) and a single-result block payload (output).
INPUT_RESULT = {"results": [
    {"guardrail_name": "toxicity", "passed": True, "action": "pass"},
    {"guardrail_name": "topic_restriction", "passed": False, "action": "block"},
]}
OUTPUT_RESULT = {"action": "block", "guardrail": "system_prompt_leak",
                 "reason": "leak", "allowed": False}


def _record_like_agent_chat(tenant_id, input_res, output_res):
    """Mirror the fix in admin_app's agent-chat handler."""
    from admin_app import _summarize_guardrail_payload
    from storage.guardrail_metrics import record_results_batch
    batch = (_summarize_guardrail_payload(input_res)
             + _summarize_guardrail_payload(output_res))
    record_results_batch(tenant_id, batch)
    return batch


def test_normalized_batch_feeds_metrics_store(fake_redis):
    """record_results_batch accepts _summarize_guardrail_payload output and the
    two tabs' read path (get_all_guardrails_summary) then returns the guardrails."""
    from storage.guardrail_metrics import get_all_guardrails_summary

    _record_like_agent_chat("bankco", INPUT_RESULT, OUTPUT_RESULT)

    summary = {g["guardrail"]: g for g in get_all_guardrails_summary("bankco", days=30)}

    # blocked guardrails show up with the right block count
    assert summary["topic_restriction"]["blocked"] == 1
    assert summary["system_prompt_leak"]["blocked"] == 1
    # a passing guardrail is still recorded (total>0) so the tab isn't empty
    assert summary["toxicity"]["total"] == 1
    assert summary["toxicity"]["blocked"] == 0


def test_board_report_totals_reflect_recording(fake_redis):
    """Board Report aggregates the same store: totals/blocked must be non-zero."""
    from storage.guardrail_metrics import get_all_guardrails_summary

    _record_like_agent_chat("bankco", INPUT_RESULT, OUTPUT_RESULT)
    summary = get_all_guardrails_summary("bankco", days=30)

    total = sum(g["total"] for g in summary)
    blocked = sum(g["blocked"] for g in summary)
    assert total == 3        # toxicity + topic_restriction + system_prompt_leak
    assert blocked == 2      # the two blocks


def test_tenant_isolation(fake_redis):
    """Metrics are scoped per tenant — another tenant sees nothing."""
    from storage.guardrail_metrics import get_all_guardrails_summary
    _record_like_agent_chat("bankco", INPUT_RESULT, OUTPUT_RESULT)
    assert get_all_guardrails_summary("other-tenant", days=30) == []


def test_no_redis_is_a_noop(monkeypatch):
    """Without Redis the store no-ops (this is *why* the tabs were empty when the
    data plane had no Redis) — recording must not raise, read returns []."""
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    from storage.guardrail_metrics import get_all_guardrails_summary
    _record_like_agent_chat("bankco", INPUT_RESULT, OUTPUT_RESULT)  # must not raise
    assert get_all_guardrails_summary("bankco", days=30) == []


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
