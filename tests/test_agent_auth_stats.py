"""Tests for the agent-auth stats counters and ring buffer."""

import pytest

from storage import agent_auth_stats as stats


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    """Force the in-process fallback for deterministic tests."""
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    stats.clear_for_tests()
    yield
    stats.clear_for_tests()


class TestRecord:
    def test_skips_missing_tenant(self):
        stats.record(tenant_id=None, event=stats.EVENT_CAP_MINTED)
        # Nothing should land
        assert stats.get_counters("anything")["totals"][stats.EVENT_CAP_MINTED] == 0

    def test_skips_unknown_event(self):
        stats.record(tenant_id="t1", event="not_a_real_event")
        assert all(v == 0 for v in stats.get_counters("t1")["totals"].values())

    def test_never_raises_on_storage_error(self, monkeypatch):
        """Record must be fire-and-forget: storage errors don't propagate."""
        bad_store = type("BadDict", (), {
            "get": lambda self, k: (_ for _ in ()).throw(RuntimeError("boom")),
            "__setitem__": lambda self, k, v: None,
            "__contains__": lambda self, k: False,
            "pop": lambda self, k, d=None: None,
            "keys": lambda self: [],
        })()
        monkeypatch.setattr(stats, "_fallback_store", bad_store)
        # Must not raise
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED)


class TestCounters:
    def test_increments_daily(self):
        for _ in range(3):
            stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED)
        for _ in range(2):
            stats.record(tenant_id="t1", event=stats.EVENT_CAP_DENIED)

        result = stats.get_counters("t1", days=1)
        assert result["totals"][stats.EVENT_CAP_MINTED] == 3
        assert result["totals"][stats.EVENT_CAP_DENIED] == 2
        assert result["totals"][stats.EVENT_CAP_REPLAY] == 0

    def test_isolates_tenants(self):
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED)
        stats.record(tenant_id="t2", event=stats.EVENT_CAP_MINTED)
        stats.record(tenant_id="t2", event=stats.EVENT_CAP_MINTED)
        assert stats.get_counters("t1")["totals"][stats.EVENT_CAP_MINTED] == 1
        assert stats.get_counters("t2")["totals"][stats.EVENT_CAP_MINTED] == 2

    def test_days_shape(self):
        stats.record(tenant_id="t1", event=stats.EVENT_TOKEN_ISSUED)
        result = stats.get_counters("t1", days=3)
        assert len(result["days"]) == 3
        assert all("date" in d and "counts" in d for d in result["days"])
        # Today is the last entry
        today_counts = result["days"][-1]["counts"]
        assert today_counts[stats.EVENT_TOKEN_ISSUED] == 1

    def test_days_bound(self):
        # 0 → defaulted; >90 → defaulted; both should return 7 days
        assert len(stats.get_counters("t1", days=0)["days"]) == 7
        assert len(stats.get_counters("t1", days=999)["days"]) == 7


class TestRecentBuffer:
    def test_recent_newest_first(self):
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED, tool="a")
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED, tool="b")
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED, tool="c")
        events = stats.get_recent("t1")
        assert [e["tool"] for e in events] == ["c", "b", "a"]

    def test_recent_bounded_to_50(self):
        for i in range(80):
            stats.record(tenant_id="t1", event=stats.EVENT_CAP_VERIFIED, tool=str(i))
        events = stats.get_recent("t1", limit=100)
        assert len(events) == stats.RECENT_BUFFER_MAX
        # Newest is "79"
        assert events[0]["tool"] == "79"

    def test_recent_carries_details(self):
        stats.record(
            tenant_id="t1", event=stats.EVENT_CAP_DENIED,
            agent_id="billing-bot", user_sub="alice",
            tool="send_email", resource="alice/inbox",
            reason="role 'reader' not permitted to use tool 'send_email'",
        )
        e = stats.get_recent("t1")[0]
        assert e["event"] == stats.EVENT_CAP_DENIED
        assert e["agent_id"] == "billing-bot"
        assert e["user_sub"] == "alice"
        assert e["tool"] == "send_email"
        assert "not permitted" in e["reason"]

    def test_recent_isolated_per_tenant(self):
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED, tool="t1-only")
        stats.record(tenant_id="t2", event=stats.EVENT_CAP_MINTED, tool="t2-only")
        assert stats.get_recent("t1")[0]["tool"] == "t1-only"
        assert stats.get_recent("t2")[0]["tool"] == "t2-only"

    def test_recent_limit_param(self):
        for i in range(10):
            stats.record(tenant_id="t1", event=stats.EVENT_CAP_VERIFIED)
        assert len(stats.get_recent("t1", limit=3)) == 3
