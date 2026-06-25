"""Task 1 of the usage-retention spec: per-(agent, tool) last-used tracking.

storage/agent_auth_stats records a last-used timestamp on positive-use events
(cap_minted / cap_verified) so governance can compute "unused N days" hygiene
signals — without the bounded 50-event recent buffer.
"""
import time

import storage.agent_auth_stats as stats


def setup_function():
    stats.clear_for_tests()


def test_records_last_seen_on_usage_events():
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_MINTED,
                 agent_id="billing", tool="get_invoice")
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_VERIFIED,
                 agent_id="billing", tool="send_email")
    ls = stats.get_last_seen("acme")
    assert ("billing", "get_invoice") in ls
    assert ("billing", "send_email") in ls
    assert ls[("billing", "get_invoice")] <= int(time.time())


def test_non_usage_events_do_not_record():
    # denials / replays / invalids are not "use"
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_DENIED,
                 agent_id="billing", tool="wire_transfer")
    stats.record(tenant_id="acme", event=stats.EVENT_TOKEN_ISSUED, agent_id="billing")
    assert stats.get_last_seen("acme") == {}


def test_missing_agent_or_tool_is_skipped():
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_MINTED, agent_id="billing")  # no tool
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_MINTED, tool="get_invoice")  # no agent
    assert stats.get_last_seen("acme") == {}


def test_last_seen_updates_to_latest_timestamp(monkeypatch):
    t = [1000]
    monkeypatch.setattr(stats.time, "time", lambda: t[0])
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_MINTED, agent_id="b", tool="x")
    t[0] = 5000
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_VERIFIED, agent_id="b", tool="x")
    assert stats.get_last_seen("acme")[("b", "x")] == 5000


def test_tenant_isolation():
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_MINTED, agent_id="b", tool="x")
    stats.record(tenant_id="other", event=stats.EVENT_CAP_MINTED, agent_id="z", tool="y")
    assert set(stats.get_last_seen("acme")) == {("b", "x")}
    assert set(stats.get_last_seen("other")) == {("z", "y")}


def test_separator_safe_split():
    # agent/tool names with slashes etc. round-trip cleanly
    stats.record(tenant_id="acme", event=stats.EVENT_CAP_MINTED,
                 agent_id="oauth:dev@x.com", tool="read:account")
    assert ("oauth:dev@x.com", "read:account") in stats.get_last_seen("acme")
