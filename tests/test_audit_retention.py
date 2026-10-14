"""Regression tests for audit-log retention.

The old retention put a 30-day TTL on the WHOLE per-tenant ZSET and set it only
once (when ttl == -1), never refreshing it. So the entire key — every message —
expired ~30 days after its FIRST write regardless of activity, wiping all
audit/telemetry at once. These tests pin the corrected behavior:

  * retention ages out only entries older than the TTL window (by score),
  * an active tenant never loses its recent entries,
  * the key TTL is refreshed on every write (sliding backstop), so it never
    fires while the tenant is writing.
"""

import time
from unittest.mock import patch

from storage.audit_log import AuditLogger
import storage.audit_log as audit_log


class FakeRedis:
    """Minimal ZSET + TTL model sufficient for AuditLogger._write_sync."""

    def __init__(self):
        self.z: dict[str, dict[str, float]] = {}
        # -2 => no key, -1 => key but no ttl, >=0 => seconds remaining
        self.ttls: dict[str, int] = {}

    def zadd(self, key, mapping):
        d = self.z.setdefault(key, {})
        d.update(mapping)
        # New key with no explicit TTL yet.
        self.ttls.setdefault(key, -1)

    def zremrangebyscore(self, key, min_score, max_score):
        d = self.z.get(key, {})
        removed = [m for m, s in d.items() if min_score <= s <= max_score]
        for m in removed:
            del d[m]
        return len(removed)

    def zremrangebyrank(self, key, start, stop):
        d = self.z.get(key, {})
        ordered = sorted(d.items(), key=lambda kv: kv[1])
        n = len(ordered)
        lo = start if start >= 0 else n + start
        hi = stop if stop >= 0 else n + stop
        for m, _ in ordered[lo : hi + 1]:
            del d[m]

    def zcard(self, key):
        return len(self.z.get(key, {}))

    def ttl(self, key):
        if key not in self.z:
            return -2
        return self.ttls.get(key, -1)

    def expire(self, key, seconds):
        self.ttls[key] = int(seconds)

    def zrevrange(self, key, start, stop):
        d = self.z.get(key, {})
        ordered = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
        n = len(ordered)
        hi = stop if stop >= 0 else n + stop
        return [m for m, _ in ordered[start : hi + 1]]


def _entry(text: str, tenant: str = "t1"):
    return {
        "input_text": text,
        "endpoint": "/guardrails/input",
        "action_taken": "pass",
        "metadata": {"tenant_id": tenant},
    }


def test_key_ttl_refreshed_on_every_write():
    """The sliding backstop: every write (re)sets the key TTL, so it never
    fires while the tenant is active. The old bug set it only when ttl==-1."""
    r = FakeRedis()
    logger = AuditLogger()
    with patch.object(audit_log, "_get_redis", return_value=r):
        logger._write_sync(_entry("one"))
        # Simulate the key having aged partway through its TTL window.
        r.ttls["audit:t1"] = 5
        logger._write_sync(_entry("two"))
    # TTL was refreshed back to the full window, not left at 5.
    assert r.ttls["audit:t1"] == audit_log._AUDIT_TTL


def test_recent_entries_survive_retention():
    """An active tenant keeps every entry inside the TTL window."""
    r = FakeRedis()
    logger = AuditLogger()
    with patch.object(audit_log, "_get_redis", return_value=r):
        for i in range(20):
            logger._write_sync(_entry(f"msg-{i}"))
    assert r.zcard("audit:t1") == 20


def test_only_entries_older_than_window_are_dropped():
    """Entries older than the TTL window age out; newer ones stay — instead of
    the whole key (all messages) disappearing at once."""
    r = FakeRedis()
    logger = AuditLogger()
    now = time.time()
    # Seed one ancient entry (older than the retention window) directly.
    r.z["audit:t1"] = {'{"input_text": "ancient"}': now - audit_log._AUDIT_TTL - 3600}
    r.ttls["audit:t1"] = -1
    with patch.object(audit_log, "_get_redis", return_value=r):
        logger._write_sync(_entry("fresh"))
    members = r.zrevrange("audit:t1", 0, -1)
    assert any("fresh" in m for m in members)
    assert not any("ancient" in m for m in members)
