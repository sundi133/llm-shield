"""Audit logging backed by Redis for LLM Shield.

Stores audit entries in a Redis sorted set (scored by timestamp) so that
both the admin app and the Shield server share the same telemetry data.

Redis keys:
    audit:{tenant_id}  → ZSET of JSON entries, scored by unix timestamp
    audit:global        → ZSET for entries without a tenant_id
"""

import json
import os
import time
from datetime import datetime
from typing import Optional


# Max entries to keep per tenant (rolling window)
_MAX_ENTRIES = int(os.getenv("AUDIT_MAX_ENTRIES", "5000"))
# TTL for audit entries in seconds (default 7 days)
_AUDIT_TTL = int(os.getenv("AUDIT_TTL_SECONDS", str(7 * 86400)))


def _get_redis():
    """Get the shared Redis connection from tenant_store."""
    try:
        from storage.tenant_store import _get_redis as get_redis
        return get_redis()
    except Exception:
        return None


class AuditLogger:
    """Async-compatible audit logger backed by Redis."""

    def _redis_key(self, tenant_id: str | None) -> str:
        if tenant_id:
            return f"audit:{tenant_id}"
        return "audit:global"

    async def log(self, entry: dict):
        """Write an audit log entry to Redis.

        Expected keys: agent_key, endpoint, input_text, action_taken,
        guardrails_triggered (list), latency_ms, metadata (dict).
        """
        r = _get_redis()
        if not r:
            return

        tenant_id = None
        metadata = entry.get("metadata", {})
        if isinstance(metadata, dict):
            tenant_id = metadata.get("tenant_id")

        # Truncate input_text
        input_text = entry.get("input_text", "")
        if input_text and len(input_text) > 500:
            input_text = input_text[:500]

        guardrails_triggered = entry.get("guardrails_triggered", [])

        ts = time.time()
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "ts": ts,
            "agent_key": entry.get("agent_key", ""),
            "endpoint": entry.get("endpoint", ""),
            "input_text": input_text,
            "action_taken": entry.get("action_taken", "pass"),
            "guardrails_triggered": guardrails_triggered,
            "latency_ms": entry.get("latency_ms", 0.0),
            "metadata": metadata,
        }

        key = self._redis_key(tenant_id)
        try:
            r.zadd(key, {json.dumps(record): ts})
            # Trim to keep only the most recent entries
            count = r.zcard(key)
            if count and count > _MAX_ENTRIES:
                r.zremrangebyrank(key, 0, count - _MAX_ENTRIES - 1)
            # Set TTL on the key if not already set
            if r.ttl(key) == -1:
                r.expire(key, _AUDIT_TTL)
        except Exception:
            pass

    async def query(
        self,
        filters: Optional[dict] = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list:
        """Query audit log entries with optional filters."""
        r = _get_redis()
        if not r:
            return []

        key = self._redis_key(tenant_id)
        try:
            # Get entries in reverse order (newest first)
            raw_entries = r.zrevrange(key, offset, offset + limit - 1)
            if not raw_entries:
                return []

            results = []
            for raw in raw_entries:
                try:
                    entry = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue

                # Apply filters
                if filters:
                    if "agent_key" in filters and entry.get("agent_key") != filters["agent_key"]:
                        continue
                    if "action_taken" in filters and entry.get("action_taken") != filters["action_taken"]:
                        continue
                    if "since" in filters and entry.get("timestamp", "") < filters["since"]:
                        continue
                    if "until" in filters and entry.get("timestamp", "") > filters["until"]:
                        continue

                results.append(entry)

            return results
        except Exception:
            return []

    async def get_stats(self, since: Optional[datetime] = None, tenant_id: str | None = None) -> dict:
        """Get aggregated statistics from the audit log."""
        r = _get_redis()
        if not r:
            return {
                "total_requests": 0, "block_rate": 0.0, "blocked_count": 0,
                "top_guardrails": [], "avg_latency_ms": 0.0,
            }

        key = self._redis_key(tenant_id)
        try:
            if since:
                min_score = since.timestamp()
                raw_entries = r.zrangebyscore(key, min_score, "+inf")
            else:
                raw_entries = r.zrange(key, 0, -1)

            if not raw_entries:
                return {
                    "total_requests": 0, "block_rate": 0.0, "blocked_count": 0,
                    "top_guardrails": [], "avg_latency_ms": 0.0,
                }

            total = 0
            blocked = 0
            latency_sum = 0.0
            guardrail_counts: dict[str, int] = {}

            for raw in raw_entries:
                try:
                    entry = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue

                total += 1
                if entry.get("action_taken") == "block":
                    blocked += 1
                latency_sum += entry.get("latency_ms", 0.0)

                triggered = entry.get("guardrails_triggered", [])
                if isinstance(triggered, list):
                    for g in triggered:
                        guardrail_counts[g] = guardrail_counts.get(g, 0) + 1

            top_guardrails = sorted(
                guardrail_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]

            return {
                "total_requests": total,
                "block_rate": round(blocked / total, 4) if total > 0 else 0.0,
                "blocked_count": blocked,
                "top_guardrails": [
                    {"name": name, "count": count} for name, count in top_guardrails
                ],
                "avg_latency_ms": round(latency_sum / total, 2) if total > 0 else 0.0,
            }
        except Exception:
            return {
                "total_requests": 0, "block_rate": 0.0, "blocked_count": 0,
                "top_guardrails": [], "avg_latency_ms": 0.0,
            }


# Module-level singleton
audit_logger = AuditLogger()
