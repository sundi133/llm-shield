"""Audit logging using aiosqlite for LLM Shield."""

import json
import os
from datetime import datetime
from typing import Optional

import aiosqlite

_DB_PATH = os.getenv("AUDIT_DB_PATH", "storage/audit.db")

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    agent_key TEXT,
    endpoint TEXT,
    input_text TEXT,
    action_taken TEXT NOT NULL,
    guardrails_triggered TEXT,
    latency_ms REAL,
    metadata TEXT
)
"""


class AuditLogger:
    """Async audit logger backed by SQLite via aiosqlite."""

    def __init__(self, db_path: str = _DB_PATH):
        self.db_path = db_path
        self._initialized = False

    async def init_db(self):
        """Create the audit_log table if it does not exist."""
        if self._initialized:
            return
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(_CREATE_TABLE_SQL)
            await db.commit()
        self._initialized = True

    async def log(self, entry: dict):
        """Write an audit log entry.

        Expected keys: agent_key, endpoint, input_text, action_taken,
        guardrails_triggered (list), latency_ms, metadata (dict).
        """
        await self.init_db()
        # Truncate input_text to 500 chars
        input_text = entry.get("input_text", "")
        if input_text and len(input_text) > 500:
            input_text = input_text[:500]

        guardrails_triggered = entry.get("guardrails_triggered", [])
        if isinstance(guardrails_triggered, list):
            guardrails_triggered = json.dumps(guardrails_triggered)

        metadata = entry.get("metadata", {})
        if isinstance(metadata, dict):
            metadata = json.dumps(metadata)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO audit_log
                   (timestamp, agent_key, endpoint, input_text, action_taken,
                    guardrails_triggered, latency_ms, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.utcnow().isoformat(),
                    entry.get("agent_key"),
                    entry.get("endpoint"),
                    input_text,
                    entry.get("action_taken", "pass"),
                    guardrails_triggered,
                    entry.get("latency_ms", 0.0),
                    metadata,
                ),
            )
            await db.commit()

    async def query(
        self,
        filters: Optional[dict] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list:
        """Query audit log entries with optional filters.

        Supported filter keys: agent_key, action_taken, since, until.
        """
        await self.init_db()
        conditions = []
        params = []

        if filters:
            if "agent_key" in filters:
                conditions.append("agent_key = ?")
                params.append(filters["agent_key"])
            if "action_taken" in filters:
                conditions.append("action_taken = ?")
                params.append(filters["action_taken"])
            if "since" in filters:
                conditions.append("timestamp >= ?")
                params.append(filters["since"])
            if "until" in filters:
                conditions.append("timestamp <= ?")
                params.append(filters["until"])

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        sql = f"""SELECT id, timestamp, agent_key, endpoint, input_text,
                         action_taken, guardrails_triggered, latency_ms, metadata
                  FROM audit_log {where_clause}
                  ORDER BY id DESC LIMIT ? OFFSET ?"""
        params.extend([limit, offset])

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                entry = dict(row)
                # Parse JSON fields
                if entry.get("guardrails_triggered"):
                    try:
                        entry["guardrails_triggered"] = json.loads(
                            entry["guardrails_triggered"]
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass
                if entry.get("metadata"):
                    try:
                        entry["metadata"] = json.loads(entry["metadata"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                results.append(entry)
            return results

    async def get_stats(self, since: Optional[datetime] = None) -> dict:
        """Get aggregated statistics from the audit log.

        Returns dict with: total_requests, block_rate, top_guardrails, avg_latency.
        """
        await self.init_db()
        params = []
        where_clause = ""
        if since:
            where_clause = "WHERE timestamp >= ?"
            params.append(since.isoformat())

        async with aiosqlite.connect(self.db_path) as db:
            # Total requests
            cursor = await db.execute(
                f"SELECT COUNT(*) FROM audit_log {where_clause}", params
            )
            total = (await cursor.fetchone())[0]

            # Block count
            block_params = list(params)
            block_where = where_clause
            if block_where:
                block_where += " AND action_taken = 'block'"
            else:
                block_where = "WHERE action_taken = 'block'"
            cursor = await db.execute(
                f"SELECT COUNT(*) FROM audit_log {block_where}", block_params
            )
            blocked = (await cursor.fetchone())[0]

            # Average latency
            cursor = await db.execute(
                f"SELECT AVG(latency_ms) FROM audit_log {where_clause}", params
            )
            avg_latency = (await cursor.fetchone())[0] or 0.0

            # Top guardrails triggered
            cursor = await db.execute(
                f"SELECT guardrails_triggered FROM audit_log {where_clause}", params
            )
            rows = await cursor.fetchall()
            guardrail_counts: dict[str, int] = {}
            for row in rows:
                raw = row[0]
                if raw:
                    try:
                        triggered = json.loads(raw)
                        for g in triggered:
                            guardrail_counts[g] = guardrail_counts.get(g, 0) + 1
                    except (json.JSONDecodeError, TypeError):
                        pass

            # Sort by count descending, take top 10
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
                "avg_latency_ms": round(avg_latency, 2),
            }


# Module-level singleton
audit_logger = AuditLogger()
