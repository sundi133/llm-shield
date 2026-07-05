"""Guardrail effectiveness metrics — track pass/block/warn rates per guardrail.

Records every guardrail result into daily Redis counters. Provides
aggregate queries for effectiveness scoring, trend analysis, and
compliance evidence packs.

Redis key pattern:
    guardrail:metrics:{tenant_id}:{guardrail_name}:{YYYY-MM-DD}

Each key is a Redis hash with fields:
    total, passed, blocked, warned, logged
    latency_sum_ms, latency_count (for avg calculation)
    TTL: 90 days (auto-cleanup)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("votal.guardrail_metrics")

_METRICS_TTL_DAYS = 90
_METRICS_KEY_PREFIX = "guardrail:metrics"


def _key(tenant_id: str, guardrail_name: str, date_str: str) -> str:
    return f"{_METRICS_KEY_PREFIX}:{tenant_id}:{guardrail_name}:{date_str}"


def _get_redis():
    from storage.tenant_store import _get_redis as _gr
    return _gr()


# Max hashes per pipeline round-trip. Keeps a single request bounded while
# still collapsing hundreds of per-day reads into a few calls.
_BATCH_CHUNK = 200


def _decode_hash(data: dict) -> dict:
    """Normalize a hash dict to str keys/values (redis-py may return bytes)."""
    if data and isinstance(next(iter(data.keys())), bytes):
        return {
            k.decode(): (v.decode() if isinstance(v, bytes) else v)
            for k, v in data.items()
        }
    return data or {}


def _batch_hgetall(r, keys: list[str]) -> dict:
    """Fetch many hashes with as few round-trips as possible.

    Uses the client's pipeline when available — ``.execute()`` on redis-py,
    ``.exec()`` on the Upstash REST client — and **falls back to sequential
    ``hgetall`` on ANY deviation** (no pipeline support, wrong result shape,
    or an error). The fallback is byte-for-byte the prior behavior, so values
    are always correct; only latency improves when pipelining is available.

    This is why correctness can't regress: the in-memory FakeRedis used in
    tests raises on ``pipeline()`` and simply takes the sequential path.
    """
    out: dict = {}
    for start in range(0, len(keys), _BATCH_CHUNK):
        chunk = keys[start:start + _BATCH_CHUNK]
        out.update(_hgetall_chunk(r, chunk))
    return out


def _hgetall_chunk(r, chunk: list[str]) -> dict:
    if not chunk:
        return {}
    try:
        pipe = r.pipeline()
        for k in chunk:
            pipe.hgetall(k)
        # IMPORTANT ordering: the upstash_redis Pipeline exposes BOTH .exec()
        # (run the batch -> list) and .execute(command) (queue one command ->
        # Pipeline). Calling .execute() with no args raises, so prefer .exec().
        # redis-py has only .execute() and no .exec(), so it falls through.
        if hasattr(pipe, "exec"):          # upstash_redis REST client
            results = pipe.exec()
        elif hasattr(pipe, "execute"):     # redis-py
            results = pipe.execute()
        else:
            raise AttributeError("pipeline has no executor")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise ValueError("unexpected pipeline result shape")
        return {k: (results[i] or {}) for i, k in enumerate(chunk)}
    except Exception:
        # Fallback: identical to the original per-key sequential reads.
        out: dict = {}
        for k in chunk:
            try:
                out[k] = r.hgetall(k) or {}
            except Exception:
                out[k] = {}
        return out


def _compute_effectiveness(guardrail_name: str, days: int, dated_data: list) -> dict:
    """Aggregate per-day hashes into the effectiveness summary.

    ``dated_data`` is a list of ``(date_str, raw_hash)`` in i=0..days-1 order
    (today first), exactly as the prior per-day loop produced. This is the
    single source of truth for the math so the single-guardrail and all-guardrail
    paths return identical values.
    """
    totals = {"total": 0, "passed": 0, "blocked": 0, "warned": 0, "logged": 0}
    latency_sum = 0.0
    latency_count = 0
    daily = []

    for date, raw in dated_data:
        data = _decode_hash(raw)
        if not data:
            continue
        day_total = int(data.get("total", 0))
        day_passed = int(data.get("passed", 0))
        day_blocked = int(data.get("blocked", 0))
        day_warned = int(data.get("warned", 0))
        day_logged = int(data.get("logged", 0))

        totals["total"] += day_total
        totals["passed"] += day_passed
        totals["blocked"] += day_blocked
        totals["warned"] += day_warned
        totals["logged"] += day_logged

        latency_sum += float(data.get("latency_sum_ms", 0))
        latency_count += int(data.get("latency_count", 0))

        daily.append({
            "date": date,
            "total": day_total,
            "passed": day_passed,
            "blocked": day_blocked,
            "warned": day_warned,
            "logged": day_logged,
        })

    daily.reverse()  # oldest first

    t = totals["total"] or 1
    avg_lat = latency_sum / latency_count if latency_count else 0.0

    trend = "stable"
    if len(daily) >= 14:
        recent = sum(d["blocked"] for d in daily[-7:])
        previous = sum(d["blocked"] for d in daily[-14:-7])
        if recent > previous * 1.2:
            trend = "up"
        elif recent < previous * 0.8:
            trend = "down"

    return {
        "guardrail": guardrail_name,
        "days": days,
        **totals,
        "pass_rate": round(totals["passed"] / t, 4),
        "block_rate": round(totals["blocked"] / t, 4),
        "avg_latency_ms": round(avg_lat, 2),
        "daily": daily,
        "trend": trend,
    }


def record_result(
    tenant_id: str,
    guardrail_name: str,
    passed: bool,
    action: str,
    latency_ms: float = 0.0,
) -> None:
    """Record a single guardrail check result. Fire-and-forget."""
    if not tenant_id or not guardrail_name:
        return

    r = _get_redis()
    if not r:
        return

    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = _key(tenant_id, guardrail_name, today)

    # Direct calls (not a pipeline). The Upstash REST client used in production
    # has a different pipeline API than redis-py (no transaction= kwarg, and it
    # executes via .exec() not .execute()), so a pipeline here raised and was
    # silently swallowed — metrics never recorded while audit_log (direct calls)
    # worked. Mirror audit_log and call directly; works on both clients.
    try:
        r.hincrby(key, "total", 1)
        if passed:
            r.hincrby(key, "passed", 1)
        elif action == "block":
            r.hincrby(key, "blocked", 1)
        elif action == "warn":
            r.hincrby(key, "warned", 1)
        else:
            r.hincrby(key, "logged", 1)
        if latency_ms > 0:
            r.hincrbyfloat(key, "latency_sum_ms", latency_ms)
            r.hincrby(key, "latency_count", 1)
        r.expire(key, _METRICS_TTL_DAYS * 86400)
    except Exception as e:
        logger.debug(f"guardrail_metrics record failed: {e}")


def record_results_batch(tenant_id: str, guardrail_results: list) -> None:
    """Record a batch of guardrail results from a pipeline run."""
    for gr in guardrail_results:
        name = gr.get("guardrail") or gr.get("guardrail_name") or ""
        if not name:
            continue
        record_result(
            tenant_id=tenant_id,
            guardrail_name=name,
            passed=gr.get("passed", True),
            action=gr.get("action", "pass"),
            latency_ms=gr.get("latency_ms", 0.0),
        )


def get_effectiveness(
    tenant_id: str,
    guardrail_name: str,
    days: int = 30,
) -> dict:
    """Get effectiveness metrics for a single guardrail over N days.

    Returns:
        {
            "guardrail": str,
            "days": int,
            "total": int,
            "passed": int, "blocked": int, "warned": int, "logged": int,
            "pass_rate": float,  # 0.0 - 1.0
            "block_rate": float,
            "avg_latency_ms": float,
            "daily": [{"date": str, "total": int, "blocked": int, ...}, ...],
            "trend": "up" | "down" | "stable",
        }
    """
    r = _get_redis()
    if not r:
        return {"guardrail": guardrail_name, "days": days, "total": 0,
                "passed": 0, "blocked": 0, "warned": 0, "logged": 0,
                "pass_rate": 0.0, "block_rate": 0.0, "avg_latency_ms": 0.0,
                "daily": [], "trend": "stable"}

    dates = [
        (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range(days)
    ]
    keys = [_key(tenant_id, guardrail_name, d) for d in dates]
    fetched = _batch_hgetall(r, keys)
    dated_data = [(dates[i], fetched.get(keys[i], {})) for i in range(days)]
    return _compute_effectiveness(guardrail_name, days, dated_data)


# ── DLP-style dashboard aggregation (read-only, admin plane) ──────────────
#
# Severity is DERIVED at query time, never stored, so the guard path stays
# untouched and the mapping can be tuned without a migration. A blocked event
# from one of these guardrails is Critical; any other block is High; warns are
# Medium; log-only triggers are Low.
_CRITICAL_GUARDRAILS = {
    "adversarial_detection",
    "system_prompt_leak",
    "custom_policy_input",
}
_CRITICAL_PREFIXES = ("pii",)

# Upper bound on audit entries parsed per dashboard request. The audit ZSET
# can hold up to AUDIT_MAX_ENTRIES (1M); reading it all would stall the admin
# plane. The response carries scanned/truncated so the UI can say "based on
# the most recent N events" instead of silently under-counting.
_DASHBOARD_MAX_SCAN = 20_000


def _is_critical_guardrail(name: str) -> bool:
    return name in _CRITICAL_GUARDRAILS or name.startswith(_CRITICAL_PREFIXES)


def _event_severity(action: str, triggered: list) -> str:
    if action == "block":
        if any(_is_critical_guardrail(str(t)) for t in triggered):
            return "critical"
        return "high"
    if action == "warn":
        return "medium"
    return "low"


def _issue_severity(name: str, blocked: int, warned: int) -> str:
    if blocked and _is_critical_guardrail(name):
        return "critical"
    if blocked:
        return "high"
    if warned:
        return "medium"
    return "low"


def _empty_dashboard(tenant_id: str, days: int) -> dict:
    return {
        "tenant_id": tenant_id,
        "days": days,
        "scanned": 0,
        "truncated": False,
        "summary": {
            "blocked": 0, "warned": 0, "total": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        },
        "daily": [],
        "top_issues": [],
        "top_users": [],
        "top_devices": [],
        "recent_blocked": [],
    }


def _fetch_audit_window(r, tenant_id: str, days: int, max_scan: int) -> list:
    """Most-recent-first raw audit JSON strings within the window, bounded."""
    key = f"audit:{tenant_id}"
    min_score = (datetime.utcnow() - timedelta(days=days)).timestamp()
    try:
        try:
            # Upstash REST client signature
            return r.zrevrangebyscore(key, "+inf", min_score, offset=0, count=max_scan) or []
        except TypeError:
            # redis-py signature
            return r.zrevrangebyscore(key, "+inf", min_score, start=0, num=max_scan) or []
    except Exception as e:
        logger.debug(f"dashboard audit read failed: {e}")
        return []


def _daily_totals(tenant_id: str, days: int) -> list[dict]:
    """Per-day blocked/warned/passed guardrail-check counts across all
    guardrails, oldest first. Reuses the effectiveness store, so the numbers
    count guardrail checks (a request may run several)."""
    summary_rows = get_all_guardrails_summary(tenant_id, days=days)
    if not summary_rows:
        return []
    # get_all_guardrails_summary drops the daily series, so re-aggregate from
    # per-guardrail effectiveness. One batched fetch per guardrail set.
    dates = [
        (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range(days)
    ]
    totals = {d: {"date": d, "blocked": 0, "warned": 0, "passed": 0, "total": 0}
              for d in dates}
    r = _get_redis()
    if not r:
        return []
    names = [row["guardrail"] for row in summary_rows]
    keys_by_name = {n: [_key(tenant_id, n, d) for d in dates] for n in names}
    all_keys = [k for ks in keys_by_name.values() for k in ks]
    fetched = _batch_hgetall(r, all_keys)
    for n in names:
        for i, d in enumerate(dates):
            data = _decode_hash(fetched.get(keys_by_name[n][i], {}))
            if not data:
                continue
            totals[d]["blocked"] += int(data.get("blocked", 0))
            totals[d]["warned"] += int(data.get("warned", 0))
            totals[d]["passed"] += int(data.get("passed", 0))
            totals[d]["total"] += int(data.get("total", 0))
    return [totals[d] for d in reversed(dates)]  # oldest first


def get_blocked_dashboard(
    tenant_id: str,
    days: int = 30,
    max_scan: int = _DASHBOARD_MAX_SCAN,
) -> dict:
    """DLP-style dashboard: severity split, daily trend, top issues, top
    users/devices, and recent blocked events. Read-only aggregation over the
    existing guardrail-metrics hashes and audit ZSET; nothing is written.
    """
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 30
    days = max(1, min(days, 90))
    out = _empty_dashboard(tenant_id, days)
    r = _get_redis()
    if not r or not tenant_id:
        return out

    out["daily"] = _daily_totals(tenant_id, days)

    raw_entries = _fetch_audit_window(r, tenant_id, days, max_scan)
    out["scanned"] = len(raw_entries)
    out["truncated"] = len(raw_entries) >= max_scan

    by_severity = out["summary"]["by_severity"]
    issue_counts: dict = {}     # guardrail -> {blocked, warned}
    user_counts: dict = {}      # agent_key -> {blocked, warned}
    device_counts: dict = {}    # device_id -> {blocked, warned}
    recent_blocked: list = []

    for raw in raw_entries:
        try:
            entry = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(entry, dict):
            continue

        action = entry.get("action_taken", "pass")
        triggered = entry.get("guardrails_triggered") or []
        if action not in ("block", "warn") and not triggered:
            continue  # clean pass: not an issue

        metadata = entry.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        agent = entry.get("agent_key") or "(unknown)"
        device = metadata.get("device_id") or "(unknown)"

        sev = _event_severity(action, triggered)
        by_severity[sev] += 1
        out["summary"]["total"] += 1
        if action == "block":
            out["summary"]["blocked"] += 1
        elif action == "warn":
            out["summary"]["warned"] += 1

        bucket = "blocked" if action == "block" else "warned"
        for name in triggered:
            c = issue_counts.setdefault(str(name), {"blocked": 0, "warned": 0})
            c[bucket] += 1
        u = user_counts.setdefault(agent, {"blocked": 0, "warned": 0})
        u[bucket] += 1
        d = device_counts.setdefault(device, {"blocked": 0, "warned": 0})
        d[bucket] += 1

        if action == "block" and len(recent_blocked) < 10:
            recent_blocked.append({
                "ts": entry.get("ts", 0),
                "timestamp": entry.get("timestamp", ""),
                "agent_key": agent,
                "device_id": device,
                "guardrails": [str(t) for t in triggered],
                "message": str(entry.get("input_text", ""))[:120],
            })

    def _top10(counts: dict, label: str) -> list[dict]:
        rows = [{label: k, **v} for k, v in counts.items()]
        rows.sort(key=lambda x: (x["blocked"], x["warned"]), reverse=True)
        return rows[:10]

    out["top_issues"] = [
        {"guardrail": row["guardrail"],
         "count": row["blocked"] + row["warned"],
         "blocked": row["blocked"], "warned": row["warned"],
         "severity": _issue_severity(row["guardrail"], row["blocked"], row["warned"])}
        for row in _top10(issue_counts, "guardrail")
    ]
    out["top_users"] = _top10(user_counts, "agent_key")
    out["top_devices"] = _top10(device_counts, "device_id")
    out["recent_blocked"] = recent_blocked
    return out


def get_all_guardrails_summary(
    tenant_id: str,
    days: int = 30,
) -> list[dict]:
    """Get summary metrics for all guardrails that have recorded data.

    Returns list sorted by block count (highest first).
    """
    r = _get_redis()
    if not r:
        return []

    # Scan for all guardrail metric keys for this tenant
    pattern = f"{_METRICS_KEY_PREFIX}:{tenant_id}:*"
    guardrail_names = set()

    try:
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor=cursor, match=pattern, count=200)
            for key in keys:
                k = key.decode() if isinstance(key, bytes) else key
                # Key format: guardrail:metrics:{tenant}:{name}:{date}
                parts = k.split(":")
                if len(parts) >= 5:
                    # name might contain colons, date is always last
                    name = ":".join(parts[3:-1])
                    guardrail_names.add(name)
            if cursor == 0:
                break
    except Exception as e:
        logger.debug(f"guardrail_metrics scan failed: {e}")
        return []

    if not guardrail_names:
        return []

    # Build every (guardrail, day) key once and fetch them in a single batched
    # read instead of guardrails x days sequential round-trips. The previous
    # per-guardrail get_effectiveness loop did one hgetall per day per guardrail
    # (e.g. 22 x 30 = ~660 calls), which exceeded the upstream proxy timeout for
    # tenants with many guardrails. Values are unchanged — same _compute path.
    dates = [
        (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range(days)
    ]
    keys_by_name = {
        name: [_key(tenant_id, name, d) for d in dates]
        for name in guardrail_names
    }
    all_keys = [k for ks in keys_by_name.values() for k in ks]
    fetched = _batch_hgetall(r, all_keys)

    results = []
    for name in guardrail_names:
        ks = keys_by_name[name]
        dated_data = [(dates[i], fetched.get(ks[i], {})) for i in range(days)]
        eff = _compute_effectiveness(name, days, dated_data)
        if eff["total"] > 0:
            results.append({
                "guardrail": name,
                "total": eff["total"],
                "passed": eff["passed"],
                "blocked": eff["blocked"],
                "warned": eff["warned"],
                "pass_rate": eff["pass_rate"],
                "block_rate": eff["block_rate"],
                "avg_latency_ms": eff["avg_latency_ms"],
                "trend": eff["trend"],
            })

    results.sort(key=lambda x: x["blocked"], reverse=True)
    return results
