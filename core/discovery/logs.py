"""DNS and firewall log import: who contacted which AI service.

Spec: docs/specs/ai-discovery.md, sections 4.1 and 4.2 (task 3). A log is CSV
(a header row naming the columns) or JSON (an array, or one object per line),
with a time, a client and a host. Only hosts the catalog recognizes are kept;
everything else in the log is discarded while it is read, and nothing of the
log itself is stored.

  discovery_import:{tenant}:{id}   JSON job status, 7 days

Column names are matched loosely, so common exports work as they are:
host (query, qname, domain, hostname, dest_host, sni, url), client (src,
src_ip, client_ip, source, user, username, device) and time (timestamp, ts,
date, @timestamp).
"""

from __future__ import annotations

import csv
import io
import json
import secrets
import threading
import time
from datetime import datetime
from typing import Iterable, Optional

from core.discovery import catalog as cat

MAX_BYTES = 20 * 1024 * 1024
MAX_ROWS = 2_000_000
JOB_TTL_S = 7 * 86400

HOST_COLS = ("host", "query", "qname", "query_name", "domain", "hostname", "dest_host",
             "destination", "dst_host", "sni", "server_name", "url", "fqdn")
CLIENT_COLS = ("client", "src", "src_ip", "client_ip", "source", "source_ip", "user", "username",
               "user_name", "device", "src_host", "client_name")
TIME_COLS = ("time", "timestamp", "ts", "date", "datetime", "@timestamp", "event_time")
USER_COLS = ("user", "username", "user_name")


class LogError(ValueError):
    pass


def _pick(row: dict, names: Iterable[str]) -> tuple[str, str]:
    low = {str(k).strip().lower(): (k, v) for k, v in row.items() if k is not None}
    for n in names:
        if n in low and low[n][1] not in (None, ""):
            return n, str(low[n][1]).strip()
    return "", ""


def _when(raw: str, now: int) -> int:
    if not raw:
        return now
    try:
        v = float(raw)
        if v > 1e12:                      # milliseconds
            v /= 1000.0
        return int(v) if 0 < v <= now + 300 else now
    except ValueError:
        pass
    try:
        v = int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
        return v if 0 < v <= now + 300 else now
    except ValueError:
        return now


def rows(data: bytes, fmt: str = "") -> Iterable[dict]:
    """Rows of a CSV or JSON log. Raises LogError on a log it cannot read."""
    text = data.decode("utf-8-sig", errors="replace")
    head = text.lstrip()[:1]
    fmt = fmt or ("json" if head in ("[", "{") else "csv")
    if fmt == "json":
        if head == "[":
            try:
                items = json.loads(text)
            except ValueError as e:
                raise LogError(f"not a JSON array: {e}")
            for it in items:
                if isinstance(it, dict):
                    yield it
            return
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                it = json.loads(line)
            except ValueError:
                continue
            if isinstance(it, dict):
                yield it
        return
    if fmt != "csv":
        raise LogError("format: csv or json")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not any(str(f).strip().lower() in HOST_COLS for f in reader.fieldnames):
        raise LogError(f"the CSV header names no host column (one of {', '.join(HOST_COLS)})")
    yield from reader


def observations(data: bytes, catalog: list, *, fmt: str = "", now: Optional[int] = None,
                 progress=None) -> tuple[list[dict], dict]:
    """Aggregated observations ({kind: domain, domain, subject, seen_at, count})
    for the catalog hosts in a log, and counts. Hosts outside the catalog are
    dropped as they are read."""
    now = int(now or time.time())
    agg: dict[tuple, dict] = {}
    host_cache: dict[str, bool] = {}
    counts = {"rows": 0, "matched": 0, "skipped": 0}
    for row in rows(data, fmt):
        counts["rows"] += 1
        if counts["rows"] > MAX_ROWS:
            raise LogError(f"at most {MAX_ROWS} rows per import")
        if progress and counts["rows"] % 50_000 == 0:
            progress(counts)
        _, host = _pick(row, HOST_COLS)
        host = cat.normalize_host(host)
        if not host:
            counts["skipped"] += 1
            continue
        ok = host_cache.get(host)
        if ok is None:
            ok = host_cache[host] = cat.match_domain(host, catalog) is not None
            if len(host_cache) > 200_000:
                host_cache.clear()
        if not ok:
            continue
        col, client = _pick(row, CLIENT_COLS)
        subject = {"type": "user" if col in USER_COLS else "device", "id": client[:200]} if client else None
        at = _when(_pick(row, TIME_COLS)[1], now)
        key = (host, client and f"{subject['type']}:{client}")
        a = agg.get(key)
        if a is None:
            a = agg[key] = {"kind": "domain", "domain": host, "seen_at": at, "count": 0}
            if subject:
                a["subject"] = subject
        a["count"] += 1
        a["seen_at"] = max(a["seen_at"], at)
        counts["matched"] += 1
    return list(agg.values()), counts


# ── import jobs ───────────────────────────────────────────────────────


def _job_key(tenant_id: str, job_id: str) -> str:
    return f"discovery_import:{tenant_id}:{job_id}"


def job(tenant_id: str, job_id: str) -> Optional[dict]:
    from storage.tenant_store import kv_get
    return kv_get(_job_key(tenant_id, job_id))


def _save_job(tenant_id: str, j: dict) -> None:
    from storage.tenant_store import kv_set
    kv_set(_job_key(tenant_id, j["id"]), j, ttl=JOB_TTL_S)


def start(tenant_id: str, data: bytes, *, source: str = "dns_log", fmt: str = "",
          name: str = "", actor: str = "", background: bool = True) -> dict:
    """Queue an import and return its job. The log is read in a thread; the
    request that uploaded it does not wait."""
    if len(data) > MAX_BYTES:
        raise LogError(f"at most {MAX_BYTES // (1024 * 1024)} MB per import")
    if fmt not in ("", "csv", "json"):
        raise LogError("format: csv or json")
    j = {"id": secrets.token_hex(8), "state": "queued", "source": source, "name": name[:200],
         "bytes": len(data), "by": actor[:200], "created_at": int(time.time()),
         "rows": 0, "matched": 0, "observations": 0, "accepted": 0, "pending": 0, "error": ""}
    _save_job(tenant_id, j)
    queued = dict(j)                        # the thread updates j as it goes
    if background:
        threading.Thread(target=_run, args=(tenant_id, j, data, fmt), daemon=True,
                         name=f"discovery-import-{j['id']}").start()
    else:
        _run(tenant_id, j, data, fmt)
    return queued


def _run(tenant_id: str, j: dict, data: bytes, fmt: str) -> None:
    from core.discovery import inventory

    def progress(c: dict) -> None:
        j.update(state="reading", rows=c["rows"], matched=c["matched"])
        _save_job(tenant_id, j)
    try:
        j["state"] = "reading"
        _save_job(tenant_id, j)
        obs, counts = observations(data, cat.entries(tenant_id), fmt=fmt, progress=progress)
        j.update(rows=counts["rows"], matched=counts["matched"], observations=len(obs), state="recording")
        _save_job(tenant_id, j)
        raised: list = []
        for i in range(0, len(obs), inventory.OBS_MAX):
            out = inventory.record(tenant_id, j["source"], obs[i:i + inventory.OBS_MAX])
            j["accepted"] += out["accepted"]
            j["pending"] += out["pending"]
            raised.extend(out["events"])
        j.update(state="done", finished_at=int(time.time()), new_entries=len(raised))
        _save_job(tenant_id, j)
        if raised:
            try:
                from core.discovery import notify
                notify.dispatch_sync(tenant_id, raised)
            except ImportError:
                pass
    except LogError as e:
        j.update(state="failed", error=str(e), finished_at=int(time.time()))
        _save_job(tenant_id, j)
    except Exception:
        import logging
        logging.getLogger("votal.discovery").warning("import %s failed", j["id"], exc_info=True)
        j.update(state="failed", error="the import could not be recorded; try again",
                 finished_at=int(time.time()))
        _save_job(tenant_id, j)
