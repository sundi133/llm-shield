"""Prompt exception requests: a user whose prompt was blocked asks for a review.

Spec: docs/specs/prompt-exception-requests.md. This module is the store and its
rules; nothing here runs on the guard path. Routes: api/routes_exceptions.py.

  prompt_exc_settings:{tenant}            the tenant's settings
  prompt_exc:{tenant}:{request_id}        one request, with the prompt text
  prompt_exc_idx:{tenant}                 sorted set of request ids by time (all)
  prompt_exc_st:{tenant}:{status}         sorted set of ids in one status, score expires_at
  prompt_exc_pol:{tenant}:{policy_key}    sorted set of pending ids one policy blocked
  prompt_exc_pols:{tenant}                hash policy_key -> the policy's names
  prompt_exc_v2:{tenant}                  marker: the status indexes are built
  prompt_exc_user:{tenant}:{user_hash}    this user's open request ids
  prompt_exc_fp:{tenant}                  hash of per-policy counters

The tenant is always the caller's, from the API key. A request id is random and
is only ever looked up under its tenant's prefix.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
import unicodedata
from typing import Any, Optional

from core.policy_mode import BLOCKING_ACTIONS

PROMPT_STORE_MAX = 4000
REASON_MAX = 500
MESSAGE_MAX = 300
INDEX_MAX = 1000
KEEP_AFTER_EXPIRY_S = 7 * 86400
STATUSES = ("pending", "approved", "denied", "expired", "used")

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": False,
    # Guardrails whose blocks cannot be requested or waived (hard rules).
    "non_appealable": [],
    "request_ttl_s": 86400,
    "grant_ttl_s": 900,
    "max_pending_per_user": 3,
    # Second opinion by a larger model (task 6). Stored, not acted on yet.
    "auto_review": False,
}
_BOUNDS = {"request_ttl_s": (300, 7 * 86400), "grant_ttl_s": (60, 3600),
           "max_pending_per_user": (1, 20)}
_ID = re.compile(r"^pex_[0-9a-f]{20}$")

#: Used when no Redis is configured (dev and tests), like tenant_store's.
_mem_index: dict[str, dict[str, float]] = {}
_mem_counts: dict[str, dict[str, int]] = {}


class ExceptionError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


# ── settings ─────────────────────────────────────────────────────────

def validate_settings(raw: Any) -> dict:
    """The settings, with defaults. Raises ExceptionError(422) naming every problem."""
    if not isinstance(raw, dict):
        raise ExceptionError(422, "invalid_settings", "settings: an object")
    errors = [f"{k}: unknown setting" for k in raw if k not in DEFAULT_SETTINGS]
    out = {**DEFAULT_SETTINGS, **{k: v for k, v in raw.items() if k in DEFAULT_SETTINGS}}
    for k in ("enabled", "auto_review"):
        if not isinstance(out[k], bool):
            errors.append(f"{k}: true or false")
    for k, (lo, hi) in _BOUNDS.items():
        v = out[k]
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            errors.append(f"{k}: a whole number from {lo} to {hi}")
    names = out["non_appealable"]
    if not isinstance(names, list) or len(names) > 50 or not all(
            isinstance(n, str) and re.match(r"^[a-z0-9_]{1,64}$", n) for n in names):
        errors.append("non_appealable: up to 50 guardrail names (lowercase, digits, _)")
    else:
        out["non_appealable"] = sorted(set(names))
    if errors:
        raise ExceptionError(422, "invalid_settings", "invalid exception settings", errors=errors)
    return out


def get_settings(tenant_id: str) -> dict:
    from storage.tenant_store import kv_get
    stored = kv_get(f"prompt_exc_settings:{tenant_id}")
    try:
        return validate_settings(stored if isinstance(stored, dict) else {})
    except ExceptionError:
        # A stored value that no longer validates must not turn the feature on.
        return dict(DEFAULT_SETTINGS)


def save_settings(tenant_id: str, raw: Any) -> dict:
    from storage.tenant_store import kv_set
    settings = validate_settings(raw)
    kv_set(f"prompt_exc_settings:{tenant_id}", settings)
    return settings


# ── hashing ──────────────────────────────────────────────────────────

def prompt_sha256(prompt: str) -> str:
    """The prompt's identity: NFC-normalised, outer whitespace trimmed. A grant
    is bound to this, so the user must resend the same text."""
    return hashlib.sha256(unicodedata.normalize("NFC", prompt).strip().encode()).hexdigest()


def _user_hash(user_id: str) -> str:
    return hashlib.sha256(user_id.encode()).hexdigest()[:24]


def blocking_results(result: dict, cap: int = 20) -> list[dict]:
    """What blocked the prompt, from a /guardrails/input result: the failed
    guardrails whose action stops the request. Warnings are not listed."""
    out = []
    for gr in result.get("guardrail_results") or ():
        if not isinstance(gr, dict) or gr.get("passed", True) \
                or gr.get("action") not in BLOCKING_ACTIONS:
            continue
        details = gr.get("details") if isinstance(gr.get("details"), dict) else {}
        primary = details.get("primary_violation") \
            if isinstance(details.get("primary_violation"), dict) else {}
        out.append({
            "guardrail": str(gr.get("guardrail") or "")[:64],
            "policy": str(primary.get("policy_name") or details.get("policy_name") or "")[:200],
            "policy_id": str(primary.get("policy_id") or details.get("policy_id") or "")[:100],
            "message": str(gr.get("message") or "")[:MESSAGE_MAX],
        })
    return out[:cap]


# ── index and counters (Redis sorted set / hash, or memory) ───────────

def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _decode(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _index_add(tenant_id: str, request_id: str, at: float) -> None:
    key, r = f"prompt_exc_idx:{tenant_id}", _redis()
    if r is None:
        idx = _mem_index.setdefault(key, {})
        idx[request_id] = at
        for old in sorted(idx, key=idx.get)[:-INDEX_MAX]:
            idx.pop(old, None)
        return
    r.zadd(key, {request_id: at})
    count = r.zcard(key)
    if count and int(count) > INDEX_MAX:
        r.zremrangebyrank(key, 0, int(count) - INDEX_MAX - 1)


def _index_ids(tenant_id: str, limit: int) -> list[str]:
    """Newest first."""
    key, r = f"prompt_exc_idx:{tenant_id}", _redis()
    if r is None:
        idx = _mem_index.get(key, {})
        return sorted(idx, key=idx.get, reverse=True)[:limit]
    return [_decode(i) for i in (r.zrevrange(key, 0, limit - 1) or [])]


def count(tenant_id: str, blocked_by: list[dict], field: str) -> None:
    """Add one to `field` (requested | approved | false_positive) for each
    policy that blocked the prompt. Never raises: counters are not the record."""
    key = f"prompt_exc_fp:{tenant_id}"
    try:
        r = _redis()
        for b in blocked_by:
            name = f"{b.get('guardrail', '')}|{b.get('policy', '')}|{field}"
            if r is None:
                c = _mem_counts.setdefault(key, {})
                c[name] = c.get(name, 0) + 1
            else:
                r.hincrby(key, name, 1)
    except Exception:
        pass


def counters(tenant_id: str) -> list[dict]:
    """[{guardrail, policy, requested, approved, false_positive}], most requested first."""
    key, r = f"prompt_exc_fp:{tenant_id}", _redis()
    raw = dict(_mem_counts.get(key, {})) if r is None else (r.hgetall(key) or {})
    rows: dict[tuple, dict] = {}
    for name, n in raw.items():
        parts = _decode(name).rsplit("|", 2)
        if len(parts) != 3:
            continue
        row = rows.setdefault((parts[0], parts[1]), {
            "guardrail": parts[0], "policy": parts[1],
            "requested": 0, "approved": 0, "false_positive": 0})
        if parts[2] in row:
            row[parts[2]] = int(n)
    return sorted(rows.values(), key=lambda x: -x["requested"])


# ── status and policy indexes (docs/specs/prompt-exception-queue-at-scale.md)
#
# One sorted set per status and one per policy (pending only), all scored by the
# request's expires_at: "still pending" is then a count from now, with no sweep.
# The record is the truth; an index that disagrees with it is repaired when a
# page meets the id.

STATUS_KEEP = 5000
SCAN_MAX = 1000
_mem_z: dict[str, dict[str, float]] = {}
_mem_h: dict[str, dict[str, str]] = {}


def _st_key(tenant_id: str, status: str) -> str:
    return f"prompt_exc_st:{tenant_id}:{status}"


def policy_key(b: dict) -> str:
    ident = f"{b.get('guardrail', '')}|{b.get('policy_id') or b.get('policy', '')}"
    return hashlib.sha256(ident.encode()).hexdigest()[:16]


def _pol_key(tenant_id: str, pk: str) -> str:
    return f"prompt_exc_pol:{tenant_id}:{pk}"


def _zadd(key: str, member: str, score: float) -> None:
    r = _redis()
    if r is None:
        _mem_z.setdefault(key, {})[member] = float(score)
    else:
        r.zadd(key, {member: float(score)})


def _zrem(key: str, *members: str) -> None:
    if not members:
        return
    r = _redis()
    if r is None:
        for m in members:
            _mem_z.get(key, {}).pop(m, None)
    else:
        r.zrem(key, *members)


def _zcard(key: str) -> int:
    r = _redis()
    return len(_mem_z.get(key, {})) if r is None else int(r.zcard(key) or 0)


def _zcount(key: str, lo: float, hi: float = float("inf")) -> int:
    r = _redis()
    if r is None:
        return sum(1 for v in _mem_z.get(key, {}).values() if lo <= v <= hi)
    return int(r.zcount(key, lo, "+inf" if hi == float("inf") else hi) or 0)


def _zrange(key: str, lo: float, hi: float, n: int, desc: bool) -> list[str]:
    """Up to n members with lo <= score <= hi; ascending, or descending."""
    r = _redis()
    if r is None:
        items = sorted(((v, m) for m, v in _mem_z.get(key, {}).items() if lo <= v <= hi),
                       reverse=desc)
        return [m for _v, m in items[:n]]
    lo_s, hi_s = ("-inf" if lo == float("-inf") else lo), ("+inf" if hi == float("inf") else hi)
    try:      # Upstash REST client
        out = (r.zrevrangebyscore(key, hi_s, lo_s, offset=0, count=n) if desc
               else r.zrangebyscore(key, lo_s, hi_s, offset=0, count=n))
    except TypeError:     # redis-py
        out = (r.zrevrangebyscore(key, hi_s, lo_s, start=0, num=n) if desc
               else r.zrangebyscore(key, lo_s, hi_s, start=0, num=n))
    return [_decode(m) for m in (out or [])]


def _trim(key: str) -> None:
    r = _redis()
    if r is None:
        z = _mem_z.get(key, {})
        for m in sorted(z, key=z.get)[:-STATUS_KEEP]:
            z.pop(m, None)
        return
    n = int(r.zcard(key) or 0)
    if n > STATUS_KEEP:
        r.zremrangebyrank(key, 0, n - STATUS_KEEP - 1)


def _hset(key: str, field: str, value: dict) -> None:
    import json
    r = _redis()
    if r is None:
        _mem_h.setdefault(key, {})[field] = json.dumps(value)
    else:
        r.hset(key, field, json.dumps(value))


def _hgetall(key: str) -> dict[str, dict]:
    import json
    r = _redis()
    raw = dict(_mem_h.get(key, {})) if r is None else (r.hgetall(key) or {})
    out = {}
    for k, v in raw.items():
        try:
            out[_decode(k)] = json.loads(_decode(v))
        except ValueError:
            continue
    return out


def _mget(tenant_id: str, ids: list[str]) -> list[Optional[dict]]:
    """The records for ids, in order, in one call."""
    import json
    from storage.tenant_store import _fallback_store
    if not ids:
        return []
    keys = [_key(tenant_id, i) for i in ids]
    r = _redis()
    raw = [_fallback_store.get(k) for k in keys] if r is None else (r.mget(*keys) or [])
    out = []
    for v in raw:
        try:
            rec = json.loads(_decode(v)) if v is not None else None
        except ValueError:
            rec = None
        out.append(rec if isinstance(rec, dict) and rec.get("tenant_id") == tenant_id else None)
    return out


def _index_new(rec: dict) -> None:
    t, rid = rec["tenant_id"], rec["request_id"]
    _zadd(_st_key(t, "pending"), rid, rec["expires_at"])
    for b in rec["blocked_by"]:
        pk = policy_key(b)
        _zadd(_pol_key(t, pk), rid, rec["expires_at"])
        _hset(f"prompt_exc_pols:{t}", pk, {"guardrail": b.get("guardrail", ""),
                                           "policy": b.get("policy", ""),
                                           "policy_id": b.get("policy_id", "")})


def _index_move(rec: dict, frm: str, to: str) -> None:
    """Move a request between status indexes. Never raises: the record is the
    truth, and a page repairs an index that missed a move."""
    try:
        t, rid = rec["tenant_id"], rec["request_id"]
        _zrem(_st_key(t, frm), rid)
        _zadd(_st_key(t, to), rid, rec["expires_at"])
        if frm == "pending":
            for b in rec["blocked_by"]:
                _zrem(_pol_key(t, policy_key(b)), rid)
        if to != "pending":
            _trim(_st_key(t, to))
    except Exception:
        pass


def _ensure_indexes(tenant_id: str) -> None:
    """Build the status and policy indexes from the old all-requests index,
    once per tenant. Idempotent, so two planes doing it at once is harmless."""
    from storage.tenant_store import kv_get, kv_set
    marker = f"prompt_exc_v2:{tenant_id}"
    if kv_get(marker):
        return
    ids = _index_ids(tenant_id, INDEX_MAX)
    now = time.time()
    for start in range(0, len(ids), 100):
        batch = ids[start:start + 100]
        for rid, rec in zip(batch, _mget(tenant_id, batch)):
            if not rec:
                continue
            status = rec.get("status", "pending")
            if status == "pending" and now >= rec.get("expires_at", 0):
                status = "expired"
            _zadd(_st_key(tenant_id, status), rid, rec["expires_at"])
            if status == "pending":
                for b in rec.get("blocked_by") or []:
                    _zadd(_pol_key(tenant_id, policy_key(b)), rid, rec["expires_at"])
                    _hset(f"prompt_exc_pols:{tenant_id}", policy_key(b), {
                        "guardrail": b.get("guardrail", ""), "policy": b.get("policy", ""),
                        "policy_id": b.get("policy_id", "")})
    kv_set(marker, {"at": int(now)})


def _sweep_expired(tenant_id: str, limit: int = 200) -> None:
    """Pending ids whose time has passed go to expired (their records too)."""
    stale = _zrange(_st_key(tenant_id, "pending"), float("-inf"), time.time() - 0.001, limit, False)
    for rid in stale:
        rec = get(tenant_id, rid)            # marks the record expired and moves it
        if rec is None:
            _zrem(_st_key(tenant_id, "pending"), rid)


# ── requests ─────────────────────────────────────────────────────────

def _key(tenant_id: str, request_id: str) -> str:
    return f"prompt_exc:{tenant_id}:{request_id}"


def _save(rec: dict) -> None:
    from storage.tenant_store import kv_set
    ttl = max(60, int(rec["expires_at"] - time.time()) + KEEP_AFTER_EXPIRY_S)
    kv_set(_key(rec["tenant_id"], rec["request_id"]), rec, ttl=ttl)


def get(tenant_id: str, request_id: str, now: Optional[float] = None) -> Optional[dict]:
    """The request, or None. A pending request past its deadline becomes
    `expired` here: the value's own deadline decides, never a Redis TTL."""
    from storage.tenant_store import kv_get
    if not _ID.match(request_id or ""):
        return None
    rec = kv_get(_key(tenant_id, request_id))
    if not isinstance(rec, dict) or rec.get("tenant_id") != tenant_id:
        return None
    now = time.time() if now is None else now
    if rec.get("status") == "pending" and now >= rec.get("expires_at", 0):
        rec["status"] = "expired"
        _save(rec)
        _index_move(rec, "pending", "expired")
    return rec


def _open_for_user(tenant_id: str, user_id: str, now: float) -> list[dict]:
    """This user's pending requests, and the list of ids rewritten without the
    ones that are no longer pending."""
    from storage.tenant_store import kv_get, kv_set
    key = f"prompt_exc_user:{tenant_id}:{_user_hash(user_id)}"
    ids = kv_get(key)
    ids = [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []
    pending = [rec for rec in (get(tenant_id, i, now) for i in ids)
               if rec and rec["status"] == "pending"]
    if len(pending) != len(ids):
        kv_set(key, [p["request_id"] for p in pending], ttl=7 * 86400)
    return pending


def find_pending(tenant_id: str, user_id: str, sha: str, destination: str) -> Optional[dict]:
    for rec in _open_for_user(tenant_id, user_id, time.time()):
        if rec["prompt_sha256"] == sha and rec["destination"] == destination:
            return rec
    return None


def check_limit(tenant_id: str, user_id: str, settings: dict) -> None:
    if len(_open_for_user(tenant_id, user_id, time.time())) >= settings["max_pending_per_user"]:
        raise ExceptionError(429, "too_many_pending",
                             f"You already have {settings['max_pending_per_user']} requests "
                             f"waiting for review.")


def create(tenant_id: str, *, user_id: str, device_id: str, destination: str, prompt: str,
           reason: str, blocked_by: list[dict], settings: dict) -> dict:
    """Store a new pending request. The caller has already established that
    the prompt is blocked, by what, and that the user is under the limit."""
    from storage.tenant_store import kv_get, kv_set
    now = time.time()
    rec = {
        "request_id": "pex_" + secrets.token_hex(10),
        "tenant_id": tenant_id,
        "status": "pending",
        "created_at": int(now),
        "expires_at": int(now) + settings["request_ttl_s"],
        "decided_at": None,
        "user_id": user_id[:256],
        "device_id": device_id[:256],
        "destination": destination,
        "prompt_sha256": prompt_sha256(prompt),
        "prompt": prompt[:PROMPT_STORE_MAX],
        "prompt_len": len(prompt),
        "reason": reason[:REASON_MAX],
        "blocked_by": blocked_by,
        "decision": None,
        "grant_id": None,
    }
    _save(rec)
    _index_add(tenant_id, rec["request_id"], now)
    try:
        _index_new(rec)
    except Exception:
        pass                                 # repaired by _ensure_indexes / a page
    ukey = f"prompt_exc_user:{tenant_id}:{_user_hash(user_id)}"
    ids = kv_get(ukey)
    kv_set(ukey, ([i for i in ids if isinstance(i, str)] if isinstance(ids, list) else [])
           + [rec["request_id"]], ttl=7 * 86400)
    count(tenant_id, blocked_by, "requested")
    return rec


def _matches(rec: dict, policy: Optional[str], user: Optional[str],
             destination: Optional[str], q: Optional[str]) -> bool:
    if policy and policy not in {policy_key(b) for b in rec.get("blocked_by") or []}:
        return False
    if user and rec.get("user_id") != user:
        return False
    if destination and rec.get("destination") != destination:
        return False
    if q:
        needle = q.lower()
        hay = " ".join(str(rec.get(k) or "") for k in
                       ("prompt", "reason", "user_id", "device_id", "destination")).lower()
        if needle not in hay:
            return False
    return True


def _cursor(rec: dict) -> str:
    return f"{rec['expires_at']}:{rec['request_id']}"


def _parse_cursor(cursor: Optional[str]) -> Optional[tuple[float, str]]:
    if not cursor:
        return None
    try:
        score, rid = cursor.split(":", 1)
        if not _ID.match(rid):
            return None
        return float(score), rid
    except ValueError:
        return None


def list_page(tenant_id: str, status: str = "pending", *, policy: Optional[str] = None,
              user: Optional[str] = None, destination: Optional[str] = None,
              q: Optional[str] = None, limit: int = 25, cursor: Optional[str] = None) -> dict:
    """{requests, next_cursor, total, searched?}. Pending is oldest first, the
    others newest first. A page is one range read and one batch read, unless a
    user, site or text filter makes it scan (at most SCAN_MAX ids)."""
    if status not in STATUSES + ("all",):
        raise ExceptionError(400, "invalid_status", "status: " + ", ".join(STATUSES + ("all",)))
    limit = max(1, min(int(limit), 100))
    _ensure_indexes(tenant_id)
    if status in ("pending", "expired"):
        _sweep_expired(tenant_id)
    if status == "all":
        return _list_all(tenant_id, policy=policy, user=user, destination=destination, q=q,
                         limit=limit, cursor=cursor)
    now = time.time()
    desc = status != "pending"
    key = _pol_key(tenant_id, policy) if (policy and status == "pending") else _st_key(tenant_id, status)
    lo = now if status == "pending" else float("-inf")
    total = _zcount(key, lo) if status == "pending" else _zcard(key)
    scanning = bool(user or destination or q or (policy and status != "pending"))
    after = _parse_cursor(cursor)
    budget = SCAN_MAX if scanning else limit + 100
    out: list[dict] = []
    searched = 0
    examined: Optional[dict] = None          # the last record looked at
    while len(out) < limit and searched < budget:
        lo_b, hi_b = lo, float("inf")
        if after:
            if desc:
                hi_b = after[0]
            else:
                lo_b = max(lo, after[0])
        want = min(100, budget - searched) if scanning else limit + 50
        ids = _zrange(key, lo_b, hi_b, want, desc)
        recs = _mget(tenant_id, ids)          # one batch read per round
        pairs = list(zip(ids, recs))
        if after:
            # Ties on the cursor's score are ordered by id: drop the ones
            # already returned (ascending: ids <= the cursor's; descending: >=).
            pairs = [(i, r) for i, r in pairs
                     if not (r and float(r["expires_at"]) == after[0]
                             and ((i <= after[1]) if not desc else (i >= after[1])))]
        if not pairs:
            break
        for rid, rec in pairs:
            if searched >= budget:
                break
            searched += 1
            if rec is None:                      # the record has expired: drop the id
                _zrem(key, rid)
                continue
            examined = rec
            if rec.get("status") == "pending" and now >= rec.get("expires_at", 0):
                rec = get(tenant_id, rid) or rec    # becomes expired, index moved
            if rec.get("status") != status:          # the record is the truth
                _index_move(rec, status, rec.get("status", status))
                continue
            if _matches(rec, policy if scanning else None, user, destination, q):
                out.append(rec)
                if len(out) >= limit:
                    break
        if examined is None or len(ids) < want:
            break
        after = (float(examined["expires_at"]), examined["request_id"])
    more = len(out) >= limit or (scanning and searched >= budget)
    page = {"requests": out,
            "next_cursor": _cursor(examined) if more and examined else None,
            "total": total}
    if scanning:
        page["searched"] = searched
    return page


def _list_all(tenant_id: str, *, policy, user, destination, q, limit: int,
              cursor: Optional[str]) -> dict:
    """Every status, newest first, from the all-requests index, by offset."""
    try:
        offset = max(0, int(cursor or 0))
    except ValueError:
        offset = 0
    ids = _index_ids(tenant_id, INDEX_MAX)
    out, i = [], offset
    while i < len(ids) and len(out) < limit:
        batch = ids[i:i + 100]
        for rid, rec in zip(batch, _mget(tenant_id, batch)):
            i += 1
            if rec and _matches(rec, policy, user, destination, q):
                out.append(rec)
                if len(out) >= limit:
                    break
    return {"requests": out, "next_cursor": str(i) if i < len(ids) and len(out) >= limit else None,
            "total": len(ids), "searched": i - offset}


def list_requests(tenant_id: str, status: Optional[str] = None, limit: int = 100) -> list[dict]:
    return list_page(tenant_id, status or "all", limit=min(limit, 100))["requests"]


def counts(tenant_id: str) -> dict:
    """Requests per status, and pending per policy, in a few store calls."""
    _ensure_indexes(tenant_id)
    _sweep_expired(tenant_id)
    now = time.time()
    out = {s: (_zcount(_st_key(tenant_id, s), now) if s == "pending"
               else _zcard(_st_key(tenant_id, s))) for s in STATUSES}
    history = {(c["guardrail"], c["policy"]): c for c in counters(tenant_id)}
    by_policy = []
    for pk, meta in _hgetall(f"prompt_exc_pols:{tenant_id}").items():
        h = history.get((meta.get("guardrail", ""), meta.get("policy", "")), {})
        by_policy.append({"policy_key": pk, "guardrail": meta.get("guardrail", ""),
                          "policy": meta.get("policy", ""),
                          "pending": _zcount(_pol_key(tenant_id, pk), now),
                          "requested": h.get("requested", 0), "approved": h.get("approved", 0),
                          "false_positive": h.get("false_positive", 0)})
    out["by_policy"] = sorted(by_policy, key=lambda x: (-x["pending"], -x["requested"]))
    return out


def for_requester(rec: dict) -> dict:
    """What the person who asked may see: the outcome, not the review trail."""
    decision = rec.get("decision") or {}
    return {
        "request_id": rec["request_id"], "status": rec["status"],
        "created_at": rec["created_at"], "expires_at": rec["expires_at"],
        "decided_at": rec.get("decided_at"), "destination": rec["destination"],
        "prompt_sha256": rec["prompt_sha256"], "blocked_by": rec["blocked_by"],
        "decision": {"reason": decision.get("reason", ""),
                     "approver": decision.get("approver", "")} if decision else None,
    }


# ── what blocked a prompt, remembered briefly ────────────────────────
#
# A request names the prompt; what blocked it must come from Shield, not the
# caller. Re-screening it at request time is not enough on its own: a policy
# judged by a model can block a prompt and pass the same prompt a moment later,
# and the request was then refused as "no longer blocked". So when
# /guardrails/input blocks, it records what blocked the prompt, keyed by
# tenant, user, destination and prompt hash, for BLOCK_MEMORY_S.

BLOCK_MEMORY_S = 3600


def _block_key(tenant_id: str, user_id: str, destination: str, sha: str) -> str:
    dest = hashlib.sha256(destination.encode()).hexdigest()[:16]
    return f"prompt_exc_block:{tenant_id}:{_user_hash(user_id)}:{dest}:{sha}"


def remember_block(tenant_id: str, user_id: str, destination: str, message: str,
                   blocked_by: list[dict]) -> None:
    """Never raises: this runs after the verdict, in the background."""
    if not (tenant_id and user_id and blocked_by):
        return
    try:
        from storage.tenant_store import kv_set
        kv_set(_block_key(tenant_id, user_id, destination, prompt_sha256(message)),
               {"at": int(time.time()), "blocked_by": blocked_by}, ttl=BLOCK_MEMORY_S)
    except Exception:
        pass


def recent_block(tenant_id: str, user_id: str, destination: str, prompt: str,
                 now: Optional[float] = None) -> Optional[list[dict]]:
    """What blocked this exact prompt for this user and destination in the last
    BLOCK_MEMORY_S, or None. The value's own time decides, not a Redis TTL."""
    from storage.tenant_store import kv_get
    rec = kv_get(_block_key(tenant_id, user_id, destination, prompt_sha256(prompt)))
    now = time.time() if now is None else now
    if not isinstance(rec, dict) or now - rec.get("at", 0) > BLOCK_MEMORY_S:
        return None
    blocked_by = rec.get("blocked_by")
    return blocked_by if isinstance(blocked_by, list) and blocked_by else None


# ── who is asking ────────────────────────────────────────────────────

def requester(request) -> tuple[str, str]:
    """(user id, device id) as the extension sends them. The user id ties a
    request, and later its grant, to one person."""
    state = getattr(request, "state", None)
    user = (getattr(state, "agent_key", None) or request.headers.get("x-agent-key") or "").strip()
    device = (request.headers.get("x-device-id") or "").strip()
    return (user or device)[:256], device[:256]


# ── deciding ─────────────────────────────────────────────────────────

GRANT_TOOL = "prompt_exception"
GRANT_HEADER = "x-shield-exception-grant"


def grant_resource(sha: str, destination: str) -> str:
    return f"prompt:{sha}@{destination}"


def _waived_hash(blocked_by: list[dict]) -> str:
    """Binds a grant to the set of guardrails it may waive."""
    names = sorted({b.get("guardrail", "") for b in blocked_by})
    return "sha256:" + hashlib.sha256("\n".join(names).encode()).hexdigest()


def decide(tenant_id: str, request_id: str, *, approve: bool, approver: str, method: str,
           reason: str = "", false_positive: bool = False) -> dict:
    """Approve or deny a pending request. The first decision stands: a request
    that is no longer pending is returned as it is, with `changed: False`."""
    rec = get(tenant_id, request_id)
    if rec is None:
        raise ExceptionError(404, "not_found", "No such exception request.")
    if rec["status"] != "pending":
        return {**rec, "changed": False}
    who = approver.split(":", 1)[-1].strip().lower()
    if who and who == rec["user_id"].strip().lower():
        raise ExceptionError(403, "self_approval",
                             "The person who asked cannot decide their own request.")
    rec["status"] = "approved" if approve else "denied"
    rec["decided_at"] = int(time.time())
    _index_move(rec, "pending", rec["status"])
    rec["decision"] = {"approver": approver[:200], "method": method, "reason": reason[:REASON_MAX],
                       "false_positive": bool(false_positive)}
    _save(rec)
    if approve:
        count(tenant_id, rec["blocked_by"], "approved")
    if false_positive:
        count(tenant_id, rec["blocked_by"], "false_positive")
    return {**rec, "changed": True}


def mint_for(rec: dict, settings: dict) -> tuple[str, int]:
    """(grant token, its expiry) for an approved request, minted when the
    requester collects it so the short lifetime starts when they can use it.
    Any number may be minted: the request itself can be redeemed only once."""
    from core.approvals import mint_grant
    decision = rec.get("decision") or {}
    ttl = max(60, min(settings["grant_ttl_s"], rec["expires_at"] - int(time.time())))
    token = mint_grant(
        tenant_id=rec["tenant_id"], agent_id=rec["user_id"], agent_instance_id=rec["user_id"],
        session_id=rec["request_id"], tool=GRANT_TOOL,
        resource=grant_resource(rec["prompt_sha256"], rec["destination"]),
        params_hash=_waived_hash(rec["blocked_by"]),
        approvers=[{"sub": decision.get("approver", ""), "method": decision.get("method", ""),
                    "at": rec.get("decided_at")}],
        request_id=rec["request_id"], ttl_seconds=ttl)
    return token, int(time.time()) + ttl


# ── redeeming a grant (called by /guardrails/input on a blocked resend) ──

def redeem(token: str, *, tenant_id: str, user_id: str, destination: str, message: str,
           result: dict) -> tuple[Optional[dict], str]:
    """(request, "") when the grant releases this exact blocked prompt, once;
    (None, why) otherwise, and the block stands.

    Order matters: everything that can be checked is checked before anything
    is burned, so a mismatched resend does not spend the approval.
    """
    from core.approvals import ApprovalError, verify_grant
    from core.nonce_store import NonceStoreUnavailable, burn_nonce_if_unused

    if not tenant_id:
        return None, "no_tenant"
    settings = get_settings(tenant_id)
    if not settings["enabled"]:
        return None, "exceptions_disabled"
    try:
        claims = verify_grant(
            token, expected_tool=GRANT_TOOL,
            expected_resource=grant_resource(prompt_sha256(message), destination),
            allow_breakglass=False, burn_nonce=False)
    except ApprovalError as e:
        text = str(e).lower()
        if "resource mismatch" in text:
            return None, "grant_mismatch"       # another prompt or destination
        if "expired" in text or "exp" in text.split():
            return None, "grant_expired"
        return None, "grant_invalid"
    if claims.tenant_id != tenant_id or not user_id or claims.agent_id != user_id:
        return None, "grant_mismatch"
    rec = get(tenant_id, claims.request_id)
    if rec is None:
        return None, "grant_invalid"
    if rec["status"] != "approved":
        return None, "grant_used" if rec["status"] == "used" else "grant_invalid"
    if time.time() >= rec["expires_at"]:
        return None, "grant_expired"

    # A grant waives what blocked the prompt when it was requested, and nothing
    # else: a guardrail that blocks now but did not then still blocks.
    now_blocking = {b["guardrail"] for b in blocking_results(result)}
    allowed = {b["guardrail"] for b in rec["blocked_by"]}
    if claims.params_hash != _waived_hash(rec["blocked_by"]) or not now_blocking <= allowed:
        return None, "new_violation"
    if now_blocking & set(settings["non_appealable"]):
        return None, "not_appealable"

    try:
        once = burn_nonce_if_unused(f"shield:prompt_exc:used:{tenant_id}:{rec['request_id']}",
                                    max(60, rec["expires_at"] - int(time.time()) + 3600))
    except NonceStoreUnavailable:
        return None, "store_unavailable"        # fail closed: it could be replayed
    if not once:
        return None, "grant_used"
    rec["status"] = "used"
    rec["used_at"] = int(time.time())
    _index_move(rec, "approved", "used")
    rec["grant_id"] = claims.grant_id
    _save(rec)
    return rec, ""


def release(result: dict, rec: dict) -> dict:
    """The blocked result, turned into a pass by an approved exception. The
    failed results stay, marked: the record of what was waived is the point."""
    out = dict(result)
    waived = []
    results = []
    for gr in result.get("guardrail_results") or ():
        if isinstance(gr, dict) and not gr.get("passed", True) \
                and gr.get("action") in BLOCKING_ACTIONS:
            gr = {**gr, "enforced": False, "exception_granted": True}
            waived.append(gr.get("guardrail", ""))
        results.append(gr)
    out["guardrail_results"] = results
    out["safe"], out["action"] = True, "pass"
    out["exception"] = {"request_id": rec["request_id"], "waived": waived,
                        "approver": (rec.get("decision") or {}).get("approver", "")}
    return out
