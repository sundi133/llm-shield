"""Prompt exception requests: a user whose prompt was blocked asks for a review.

Spec: docs/specs/prompt-exception-requests.md. This module is the store and its
rules; nothing here runs on the guard path. Routes: api/routes_exceptions.py.

  prompt_exc_settings:{tenant}            the tenant's settings
  prompt_exc:{tenant}:{request_id}        one request, with the prompt text
  prompt_exc_idx:{tenant}                 sorted set of request ids by time
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
    ukey = f"prompt_exc_user:{tenant_id}:{_user_hash(user_id)}"
    ids = kv_get(ukey)
    kv_set(ukey, ([i for i in ids if isinstance(i, str)] if isinstance(ids, list) else [])
           + [rec["request_id"]], ttl=7 * 86400)
    count(tenant_id, blocked_by, "requested")
    return rec


def list_requests(tenant_id: str, status: Optional[str] = None, limit: int = 100) -> list[dict]:
    now = time.time()
    out = []
    for request_id in _index_ids(tenant_id, INDEX_MAX):
        rec = get(tenant_id, request_id, now)
        if rec and (status is None or rec["status"] == status):
            out.append(rec)
            if len(out) >= limit:
                break
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
