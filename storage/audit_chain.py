"""Tamper-evident audit chain — hash-chained records + signed checkpoints.

Opt-in via ``SHIELD_AUDIT_TAMPER_EVIDENT=1``. When enabled,
``append_hashchained()`` links each audit record into a per-scope hash chain, and
``checkpoint()`` signs the chain head with an Ed25519 audit signer (reusing
``core.signers``). ``verify_chain()`` proves the log is intact and pinpoints the
first tampered sequence; ``export_bundle()`` / ``verify_bundle()`` support
offline verification by an auditor.

This module is the pure core (spec task 1): all logic is exercised against the
in-memory fallback store (no live Redis, no new dependency). The Redis path uses
a Lua compare-and-set for cross-process atomicity; the fallback path uses an
in-process lock.

Storage keys (Redis when available, ``_fallback_store`` dict otherwise):
    auditchain:{scope}         LIST of chained record JSON (append order)
    auditchain:{scope}:head    JSON {"seq", "record_hash"}
    auditchain:ckpt:{scope}    LIST of signed checkpoint JSON
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from storage.tenant_store import _fallback_store, _get_redis

# prev_hash of the very first record in a chain.
GENESIS = "GENESIS"

# Guards the read-head → compute → append critical section for the fallback path.
_lock = threading.Lock()

# Cached audit signer (separate key from agent/cap tokens; its own env var).
_signer = None
_signer_lock = threading.Lock()


def is_enabled() -> bool:
    return os.getenv("SHIELD_AUDIT_TAMPER_EVIDENT", "").lower() in ("1", "true", "yes")


# ── canonicalization + hashing ───────────────────────────────────────


def _canonical(obj) -> bytes:
    """Deterministic JSON encoding — stable across Python versions/dict order."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _core(record: dict) -> dict:
    """The hashed view of a record: everything except the chain fields."""
    return {k: v for k, v in record.items() if k not in ("prev_hash", "record_hash")}


def record_hash(record_core: dict, prev_hash: str) -> str:
    """sha256 over canonical(core) linked to the previous record's hash."""
    h = hashlib.sha256()
    h.update(_canonical(record_core))
    h.update(b"|")
    h.update(prev_hash.encode("utf-8"))
    return h.hexdigest()


# ── signer ───────────────────────────────────────────────────────────


def _audit_signer():
    global _signer
    if _signer is not None:
        return _signer
    with _signer_lock:
        if _signer is None:
            from core.signers import build_signer

            _signer = build_signer(
                kid=os.getenv("SHIELD_AUDIT_SIGNING_KID", "audit-v1"),
                local_key_env="SHIELD_AUDIT_SIGNING_KEY",
            )
    return _signer


# ── key helpers ──────────────────────────────────────────────────────


def _rec_key(scope: str) -> str:
    return f"auditchain:{scope}"


def _head_key(scope: str) -> str:
    return f"auditchain:{scope}:head"


def _ckpt_key(scope: str) -> str:
    return f"auditchain:ckpt:{scope}"


# ── fallback-store accessors (list stored as JSON string) ────────────


def _fb_list(key: str) -> list:
    return json.loads(_fallback_store.get(key, "[]"))


def _fb_set_list(key: str, items: list) -> None:
    _fallback_store[key] = json.dumps(items)


# ── append ───────────────────────────────────────────────────────────


def append_hashchained(scope: str, record: dict) -> dict:
    """Append ``record`` to ``scope``'s hash chain and return the stored record
    (with ``seq``, ``prev_hash``, ``record_hash`` added). Atomic per scope."""
    r = _get_redis()
    if r is not None:
        return _append_redis(r, scope, record)
    with _lock:
        return _append_fallback(scope, record)


def _build_record(record: dict, seq: int, prev_hash: str) -> dict:
    core = {**record, "seq": seq}
    h = record_hash(core, prev_hash)
    return {**core, "prev_hash": prev_hash, "record_hash": h}


def _append_fallback(scope: str, record: dict) -> dict:
    head_raw = _fallback_store.get(_head_key(scope))
    if head_raw:
        head = json.loads(head_raw)
        seq = int(head["seq"]) + 1
        prev = head["record_hash"]
    else:
        seq = 1
        prev = GENESIS
    stored = _build_record(record, seq, prev)
    items = _fb_list(_rec_key(scope))
    items.append(stored)
    _fb_set_list(_rec_key(scope), items)
    _fallback_store[_head_key(scope)] = json.dumps(
        {"seq": seq, "record_hash": stored["record_hash"]}
    )
    return stored


# Lua: append only if the current head still matches what we hashed against
# (compare-and-set). KEYS[1]=head, KEYS[2]=list. ARGV[1]=expected_prev_hash
# ('' for genesis), ARGV[2]=new_head_json, ARGV[3]=record_json. Returns 1/0.
_CAS_LUA = """
local cur = redis.call('GET', KEYS[1])
local expected = ARGV[1]
if cur == false then cur = '' end
local cur_hash = ''
if cur ~= '' then cur_hash = cjson.decode(cur)['record_hash'] end
if (cur == '' and expected == '') or (cur_hash == expected) then
  redis.call('RPUSH', KEYS[2], ARGV[3])
  redis.call('SET', KEYS[1], ARGV[2])
  return 1
end
return 0
"""


def _append_redis(r, scope: str, record: dict, attempts: int = 8) -> dict:
    for _ in range(attempts):
        head_raw = r.get(_head_key(scope))
        if head_raw:
            head = json.loads(head_raw)
            seq = int(head["seq"]) + 1
            prev = head["record_hash"]
        else:
            seq = 1
            prev = GENESIS
        stored = _build_record(record, seq, prev)
        new_head = json.dumps({"seq": seq, "record_hash": stored["record_hash"]})
        expected = "" if prev == GENESIS else prev
        ok = r.eval(_CAS_LUA, 2, _head_key(scope), _rec_key(scope),
                    expected, new_head, json.dumps(stored))
        if ok == 1 or ok == b"1" or ok == "1":
            return stored
    raise RuntimeError(f"audit_chain: CAS append failed after {attempts} attempts")


# ── checkpoints ──────────────────────────────────────────────────────


def checkpoint(scope: str, ts: Optional[float] = None) -> Optional[dict]:
    """Sign the current chain head into a checkpoint. Returns None if empty."""
    r = _get_redis()
    head_raw = r.get(_head_key(scope)) if r is not None else _fallback_store.get(_head_key(scope))
    if not head_raw:
        return None
    head = json.loads(head_raw)
    signer = _audit_signer()
    payload_obj = {
        "scope": scope,
        "seq": int(head["seq"]),
        "head_hash": head["record_hash"],
        "ts": ts if ts is not None else time.time(),
    }
    sig = signer.sign(_canonical(payload_obj)).hex()
    ckpt = {**payload_obj, "sig": sig, "kid": signer.kid}
    if r is not None:
        r.rpush(_ckpt_key(scope), json.dumps(ckpt))
    else:
        items = _fb_list(_ckpt_key(scope))
        items.append(ckpt)
        _fb_set_list(_ckpt_key(scope), items)
    return ckpt


# ── reads ────────────────────────────────────────────────────────────


def get_records(scope: str) -> list:
    r = _get_redis()
    if r is not None:
        raw = r.lrange(_rec_key(scope), 0, -1) or []
        return [json.loads(x if isinstance(x, str) else x.decode()) for x in raw]
    return _fb_list(_rec_key(scope))


def get_checkpoints(scope: str) -> list:
    r = _get_redis()
    if r is not None:
        raw = r.lrange(_ckpt_key(scope), 0, -1) or []
        return [json.loads(x if isinstance(x, str) else x.decode()) for x in raw]
    return _fb_list(_ckpt_key(scope))


# ── verification ─────────────────────────────────────────────────────


def _verify_records(records: list) -> dict:
    """Recompute the chain over ``records``. Returns {valid, checked, break_at_seq, reason}."""
    prev = GENESIS
    expected_seq = 1
    for rec in records:
        seq = rec.get("seq")
        if seq != expected_seq:
            return {"valid": False, "checked": expected_seq - 1,
                    "break_at_seq": seq, "reason": f"sequence gap: expected {expected_seq}, got {seq}"}
        if rec.get("prev_hash") != prev:
            return {"valid": False, "checked": expected_seq - 1,
                    "break_at_seq": seq, "reason": "prev_hash mismatch (record inserted/removed/reordered)"}
        expected_hash = record_hash(_core(rec), prev)
        if rec.get("record_hash") != expected_hash:
            return {"valid": False, "checked": expected_seq - 1,
                    "break_at_seq": seq, "reason": "record_hash mismatch (record altered)"}
        prev = rec["record_hash"]
        expected_seq += 1
    return {"valid": True, "checked": len(records), "break_at_seq": None, "reason": None}


def _verify_checkpoints(records: list, checkpoints: list, verify_sig) -> dict:
    """Check each checkpoint's signature and that it matches the chain at its seq.
    ``verify_sig(payload_bytes, sig_bytes) -> None`` raises on bad signature."""
    by_seq = {rec.get("seq"): rec.get("record_hash") for rec in records}
    max_seq = len(records)
    for ckpt in checkpoints:
        payload_obj = {"scope": ckpt["scope"], "seq": ckpt["seq"],
                       "head_hash": ckpt["head_hash"], "ts": ckpt["ts"]}
        try:
            verify_sig(_canonical(payload_obj), bytes.fromhex(ckpt["sig"]))
        except Exception:
            return {"valid": False, "break_at_seq": ckpt["seq"],
                    "reason": f"checkpoint signature invalid at seq {ckpt['seq']}"}
        seq = ckpt["seq"]
        if seq > max_seq:
            return {"valid": False, "break_at_seq": seq,
                    "reason": f"checkpoint at seq {seq} but chain has only {max_seq} records (truncated)"}
        if by_seq.get(seq) != ckpt["head_hash"]:
            return {"valid": False, "break_at_seq": seq,
                    "reason": f"checkpoint head_hash does not match chain at seq {seq}"}
    return {"valid": True, "break_at_seq": None, "reason": None}


def verify_chain(scope: str) -> dict:
    """Verify a scope's chain against its signed checkpoints (live store)."""
    records = get_records(scope)
    checkpoints = get_checkpoints(scope)
    rec_result = _verify_records(records)
    if not rec_result["valid"]:
        return {**rec_result, "last_checkpoint": _last_ckpt(checkpoints)}
    signer = _audit_signer()
    ck = _verify_checkpoints(records, checkpoints, signer.verify)
    if not ck["valid"]:
        return {"valid": False, "checked": rec_result["checked"],
                "break_at_seq": ck["break_at_seq"], "reason": ck["reason"],
                "last_checkpoint": _last_ckpt(checkpoints)}
    return {"valid": True, "checked": rec_result["checked"], "break_at_seq": None,
            "reason": None, "last_checkpoint": _last_ckpt(checkpoints)}


def _last_ckpt(checkpoints: list) -> Optional[dict]:
    if not checkpoints:
        return None
    last = checkpoints[-1]
    return {"seq": last["seq"], "ts": last["ts"]}


# ── export / offline verify ──────────────────────────────────────────


def export_bundle(scope: str) -> dict:
    """A self-verifying bundle: records + checkpoints + the public key to check them."""
    signer = _audit_signer()
    return {
        "scope": scope,
        "kid": signer.kid,
        "public_key_hex": signer.public_key_bytes().hex(),
        "records": get_records(scope),
        "checkpoints": get_checkpoints(scope),
    }


def verify_bundle(bundle: dict) -> dict:
    """Verify an exported bundle offline using only its embedded public key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["public_key_hex"]))

    def _verify(payload: bytes, sig: bytes) -> None:
        pk.verify(sig, payload)

    records = bundle.get("records", [])
    rec_result = _verify_records(records)
    if not rec_result["valid"]:
        return rec_result
    return _verify_checkpoints(records, bundle.get("checkpoints", []), _verify)


# ── background writer (keeps the guard path at +0ms) ─────────────────
#
# All three audit writers call enqueue(); a single worker thread serializes the
# hash-chain appends (which also avoids CAS contention within a process) and
# periodically checkpoints. Best-effort: a dropped append surfaces as a chain
# gap on verify rather than blocking or crashing the caller.

_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()
_append_counts: dict[str, int] = {}


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="audit-chain"
                )
    return _executor


def _worker(scope: str, record: dict) -> None:
    try:
        append_hashchained(scope, record)
        n = _append_counts.get(scope, 0) + 1
        _append_counts[scope] = n
        ckpt_n = int(os.getenv("SHIELD_AUDIT_CHECKPOINT_N", "100"))
        if ckpt_n > 0 and n % ckpt_n == 0:
            checkpoint(scope)
    except Exception:
        pass  # best-effort; loss shows up as a gap on verify_chain()


def enqueue(scope: str, record: dict) -> None:
    """Fire-and-forget: chain-append ``record`` off the caller's thread.

    No-op when tamper-evidence is disabled. Never raises to the caller."""
    if not is_enabled():
        return
    try:
        _get_executor().submit(_worker, scope, record)
    except Exception:
        pass


# ── test support ─────────────────────────────────────────────────────


def flush_for_tests() -> None:
    """Block until the background writer has drained (single-worker FIFO)."""
    if _executor is not None:
        _executor.submit(lambda: None).result()


def reset_for_tests() -> None:
    """Clear the cached signer (call after changing signing-key env in a test)."""
    global _signer
    with _signer_lock:
        _signer = None
    _append_counts.clear()
