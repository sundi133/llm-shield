"""Laptops running the DLP agent: enrollment, device keys, heartbeat, revoke.

Spec: docs/specs/device-dlp-agent.md §5.2, §6.

  device_enroll:{tenant_id}:{token_sha256}       {fleet, uses, expires_at, created_by, created_at}
  device_enroll_used:{tenant_id}:{token_sha256}  counter, INCR'd per enrollment (atomic)
  devices:{tenant_id}                            HASH device_id -> identity + key_hash
  device_seen:{tenant_id}                        HASH device_id -> last heartbeat

An enrollment token looks like `vde.<tenant_id>.<secret>`: the agent has
nothing else to go on at install, so the token names its tenant. Only the
secret's SHA-256 is stored. Each device gets its own key (`vdk_...`, scope
`device`); Shield keeps only its hash, in the key store and in the device
record, which is what revoke removes.

A device key may reach four endpoints and nothing else (DEVICE_PATHS). The
check is a prefix test on the presented key, run inside ShieldMiddleware, so
it adds no Redis read and no middleware layer to any other request, including
the guard path. Each of those endpoints also checks the device record, so a
revoke takes effect at once on every worker, not after the tenant cache expires.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from typing import Optional

from storage.tenant_store import DEVICE_KEY_PREFIX, SCOPE_DEVICE

ENROLL_TOKEN_PREFIX = "vde."
DEVICE_PATHS = frozenset({
    ("GET", "/v1/edge/dlp-bundle"),
    ("POST", "/v1/devices/heartbeat"),
    ("POST", "/v1/devices/ca"),
    ("POST", "/v1/shield/runtime/events"),
})
STATES = ("ok", "no_bundle", "stale_bundle", "model_unavailable", "model_unsupported",
          "model_mismatch", "degraded")
OS_NAMES = ("macos", "windows")
MAX_USES = 10000
MAX_TOKEN_DAYS = 90
# A rollout kit's token sits in MDM for the life of the rollout (new hires
# join months later), so it may live longer and serve more laptops. It is
# still revocable, and every kit mints its own (docs/specs/device-rollout-kit.md §3).
KIT_MAX_USES = 100_000
KIT_MAX_DAYS = 365
KIT_MDMS = ("jamf", "kandji", "intune")
_KIT_ID = re.compile(r"^kit_[0-9a-f]{16}$")
MAX_COUNTERS = 20

_mem_hash: dict[str, dict[str, str]] = {}
_mem_sets: dict[str, set] = {}
_mem_counter: dict[str, int] = {}
_counter_lock = threading.Lock()
_ID = re.compile(r"^dev_[0-9a-f]{16}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class DeviceError(ValueError):
    def __init__(self, message: str, status: int = 400, alert: Optional[dict] = None):
        super().__init__(message)
        self.status = status
        # Set when the refusal is itself worth an alert (see enroll): the route
        # records it as a high-severity event for the tenant.
        self.alert = alert


def enabled() -> bool:
    return os.environ.get("SHIELD_DEVICE_AGENT", "on").strip().lower() not in (
        "0", "off", "false", "no")


#: How recently a device must have been heard from for its serial to be
#: "live" (spec: docs/specs/device-rollout-kit.md §5, point 1).
LIVE_WINDOW_S = 24 * 3600


def reenroll_live_mode() -> str:
    """reject (default) or replace: the escape hatch restoring the old rule."""
    v = os.environ.get("SHIELD_DEVICE_REENROLL_LIVE", "reject").strip().lower()
    return "replace" if v == "replace" else "reject"


def stale_after_s() -> int:
    try:
        return max(60, int(os.environ.get("SHIELD_DEVICE_STALE_S", "3600")))
    except ValueError:
        return 3600


def _sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


# ── storage primitives (Redis, or memory in dev and tests) ───────────


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _decode(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _hgetall(key: str) -> dict[str, dict]:
    r = _redis()
    raw = dict(_mem_hash.get(key, {})) if r is None else (r.hgetall(key) or {})
    out = {}
    for k, v in raw.items():
        try:
            out[_decode(k)] = json.loads(_decode(v))
        except (ValueError, TypeError):
            continue
    return out


def _hget(key: str, field: str) -> Optional[dict]:
    r = _redis()
    v = _mem_hash.get(key, {}).get(field) if r is None else r.hget(key, field)
    if v is None:
        return None
    try:
        return json.loads(_decode(v))
    except (ValueError, TypeError):
        return None


def _hset(key: str, field: str, value: dict) -> None:
    data = json.dumps(value, separators=(",", ":"))
    r = _redis()
    if r is None:
        _mem_hash.setdefault(key, {})[field] = data
    else:
        r.hset(key, field, data)


def _hdel(key: str, field: str) -> bool:
    r = _redis()
    if r is None:
        return _mem_hash.get(key, {}).pop(field, None) is not None
    return bool(r.hdel(key, field))


def _incr(key: str, ttl: int) -> int:
    r = _redis()
    if r is None:
        with _counter_lock:
            _mem_counter[key] = _mem_counter.get(key, 0) + 1
            return _mem_counter[key]
    n = int(r.incr(key))
    if n == 1 and ttl > 0:
        try:
            r.expire(key, ttl)
        except Exception:
            pass
    return n


def _counter(key: str) -> int:
    r = _redis()
    if r is None:
        return _mem_counter.get(key, 0)
    v = r.get(key)
    return int(_decode(v)) if v is not None else 0


def reset_memory() -> None:
    _mem_hash.clear()
    _mem_counter.clear()
    _mem_sets.clear()


# ── enrollment tokens ────────────────────────────────────────────────


def _token_key(tenant_id: str, token_sha: str) -> str:
    return f"device_enroll:{tenant_id}:{token_sha}"


def _used_key(tenant_id: str, token_sha: str) -> str:
    return f"device_enroll_used:{tenant_id}:{token_sha}"


def create_enrollment_token(tenant_id: str, fleet: str, *, uses: int = 50,
                            expires_in_days: int = 7, created_by: str = "",
                            kind: str = "standard", kit_id: str = "",
                            mdm: str = "") -> tuple[str, dict]:
    """(token, record). The token is returned once and never stored.

    kind "kit" is for a rollout kit (kit_id and mdm required) and has its own
    limits; "standard" is the portal's hand-made token."""
    from core.dlp.device_policy import valid_fleet
    from storage.tenant_store import kv_set
    if not valid_fleet(fleet):
        raise DeviceError("fleet: lowercase letters, digits, . _ - (1-64 characters)")
    if kind not in ("standard", "kit"):
        raise DeviceError("kind: standard or kit")
    if kind == "kit" and (not _KIT_ID.match(kit_id or "") or mdm not in KIT_MDMS):
        raise DeviceError(f"a kit token needs kit_id (kit_<16 hex>) and mdm "
                          f"({', '.join(KIT_MDMS)})")
    max_uses, max_days = (KIT_MAX_USES, KIT_MAX_DAYS) if kind == "kit" else (MAX_USES,
                                                                            MAX_TOKEN_DAYS)
    if isinstance(uses, bool) or not isinstance(uses, int) or not 1 <= uses <= max_uses:
        raise DeviceError(f"uses: an integer from 1 to {max_uses}")
    if (isinstance(expires_in_days, bool) or not isinstance(expires_in_days, int)
            or not 1 <= expires_in_days <= max_days):
        raise DeviceError(f"expires_in_days: an integer from 1 to {max_days}")
    secret = secrets.token_urlsafe(32)
    token = f"{ENROLL_TOKEN_PREFIX}{tenant_id}.{secret}"
    now = int(time.time())
    record = {"fleet": fleet, "uses": uses, "expires_at": now + expires_in_days * 86400,
              "created_by": created_by[:200], "created_at": now, "token_id": _sha(secret)[:16],
              "kind": kind}
    if kind == "kit":
        record.update(kit_id=kit_id, mdm=mdm)
    kv_set(_token_key(tenant_id, _sha(secret)), record, ttl=expires_in_days * 86400)
    return token, record


def list_enrollment_tokens(tenant_id: str) -> list[dict]:
    """Outstanding tokens (never the token itself), with uses left."""
    from storage.tenant_store import _fallback_store, kv_get
    prefix = f"device_enroll:{tenant_id}:"
    r = _redis()
    if r is None:
        keys = [k for k in list(_fallback_store) if k.startswith(prefix)]
    else:
        keys, cursor = [], 0
        while True:
            cursor, batch = r.scan(cursor, match=prefix + "*", count=200)
            keys.extend(_decode(k) for k in batch)
            if cursor == 0:
                break
    now, out = int(time.time()), []
    for k in keys:
        rec = kv_get(k)
        if not isinstance(rec, dict) or rec.get("expires_at", 0) <= now:
            continue
        used = _counter(_used_key(tenant_id, k[len(prefix):]))
        out.append({**rec, "uses_left": max(0, rec["uses"] - used)})
    return sorted(out, key=lambda t: t.get("created_at", 0), reverse=True)


def revoke_enrollment_token(tenant_id: str, token_id: str) -> bool:
    from storage.tenant_store import _fallback_store
    prefix = f"device_enroll:{tenant_id}:"
    if not re.match(r"^[0-9a-f]{16}$", token_id or ""):
        return False
    r = _redis()
    keys = ([k for k in list(_fallback_store) if k.startswith(prefix + token_id)] if r is None
            else [_decode(k) for k in r.scan_iter(match=f"{prefix}{token_id}*")])
    for k in keys:
        if r is None:
            _fallback_store.pop(k, None)
        else:
            r.delete(k)
    return bool(keys)


def _check_token(token: str) -> tuple[str, dict, str]:
    """(tenant_id, token record, token_sha) for a live token, WITHOUT taking a
    use. Raises DeviceError(401) for any token that cannot enroll, with one
    message for all of them: which part was wrong is not the caller's business."""
    from storage.tenant_store import kv_get
    bad = DeviceError("invalid or expired enrollment token", status=401)
    if not isinstance(token, str) or not token.startswith(ENROLL_TOKEN_PREFIX):
        raise bad
    tenant_id, _, secret = token[len(ENROLL_TOKEN_PREFIX):].rpartition(".")
    if not tenant_id or len(secret) < 32:
        raise bad
    token_sha = _sha(secret)
    rec = kv_get(_token_key(tenant_id, token_sha))
    if not isinstance(rec, dict) or rec.get("expires_at", 0) <= time.time():
        raise bad
    if _counter(_used_key(tenant_id, token_sha)) >= int(rec.get("uses", 0)):
        raise DeviceError("enrollment token has no uses left", status=401)
    return tenant_id, rec, token_sha


def _take_use(tenant_id: str, rec: dict, token_sha: str) -> None:
    """Take one use atomically (two enrollments racing for the last use: one wins)."""
    used = _incr(_used_key(tenant_id, token_sha), ttl=int(rec["expires_at"] - time.time()) + 60)
    if used > int(rec.get("uses", 0)):
        raise DeviceError("enrollment token has no uses left", status=401)


def _consume(token: str) -> tuple[str, dict, str]:
    tenant_id, rec, token_sha = _check_token(token)
    _take_use(tenant_id, rec, token_sha)
    return tenant_id, rec, token_sha


# ── the company inventory (opt-in) ───────────────────────────────────
# docs/specs/device-rollout-kit.md §3, §5 point 2. An admin uploads the MDM's
# serial number export; once it is non-empty, only those laptops can enroll.
# Serials are hashed on upload and never stored in the clear.
#
#   device_inventory:{tenant_id}        SET of serial_hash
#   device_inventory_meta:{tenant_id}   {count, uploaded_at, uploaded_by}

INVENTORY_MAX = 200_000
_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")


def serial_hash(serial: str) -> str:
    """Trimmed and uppercased, then SHA-256: the agent's rule too
    (votal_device_agent.agent.serial_hash), so exports and firmware agree."""
    return _sha((serial or "").strip().upper())


def _inv_key(tenant_id: str) -> str:
    return f"device_inventory:{tenant_id}"


def _inv_meta_key(tenant_id: str) -> str:
    return f"device_inventory_meta:{tenant_id}"


def parse_serials(raw: bytes, content_type: str = "") -> tuple[list[str], int]:
    """(serials, skipped) from a CSV export (Jamf, Kandji, Intune: the column
    whose header contains "serial"), a one-column list, or JSON (a list, or
    {"serials": [...]})."""
    import csv
    import io
    text = raw.decode("utf-8-sig", errors="replace")
    if "json" in (content_type or "") or text.lstrip()[:1] in ("[", "{"):
        try:
            data = json.loads(text)
        except ValueError:
            raise DeviceError("not valid JSON")
        items = data.get("serials") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise DeviceError('JSON: a list of serials, or {"serials": [...]}')
    else:
        rows = [r for r in csv.reader(io.StringIO(text)) if any(c.strip() for c in r)]
        header = [h.strip().lower() for h in (rows[0] if rows else [])]
        col = next((i for i, h in enumerate(header) if "serial" in h), None)
        if col is not None:
            items = [r[col] for r in rows[1:] if len(r) > col]
        elif all(len(r) == 1 for r in rows):
            items = [r[0] for r in rows]
        else:
            raise DeviceError("CSV: no column whose header contains \"serial\"")
    serials, skipped, seen = [], 0, set()
    for item in items:
        s = str(item).strip()
        if not s:
            continue
        if not _SERIAL.match(s):
            skipped += 1
            continue
        if s.upper() not in seen:
            seen.add(s.upper())
            serials.append(s)
    return serials, skipped


def set_inventory(tenant_id: str, serials: list[str], actor: str = "") -> dict:
    """Replace the inventory (atomically with Redis: build, then rename)."""
    from storage.tenant_store import kv_set
    if len(serials) > INVENTORY_MAX:
        raise DeviceError(f"at most {INVENTORY_MAX} serials", status=413)
    hashes = {serial_hash(s) for s in serials}
    key, r = _inv_key(tenant_id), _redis()
    if r is None:
        _mem_sets[key] = set(hashes)
    elif hashes:
        tmp = f"{key}:upload:{secrets.token_hex(6)}"
        items = list(hashes)
        for i in range(0, len(items), 1000):
            r.sadd(tmp, *items[i:i + 1000])
        r.rename(tmp, key)
    else:
        r.delete(key)
    meta = {"count": len(hashes), "uploaded_at": int(time.time()), "uploaded_by": actor[:200]}
    kv_set(_inv_meta_key(tenant_id), meta)
    return meta


def clear_inventory(tenant_id: str) -> bool:
    from storage.tenant_store import _fallback_store
    key, r = _inv_key(tenant_id), _redis()
    had = inventory_status(tenant_id)["count"] > 0
    if r is None:
        _mem_sets.pop(key, None)
        _fallback_store.pop(_inv_meta_key(tenant_id), None)
    else:
        r.delete(key)
        r.delete(_inv_meta_key(tenant_id))
    return had


def inventory_status(tenant_id: str) -> dict:
    """{count, uploaded_at, uploaded_by, enforced}: never the serials."""
    from storage.tenant_store import kv_get
    key, r = _inv_key(tenant_id), _redis()
    count = len(_mem_sets.get(key, ())) if r is None else int(r.scard(key) or 0)
    meta = kv_get(_inv_meta_key(tenant_id)) or {}
    return {"count": count, "uploaded_at": meta.get("uploaded_at"),
            "uploaded_by": meta.get("uploaded_by", ""), "enforced": count > 0}


def inventory_allows(tenant_id: str, serial_hash_: str) -> Optional[bool]:
    """None when there is no inventory (anyone with a token may enroll)."""
    key, r = _inv_key(tenant_id), _redis()
    if r is None:
        members = _mem_sets.get(key)
        if not members:
            return None
        return bool(serial_hash_) and serial_hash_ in members
    if not int(r.scard(key) or 0):
        return None
    return bool(serial_hash_) and bool(r.sismember(key, serial_hash_))


# ── devices ──────────────────────────────────────────────────────────


def _devices_key(tenant_id: str) -> str:
    return f"devices:{tenant_id}"


def _seen_key(tenant_id: str) -> str:
    return f"device_seen:{tenant_id}"


def _text(body: dict, field: str, n: int, required: bool = True) -> str:
    v = body.get(field)
    if v in (None, "") and not required:
        return ""
    if not isinstance(v, str) or not v.strip() or len(v) > n:
        raise DeviceError(f"{field}: text of 1 to {n} characters")
    return v.strip()


def enroll(token: str, body: dict) -> dict:
    """Register a laptop and mint its key. Returns what the agent stores:
    {device_id, api_key, fleet, tenant_id, pinned_public_key, kid}."""
    from core.embodied import bundle as edge_bundle
    from storage.tenant_store import add_api_key, remove_api_key_by_hash
    if not isinstance(body, dict):
        raise DeviceError("body: an object")
    info = {"hostname": _text(body, "hostname", 255),
            "os": _text(body, "os", 20).lower(),
            "os_version": _text(body, "os_version", 64),
            "agent_version": _text(body, "agent_version", 40),
            "serial_hash": _text(body, "serial_hash", 128, required=False)}
    if info["os"] not in OS_NAMES:
        raise DeviceError(f"os: one of {', '.join(OS_NAMES)}")
    if info["serial_hash"] and not re.match(r"^[0-9a-f]{64}$", info["serial_hash"]):
        raise DeviceError("serial_hash: SHA-256 hex of the hardware serial (never the serial)")
    # Checked before a use is taken: without a signing key the device could
    # never verify a bundle, so enrolling it would only burn the token.
    public_key = edge_bundle.public_key_hex()
    if public_key is None:
        raise DeviceError("bundle signing is not configured on this Shield "
                          "(SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY)", status=503)

    tenant_id, rec, token_sha = _check_token(token)
    fleet = rec["fleet"]
    if inventory_allows(tenant_id, info["serial_hash"]) is False:
        raise DeviceError(
            "this laptop is not in the company inventory; ask IT to add its serial number",
            status=403,
            alert={"tenant_id": tenant_id, "why": "not_in_inventory", "fleet": fleet,
                   "hostname_claimed": info["hostname"],
                   "token_id": rec.get("token_id", token_sha[:16])})
    # A reinstall on the same machine replaces its old identity instead of
    # leaving a ghost that reads as a silent, possibly tampered, device. But a
    # serial is not a secret (it is printed in About This Mac) and the token can
    # be read on any enrolled laptop, so claiming the serial of a device that is
    # still reporting would knock that colleague's laptop off the fleet and take
    # its place. A device heard from in the last 24 h is therefore never
    # replaced: the enrollment is refused and raised as an alert.
    device_id, replaced = None, None
    if info["serial_hash"]:
        seen = _hgetall(_seen_key(tenant_id))
        for did, d in _hgetall(_devices_key(tenant_id)).items():
            if d.get("serial_hash") == info["serial_hash"] and d.get("fleet") == fleet:
                last = int((seen.get(did) or {}).get("at") or d.get("enrolled_at") or 0)
                if time.time() - last < LIVE_WINDOW_S and reenroll_live_mode() == "reject":
                    raise DeviceError(
                        "a device with this serial is still reporting; to reinstall it, "
                        "revoke it in the portal first", status=409,
                        alert={"tenant_id": tenant_id, "why": "live_serial",
                               "device_id": did, "fleet": fleet,
                               "hostname_claimed": info["hostname"],
                               "token_id": rec.get("token_id", token_sha[:16])})
                device_id, replaced = did, d
                break
    _take_use(tenant_id, rec, token_sha)       # checks passed: only now spend a use
    if replaced:
        remove_api_key_by_hash(replaced.get("key_hash", ""))
    device_id = device_id or "dev_" + secrets.token_hex(8)
    api_key = DEVICE_KEY_PREFIX + secrets.token_urlsafe(32)
    add_api_key(tenant_id, api_key, scope=SCOPE_DEVICE, label=f"device {info['hostname']}"[:128],
                device_id=device_id)
    now = int(time.time())
    record = {**info, "fleet": fleet, "enrolled_at": now, "key_hash": _sha(api_key),
              "enrollment_token_id": rec.get("token_id", token_sha[:16]),
              "reenrolled": int((replaced or {}).get("reenrolled", -1)) + 1}
    _hset(_devices_key(tenant_id), device_id, record)
    return {"device_id": device_id, "api_key": api_key, "fleet": fleet, "tenant_id": tenant_id,
            "pinned_public_key": public_key, "kid": edge_bundle.kid(),
            "note": "Verify pinned_public_key equals the key your MDM installed; if they "
                    "differ, refuse it."}


def is_device_key(api_key: Optional[str]) -> bool:
    return bool(api_key) and api_key.startswith(DEVICE_KEY_PREFIX)


def path_allowed(method: str, path: str) -> bool:
    return (method.upper(), path.rstrip("/") or "/") in DEVICE_PATHS


def caller_device(request) -> Optional[tuple[str, str, dict]]:
    """(tenant_id, device_id, device record) when the caller presents a live
    device key; None when it presents some other key. Raises DeviceError(401)
    for a device key that is revoked or unknown."""
    from core.auth import _extract_api_key
    from storage.tenant_store import key_metadata_by_hash, key_scope_by_hash
    api_key = _extract_api_key(request)
    if not is_device_key(api_key):
        return None
    key_hash = _sha(api_key)
    meta = key_metadata_by_hash(key_hash) or {}
    tenant_id, device_id = meta.get("tenant_id"), meta.get("device_id")
    gone = DeviceError("device key revoked or unknown; enroll again", status=401)
    if not tenant_id or not device_id or key_scope_by_hash(key_hash) != SCOPE_DEVICE:
        raise gone
    record = _hget(_devices_key(tenant_id), device_id)
    if not record or record.get("key_hash") != key_hash:
        raise gone
    return tenant_id, device_id, record


def heartbeat(tenant_id: str, device_id: str, body: dict) -> dict:
    """Record what the agent reports. Unknown fields are ignored (a newer agent
    may send more); the known ones are validated."""
    if not isinstance(body, dict):
        raise DeviceError("body: an object")
    bv = body.get("bundle_version")
    if bv is not None and (isinstance(bv, bool) or not isinstance(bv, int) or bv < 0):
        raise DeviceError("bundle_version: a non-negative integer")
    digest = body.get("model_digest") or ""
    if digest and not _DIGEST.match(str(digest)):
        raise DeviceError("model_digest: sha256:<64 hex>")
    mode = body.get("mode") or ""
    if mode and mode not in ("monitor", "enforce"):
        raise DeviceError("mode: monitor or enforce")
    state = body.get("state") or "ok"
    if state not in STATES:
        raise DeviceError(f"state: one of {', '.join(STATES)}")
    counters = body.get("counters") or {}
    if (not isinstance(counters, dict) or len(counters) > MAX_COUNTERS
            or not all(isinstance(k, str) and len(k) <= 40 and isinstance(v, int)
                       and not isinstance(v, bool) and v >= 0 for k, v in counters.items())):
        raise DeviceError(f"counters: at most {MAX_COUNTERS} names mapped to non-negative integers")
    seen = {"at": int(time.time()), "bundle_version": bv, "model_digest": digest, "mode": mode,
            "state": state, "counters": counters}
    av = body.get("agent_version")
    if isinstance(av, str) and 0 < len(av) <= 40:
        seen["agent_version"] = av
    _hset(_seen_key(tenant_id), device_id, seen)
    return seen


def note_ca(tenant_id: str, device_id: str, not_after: int) -> None:
    rec = _hget(_devices_key(tenant_id), device_id)
    if rec:
        rec["ca_not_after"], rec["ca_issued_at"] = int(not_after), int(time.time())
        _hset(_devices_key(tenant_id), device_id, rec)


def list_devices(tenant_id: str, expected_digest: str = "") -> dict:
    """The fleet view: every enrolled device with its last heartbeat, and a
    summary. `stale` is computed from `at`, so a device that stops reporting
    (uninstalled, blocked, powered off) shows up without anyone polling it."""
    devices = _hgetall(_devices_key(tenant_id))
    seen = _hgetall(_seen_key(tenant_id))
    now, limit = int(time.time()), stale_after_s()
    rows = []
    for did, d in sorted(devices.items(), key=lambda kv: kv[1].get("hostname", "")):
        s = seen.get(did) or {}
        last = s.get("at")
        row = {"device_id": did, **{k: v for k, v in d.items() if k != "key_hash"},
               "last_seen": last, "stale": now - (last or d.get("enrolled_at", 0)) > limit,
               "bundle_version": s.get("bundle_version"), "model_digest": s.get("model_digest", ""),
               "mode": s.get("mode", ""), "state": s.get("state", "never_seen" if not last else "ok"),
               "counters": s.get("counters", {})}
        if s.get("agent_version"):
            row["agent_version"] = s["agent_version"]
        row["model_ok"] = (None if not (expected_digest and row["model_digest"])
                           else row["model_digest"] == expected_digest)
        rows.append(row)
    summary = {"devices": len(rows), "stale": sum(r["stale"] for r in rows),
               "by_state": {}, "by_fleet": {}, "stale_after_s": limit}
    for r in rows:
        summary["by_state"][r["state"]] = summary["by_state"].get(r["state"], 0) + 1
        summary["by_fleet"][r["fleet"]] = summary["by_fleet"].get(r["fleet"], 0) + 1
    return {"summary": summary, "devices": rows}


def revoke(tenant_id: str, device_id: str) -> Optional[dict]:
    """Remove the device and its key. Returns the removed record, or None."""
    from storage.tenant_store import remove_api_key_by_hash
    if not _ID.match(device_id or ""):
        return None
    record = _hget(_devices_key(tenant_id), device_id)
    if not record:
        return None
    remove_api_key_by_hash(record.get("key_hash", ""))
    _hdel(_devices_key(tenant_id), device_id)
    _hdel(_seen_key(tenant_id), device_id)
    return {k: v for k, v in record.items() if k != "key_hash"}
