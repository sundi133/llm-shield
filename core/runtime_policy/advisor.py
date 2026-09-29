"""Runtime policy advisor: least-privilege suggestions from what sandboxes deny.

A sandbox that keeps being denied `pypi.org` tells Shield what its profile is
missing. The advisor turns the deny events Shield already ingests (any
runtime: OpenShell, Kubernetes, Cilium, Squid) into suggestions an operator
approves in the portal. Approving writes the profile, and the sync sidecar
applies it to running sandboxes. Spec: docs/specs/runtime-live-policy.md §5.2.

Deterministic, no LLM, and never more than what was observed:
  network deny, host not allowed          -> network_allow (observed methods and
                                             paths; GET when only L4 was seen)
  L7 deny on an allowed host              -> network_method (an extra entry with
                                             only the observed methods and paths)
  deny on an allowed host, unknown binary -> binary
  file or process deny                    -> nothing: loosening a file or process
                                             boundary from observed traffic is
                                             how a sandbox escape gets approved
Rules someone added outside Shield (the sidecar's out_of_band events) become
suggestions too, so they can be approved properly instead of just reverted.

Nothing here ever changes a policy by itself. Storage (tenant-scoped):
  rtadvice:{tenant}:{profile}   HASH  {id} -> JSON, {id}:hits -> counter,
                                      _dropped -> counter; TTL refreshed on write
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import threading
import time
from typing import Optional

from core.runtime_policy.check import _glob_re, _path_re

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "*"}
#: Hosts that exist to receive data from anyone. A suggestion to allow one is
#: flagged, so it is never approved in a hurry.
EXFIL_DOMAINS = ("pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co", "transfer.sh",
                 "file.io", "0x0.st", "termbin.com", "webhook.site", "requestbin.com",
                 "pipedream.net", "ngrok.io", "ngrok-free.app", "ngrok.app",
                 "trycloudflare.com", "burpcollaborator.net", "interact.sh", "oast.fun",
                 "requestcatcher.com", "beeceptor.com", "mockbin.org", "discord.com",
                 "discordapp.com", "api.telegram.org")
KINDS = ("network_allow", "network_method", "binary")
STATUSES = ("pending", "approved", "rejected")
MAX_AGENTS, MAX_PATHS, MAX_BINARIES = 20, 10, 5
DROPPED = "_dropped"

_mem: dict[str, dict[str, str]] = {}
_mem_lock = threading.Lock()
_locks: dict[str, float] = {}


def enabled() -> bool:
    return os.environ.get("SHIELD_RUNTIME_ADVISOR", "on").strip().lower() not in (
        "off", "0", "false", "no")


def _ttl_seconds() -> int:
    try:
        return max(1, int(os.environ.get("SHIELD_RUNTIME_ADVICE_TTL_DAYS", "30"))) * 86400
    except ValueError:
        return 30 * 86400


def _max() -> int:
    try:
        return max(1, int(os.environ.get("SHIELD_RUNTIME_ADVICE_MAX", "200")))
    except ValueError:
        return 200


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _key(tenant_id: str, profile: str) -> str:
    return f"rtadvice:{tenant_id}:{profile}"


def advice_id(kind: str, host: str, port: int, binary: str = "") -> str:
    return "adv_" + hashlib.sha256(
        f"{kind}|{host}|{port}|{binary if kind == 'binary' else ''}".encode()).hexdigest()[:16]


# ── deciding what a denial asks for ──────────────────────────────────


def _entries(profile: dict, host: str, port: int) -> list[int]:
    """Indexes of network.allow entries covering host:port."""
    out = []
    for i, a in enumerate(profile["network"]["allow"]):
        rx = _glob_re([a["host"]])
        if rx is not None and rx.fullmatch(host) and a["port"] == port:
            out.append(i)
    return out


def _covers(entry: dict, method: str, path: str) -> bool:
    if method and "*" not in entry["methods"] and method not in entry["methods"]:
        return False
    if path:
        rx = _path_re(entry["paths"])
        if rx is not None and not rx.match(path):
            return False
    return True


def classify(profile: dict, detail: dict) -> Optional[tuple[str, Optional[int]]]:
    """(kind, allow-entry index) for a network denial, or None when the
    profile already allows it (the sandbox runs an older policy; drift, not
    advice)."""
    host = str(detail.get("host") or "").lower()
    port = int(detail.get("port") or 443)
    method = str(detail.get("method") or "").upper()
    path = str(detail.get("path") or "")
    binary = str(detail.get("binary") or "")
    idx = _entries(profile, host, port)
    if not idx:
        return "network_allow", None
    if not any(_covers(profile["network"]["allow"][i], method, path) for i in idx):
        return "network_method", idx[0]
    if binary and binary not in profile["process"]["allow_binaries"]:
        return "binary", None
    return None


def collapse_paths(paths: list[str]) -> list[str]:
    """At most 3 paths, as narrow as that allows. A path no deeper than the
    collapse depth is kept exactly (/zen stays /zen, so the rule is sure to
    match the request that was denied); deeper ones become a prefix glob
    (/packages/ab/x.whl -> /packages/ab/**). Too many at depth 2 -> depth 1;
    still too many, or nothing observed -> /**. Paths that are already globs
    (rules added outside Shield) are kept as they are."""
    clean = sorted({p.split("?")[0] for p in paths if isinstance(p, str) and p.startswith("/")})
    if not clean:
        return ["/**"]
    globs = {p for p in clean if any(c in p for c in "*?[")}
    if "/**" in globs:
        return ["/**"]
    for depth in (2, 1):
        out = set(globs)
        for p in clean:
            if p in globs:
                continue
            segs = [s for s in p.split("/") if s]
            out.add(p if len(segs) <= depth else "/" + "/".join(segs[:depth]) + "/**")
        if len(out) <= 3:
            return sorted(out)
    return ["/**"]


def flags(rec: dict, profile: Optional[dict] = None) -> list[str]:
    out = []
    methods = set(rec.get("methods") or [])
    if methods & WRITE_METHODS:
        out.append("write_method")
    host = rec.get("host", "")
    try:
        ipaddress.ip_address(host)
        out.append("raw_ip")
    except ValueError:
        pass
    if rec.get("port") not in (80, 443):
        out.append("non_standard_port")
    allowed_bins = set((profile or {}).get("process", {}).get("allow_binaries") or [])
    if rec.get("kind") == "binary" or any(b not in allowed_bins for b in rec.get("binaries") or []):
        out.append("binary")
    if any(host == d or host.endswith("." + d) for d in EXFIL_DOMAINS):
        out.append("exfil_domain")
    if rec.get("origin") == "out_of_band":
        out.append("out_of_band")
    return out


# ── storage ──────────────────────────────────────────────────────────


def _hgetall(tenant_id: str, profile: str) -> dict[str, str]:
    r = _redis()
    if r is None:
        with _mem_lock:
            return dict(_mem.get(_key(tenant_id, profile), {}))
    raw = r.hgetall(_key(tenant_id, profile)) or {}
    dec = (lambda v: v.decode() if isinstance(v, (bytes, bytearray)) else str(v))
    return {dec(k): dec(v) for k, v in raw.items()}


def _hset(tenant_id: str, profile: str, field: str, value: str) -> None:
    r = _redis()
    if r is None:
        with _mem_lock:
            _mem.setdefault(_key(tenant_id, profile), {})[field] = value
        return
    r.hset(_key(tenant_id, profile), field, value)
    r.expire(_key(tenant_id, profile), _ttl_seconds())


def _hincr(tenant_id: str, profile: str, field: str, n: int = 1) -> None:
    r = _redis()
    if r is None:
        with _mem_lock:
            h = _mem.setdefault(_key(tenant_id, profile), {})
            h[field] = str(int(h.get(field, "0")) + n)
        return
    r.hincrby(_key(tenant_id, profile), field, n)


def _hdel(tenant_id: str, profile: str, *fields: str) -> None:
    r = _redis()
    if r is None:
        with _mem_lock:
            for f in fields:
                _mem.get(_key(tenant_id, profile), {}).pop(f, None)
        return
    r.hdel(_key(tenant_id, profile), *fields)


def _records(raw: dict[str, str]) -> dict[str, dict]:
    out = {}
    for field, value in raw.items():
        if not field.startswith("adv_") or field.endswith(":hits"):
            continue
        try:
            rec = json.loads(value)
        except ValueError:
            continue
        rec["hits"] = int(raw.get(f"{field}:hits", "0") or 0)
        out[field] = rec
    return out


def _prune(tenant_id: str, profile: str, recs: dict[str, dict]) -> int:
    """Forget decided suggestions older than the TTL; returns how many."""
    cutoff = time.time() - _ttl_seconds()
    old = [i for i, r in recs.items() if r.get("status") != "pending"
           and (r.get("decided_at") or 0) < cutoff]
    if old:
        _hdel(tenant_id, profile, *old, *[f"{i}:hits" for i in old])
    return len(old)


# ── observe (event ingest, background) ───────────────────────────────


def _shield_hosts() -> set[str]:
    from urllib.parse import urlparse
    url = os.environ.get("SHIELD_PUBLIC_URL", "").strip()
    return {urlparse(url).hostname} if url and urlparse(url).hostname else set()


def observe(tenant_id: str, events: list[dict]) -> int:
    """Fold network denials (and out-of-band rules) into suggestions. Never
    raises; returns how many events contributed."""
    if not enabled():
        return 0
    from core.runtime_policy import check as rc
    from core.runtime_policy import store as rt_store

    profiles: dict[str, Optional[dict]] = {}
    n = 0
    for ev in events:
        try:
            d = ev.get("detail") or {}
            oob = bool(d.get("out_of_band"))
            if ev.get("kind") != "network" or not d.get("host") or \
                    not (ev.get("decision") == "deny" or oob):
                continue
            name = ev.get("profile") or ""
            if not name and ev.get("agent_id"):
                cp = rc.profile_for(tenant_id, ev["agent_id"])
                name = cp.name if cp else ""
            if not name:
                continue
            if name not in profiles:
                try:
                    profiles[name] = rt_store.get_profile(tenant_id, name)
                except Exception:
                    profiles[name] = None
            profile = profiles[name]
            if profile is None or str(d["host"]).lower() in _shield_hosts():
                continue
            n += _fold(tenant_id, name, profile, ev, oob)
        except Exception:
            continue
    return n


def _fold(tenant_id: str, name: str, profile: dict, ev: dict, oob: bool) -> int:
    d = ev["detail"]
    decided = classify(profile, d)
    if decided is None:
        return 0
    kind, _ = decided
    host, port = str(d["host"]).lower(), int(d.get("port") or 443)
    binary = str(d.get("binary") or "")
    aid = advice_id(kind, host, port, binary)
    raw = _hgetall(tenant_id, name)
    recs = _records(raw)
    rec = recs.get(aid)
    if rec is None:
        if len(recs) >= _max() and not _prune(tenant_id, name, recs):
            _hincr(tenant_id, name, DROPPED)
            return 0
        rec = {"id": aid, "kind": kind, "status": "pending", "host": host, "port": port,
               "methods": [], "methods_observed": False, "observed_paths": [],
               "binaries": [], "agents": [], "sources": [], "first_seen": ev.get("at"),
               "last_seen": ev.get("at"), "sample_reason": "", "origin": "denial",
               "decided_by": "", "decided_at": 0, "reject_reason": ""}
    rec.pop("hits", None)
    method = str(d.get("method") or "").upper()
    if method:
        rec["methods_observed"] = True
        if method not in rec["methods"]:
            rec["methods"] = sorted(set(rec["methods"]) | {method})
    path = d.get("path")
    if isinstance(path, str) and path.startswith("/") and path not in rec["observed_paths"] \
            and len(rec["observed_paths"]) < MAX_PATHS:
        rec["observed_paths"].append(path[:200])
    if binary and binary not in rec["binaries"] and len(rec["binaries"]) < MAX_BINARIES:
        rec["binaries"].append(binary[:200])
    agent = ev.get("agent_id") or ""
    if agent and agent not in rec["agents"] and len(rec["agents"]) < MAX_AGENTS:
        rec["agents"].append(agent)
    if ev.get("source") and ev["source"] not in rec["sources"]:
        rec["sources"].append(ev["source"])
    if oob:
        rec["origin"] = "out_of_band"
    rec["last_seen"] = max(rec.get("last_seen") or 0, ev.get("at") or 0)
    rec["sample_reason"] = rec["sample_reason"] or str(d.get("reason") or "")[:300]
    if rec["status"] == "approved":
        rec["status"] = "pending"            # approved, yet the profile still lacks it
        rec["decided_by"], rec["decided_at"] = "", 0
    _hset(tenant_id, name, aid, json.dumps(rec, separators=(",", ":")))
    _hincr(tenant_id, name, f"{aid}:hits")
    return 1


# ── read and decide ──────────────────────────────────────────────────


def proposal(rec: dict) -> dict:
    """The rule a suggestion would add, before any operator edit."""
    methods = rec.get("methods") or []
    return {"host": rec["host"], "port": rec["port"],
            "methods": methods if rec.get("methods_observed") and methods else ["GET"],
            "paths": collapse_paths(rec.get("observed_paths") or []),
            "binaries": list(rec.get("binaries") or [])}


def list_advice(tenant_id: str, profile_name: str, profile: Optional[dict] = None,
                status: str = "pending") -> dict:
    raw = _hgetall(tenant_id, profile_name)
    cutoff = time.time() - _ttl_seconds()
    out = []
    for rec in _records(raw).values():
        if status != "all" and rec.get("status") != status:
            continue
        if rec.get("status") != "pending" and (rec.get("decided_at") or 0) < cutoff:
            continue
        rule = proposal(rec)
        out.append({**rec, "proposal": rule, "flags": flags({**rec, **rule}, profile)})
    out.sort(key=lambda r: (-r["hits"], -(r.get("last_seen") or 0)))
    return {"advice": out, "dropped": int(raw.get(DROPPED, "0") or 0)}


def get(tenant_id: str, profile_name: str, aid: str) -> Optional[dict]:
    return _records(_hgetall(tenant_id, profile_name)).get(aid)


def apply_to_profile(profile: dict, rec: dict, *, methods=None, paths=None) -> tuple[dict, dict]:
    """The profile with the suggestion applied, and the rule that was added.
    Raises ValueError when it no longer applies."""
    rule = proposal(rec)
    if methods is not None:
        rule["methods"] = [str(m).upper() for m in methods]
    if paths is not None:
        rule["paths"] = [str(p) for p in paths]
    new = copy.deepcopy(profile)
    allow = new["network"]["allow"]
    if rec["kind"] in ("network_allow", "network_method"):
        # network_method adds its OWN entry rather than widening the existing
        # one: an entry is methods x paths, so merging POST into "GET /**"
        # would allow POST everywhere. OpenShell (verified on 0.0.80) and
        # Shield's own check both allow a request if ANY entry does.
        if rec["kind"] == "network_method" and not _entries(new, rule["host"], rule["port"]):
            raise ValueError(f"no allow entry for {rule['host']}:{rule['port']} any more")
        allow.append({"host": rule["host"], "port": rule["port"], "methods": rule["methods"],
                      "paths": rule["paths"], "description": f"approved from advisor {rec['id']}"})
    bins = new["process"]["allow_binaries"]
    for b in rule["binaries"]:
        if rec["kind"] == "binary" and b not in bins:
            bins.append(b)
    return new, rule


def decide(tenant_id: str, profile_name: str, aid: str, *, status: str, actor: str,
           reason: str = "") -> None:
    rec = get(tenant_id, profile_name, aid)
    if rec is None:
        return
    rec.pop("hits", None)
    rec.update(status=status, decided_by=actor[:200], decided_at=time.time(),
               reject_reason=reason[:300] if status == "rejected" else "")
    _hset(tenant_id, profile_name, aid, json.dumps(rec, separators=(",", ":")))


# ── profile write lock ───────────────────────────────────────────────


class Busy(Exception):
    pass


class profile_lock:
    """Serializes read-modify-write of one profile (approvals), so two
    approvals never overwrite each other. SET NX EX 5; waits up to ``wait``."""

    def __init__(self, tenant_id: str, name: str, wait: float = 2.0):
        self.key, self.wait = f"rtprofile_lock:{tenant_id}:{name}", wait
        self.token = os.urandom(8).hex()

    def __enter__(self):
        deadline = time.monotonic() + self.wait
        while True:
            if self._acquire():
                return self
            if time.monotonic() >= deadline:
                raise Busy(self.key)
            time.sleep(0.05)

    def _acquire(self) -> bool:
        r = _redis()
        if r is None:
            with _mem_lock:
                now = time.monotonic()
                if _locks.get(self.key, 0) > now:
                    return False
                _locks[self.key] = now + 5
                return True
        return bool(r.set(self.key, self.token, nx=True, ex=5))

    def __exit__(self, *exc):
        r = _redis()
        if r is None:
            with _mem_lock:
                _locks.pop(self.key, None)
            return False
        try:
            # Only release our own lock (it may have expired and been re-taken).
            if r.get(self.key) in (self.token, self.token.encode()):
                r.delete(self.key)
        except Exception:
            pass
        return False


def forget(tenant_id: str, profile: str) -> None:
    """Drop every suggestion for a deleted profile."""
    r = _redis()
    if r is None:
        with _mem_lock:
            _mem.pop(_key(tenant_id, profile), None)
        return
    r.delete(_key(tenant_id, profile))


def reset_memory() -> None:
    with _mem_lock:
        _mem.clear()
        _locks.clear()
