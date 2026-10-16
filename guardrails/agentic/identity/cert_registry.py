"""Certificate registry — maps cert fingerprints to agent identities.

Stores cert-to-agent mappings and trust metadata in Redis per tenant.

Redis keys:
    cert_registry:{tenant_id}                    → HASH fingerprint → JSON entry
                                                   (legacy: plain agent_key)
    cert_registry_v:{tenant_id}                  → "2" once legacy keys are normalized
    agent_trust:{tenant_id}:{agent_key}          → JSON trust metadata

Fingerprints are stored normalized: lowercase hex SHA-256, no separators
(core/cert_identity.normalize_fingerprint). Registrations made before that,
in whatever form the caller typed (OpenSSL prints "AB:CD:..."), are rewritten
the first time a lookup misses, so they start matching the fingerprint a proxy
forwards. Several fingerprints may map to one agent, so a renewed certificate
can be registered before the old one expires.

Spec: docs/specs/agent-cert-identity.md (task 2).
"""

import json
import logging
import time
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.cert_registry")

# Trust levels: cert > string_key > anonymous
TRUST_LEVELS = {
    "high": 3,
    "medium": 2,
    "low": 1,
}

DEFAULT_TRUST_BY_METHOD = {
    "cert": "high",
    "string_key": "medium",
    "anonymous": "low",
}


def _registry_key(tenant_id: str) -> str:
    return f"cert_registry:{tenant_id}"


def _decode(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def _entry(raw) -> Optional[dict]:
    """A registry value as a dict: today's JSON entry, or a legacy plain agent key."""
    raw = _decode(raw)
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw)
        if isinstance(v, dict) and v.get("agent_key"):
            return v
    except (ValueError, TypeError):
        pass
    return {"agent_key": str(raw)}


def _all(tenant_id: str) -> dict:
    r = _get_redis()
    if r:
        return {_decode(k): _decode(v) for k, v in (r.hgetall(_registry_key(tenant_id)) or {}).items()}
    return json.loads(_fallback_store.get(_registry_key(tenant_id), "{}"))


def _set(tenant_id: str, fingerprint: str, entry: dict) -> None:
    r = _get_redis()
    data = json.dumps(entry, separators=(",", ":"))
    if r:
        r.hset(_registry_key(tenant_id), fingerprint, data)
    else:
        registry = json.loads(_fallback_store.get(_registry_key(tenant_id), "{}"))
        registry[fingerprint] = data
        _fallback_store[_registry_key(tenant_id)] = json.dumps(registry)


def _delete(tenant_id: str, fingerprints: list[str]) -> None:
    if not fingerprints:
        return
    r = _get_redis()
    if r:
        r.hdel(_registry_key(tenant_id), *fingerprints)
    else:
        registry = json.loads(_fallback_store.get(_registry_key(tenant_id), "{}"))
        for fp in fingerprints:
            registry.pop(fp, None)
        _fallback_store[_registry_key(tenant_id)] = json.dumps(registry)


def _write_trust(tenant_id: str, agent_key: str, record: dict) -> None:
    trust_key = f"agent_trust:{tenant_id}:{agent_key}"
    r = _get_redis()
    if r:
        r.set(trust_key, json.dumps(record))
    else:
        _fallback_store[trust_key] = json.dumps(record)


def _normalize_legacy(tenant_id: str) -> int:
    """Rewrite registrations stored un-normalized ("AB:CD:..."). Once per
    tenant (cert_registry_v marks it done). Returns how many were rewritten."""
    from core.cert_identity import CertError, normalize_fingerprint
    marker = f"cert_registry_v:{tenant_id}"
    r = _get_redis()
    if (r.get(marker) if r else _fallback_store.get(marker)):
        return 0
    moved = 0
    for fp, raw in _all(tenant_id).items():
        try:
            norm = normalize_fingerprint(fp)
        except CertError:
            continue
        if norm != fp:
            entry = _entry(raw)
            if entry:
                _set(tenant_id, norm, entry)
                _delete(tenant_id, [fp])
                moved += 1
    if r:
        r.set(marker, "2")
    else:
        _fallback_store[marker] = "2"
    if moved:
        logger.info("cert registry: normalized %d legacy fingerprints for %s", moved, tenant_id)
    return moved


def register_cert(tenant_id: str, agent_key: str, fingerprint: Optional[str] = None,
                  cert_pem: Optional[str] = None, registered_by: str = "") -> dict:
    """Register a certificate for an agent, by fingerprint or (preferred) by the
    certificate itself, which also records its expiry, subject and names.

    Returns the trust metadata record. Raises core.cert_identity.CertError for a
    malformed fingerprint, or a certificate that is unreadable, expired or weak.
    """
    from core import cert_identity as ci
    entry = {"agent_key": agent_key, "registered_at": int(time.time()),
             "registered_by": registered_by}
    if cert_pem:
        cert = ci.load_pem(cert_pem)
        info = ci.cert_info(cert)
        if info["not_after"] < time.time():
            raise ci.CertError("certificate has expired")
        weak = ci.strength_problems(cert)
        if weak:
            raise ci.CertError("certificate: " + "; ".join(weak))
        fp = info["fingerprint"]
        if fingerprint and ci.normalize_fingerprint(fingerprint) != fp:
            raise ci.CertError("fingerprint does not match the certificate")
        entry.update({"not_after": info["not_after"], "subject": info["subject"],
                      "san_uri": info["san_uri"], "san_dns": info["san_dns"]})
    else:
        fp = ci.normalize_fingerprint(fingerprint)
    existing = _entry(_all(tenant_id).get(fp))
    if existing and existing.get("agent_key") != agent_key:
        raise ci.CertError(f"this certificate is already registered to agent "
                           f"'{existing.get('agent_key')}'; revoke it there first", status=409)
    _set(tenant_id, fp, entry)

    trust_record = {
        "agent_key": agent_key,
        "fingerprint": fp,
        "identity_method": "cert",
        "trust_level": "high",
        "registered_at": entry["registered_at"],
    }
    _write_trust(tenant_id, agent_key, trust_record)
    ci.invalidate(tenant_id)
    logger.info(f"Cert registered: tenant={tenant_id} agent={agent_key} fingerprint={fp[:16]}...")
    return trust_record


def resolve_cert(tenant_id: str, fingerprint: str) -> Optional[dict]:
    """The registry entry for a fingerprint (normalized first), or None:
    {agent_key, registered_at, not_after?, subject?, ...}."""
    from core.cert_identity import CertError, normalize_fingerprint
    try:
        fp = normalize_fingerprint(fingerprint)
    except CertError:
        fp = (fingerprint or "").strip()
    r = _get_redis()
    if r:
        raw = r.hget(_registry_key(tenant_id), fp)
    else:
        raw = json.loads(_fallback_store.get(_registry_key(tenant_id), "{}")).get(fp)
    if raw is None and _normalize_legacy(tenant_id):
        raw = r.hget(_registry_key(tenant_id), fp) if r else \
            json.loads(_fallback_store.get(_registry_key(tenant_id), "{}")).get(fp)
    entry = _entry(raw)
    return {**entry, "fingerprint": fp} if entry else None


def resolve_agent_by_cert(tenant_id: str, fingerprint: str) -> Optional[str]:
    """Resolve a certificate fingerprint to an agent_key (any accepted form).

    Args:
        tenant_id: Tenant identifier
        fingerprint: SHA-256 fingerprint, e.g. from X-Client-Cert-Fingerprint

    Returns:
        agent_key if found, None otherwise.
    """
    entry = resolve_cert(tenant_id, fingerprint)
    return entry.get("agent_key") if entry else None


def list_certs(tenant_id: str) -> list[dict]:
    """Every registered certificate: {fingerprint, agent_key, not_after?, ...}."""
    _normalize_legacy(tenant_id)
    out = []
    for fp, raw in _all(tenant_id).items():
        entry = _entry(raw)
        if entry:
            out.append({**entry, "fingerprint": fp})
    return sorted(out, key=lambda e: (e.get("agent_key", ""), e["fingerprint"]))


def revoke_cert(tenant_id: str, agent_key: str, fingerprint: Optional[str] = None) -> bool:
    """Revoke an agent's certificates: one (by fingerprint) or all.

    The agent keeps cert trust while it has any certificate left; with none it
    falls back to string_key / medium. Returns True if anything was revoked.
    """
    from core import cert_identity as ci
    _normalize_legacy(tenant_id)
    mine = {fp: _entry(raw) for fp, raw in _all(tenant_id).items()}
    mine = {fp: e for fp, e in mine.items() if e and e.get("agent_key") == agent_key}
    if fingerprint is not None:
        try:
            fp = ci.normalize_fingerprint(fingerprint)
        except ci.CertError:
            return False
        targets = [fp] if fp in mine else []
    else:
        targets = list(mine)
    _delete(tenant_id, targets)
    if len(targets) == len(mine):
        # Set trust back to string_key level
        _write_trust(tenant_id, agent_key, {
            "agent_key": agent_key,
            "identity_method": "string_key",
            "trust_level": "medium",
            "registered_at": int(time.time()),
        })
    ci.invalidate(tenant_id)
    return bool(targets)


def get_agent_trust(tenant_id: str, agent_key: str) -> dict:
    """Get trust metadata for an agent.

    Returns:
        Trust record with trust_level and identity_method.
        Defaults to string_key/medium if no record exists.
    """
    trust_key = f"agent_trust:{tenant_id}:{agent_key}"

    r = _get_redis()
    if r:
        data = r.get(trust_key)
        if data:
            if isinstance(data, bytes):
                data = data.decode()
            return json.loads(data)
    else:
        data = _fallback_store.get(trust_key)
        if data:
            return json.loads(data)

    # Default: string_key / medium
    return {
        "agent_key": agent_key,
        "identity_method": "string_key",
        "trust_level": "medium",
    }


def get_trust_level_value(trust_level: str) -> int:
    """Convert trust level name to numeric value for comparison."""
    return TRUST_LEVELS.get(trust_level, 0)
