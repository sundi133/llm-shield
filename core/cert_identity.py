"""Certificate-based agent identity: one verifier for forwarded client certificates.

Spec: docs/specs/agent-cert-identity.md (tasks 2 to 5).

A proxy (Envoy, nginx, a cloud load balancer) performs the TLS handshake in
which the agent proves it holds a private key, and forwards the certificate.
This module decides which registered agent that certificate is, if any:

1. a **pinned** fingerprint (guardrails/agentic/identity/cert_registry.py), or
2. a chain to one of the tenant's **trust anchors** (their CA certificates),
   not revoked by an uploaded **CRL**, mapped to an agent by a **rule** that
   matches the certificate's SAN URI, SAN DNS name or subject CN.

It never decides whether to trust the header that carried the certificate:
that is the trusted-proxy boundary (core/proxy_trust.py), checked by the
middleware that calls in here.

Storage (all tenant-scoped by key name):
  cert_anchors:{tenant}   [{id, name, pem, fingerprint, subject, not_after, added_by, added_at}]
  cert_rules:{tenant}     {"rules": [{id, match, pattern, agent_id}], "updated_at"}
  cert_crls:{tenant}      {anchor_id: {pem, this_update, next_update, revoked, stale, ...}}
  cert_seen:{tenant}      {fingerprint: {at, method}}

Verified certificates are cached per process (CACHE_MAX entries, LRU), each
until the earlier of CACHE_TTL_S or the certificate's expiry; changes to a
tenant's anchors, rules, CRLs or pinned certificates clear that tenant's
entries on this process, and other processes within CACHE_TTL_S.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import re
import threading
import time
import urllib.parse
from collections import OrderedDict
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger("votal.cert_identity")

PEM_MAX = 64 * 1024
ANCHORS_MAX = 20
RULES_MAX = 100
CRL_REVOKED_MAX = 200_000
CHAIN_DEPTH_MAX = 5
CACHE_TTL_S = 300
NEGATIVE_TTL_S = 30
CACHE_MAX = 10_000
RSA_MIN_BITS = 2048
RULE_MATCHES = ("san_uri", "san_dns", "subject_cn")
STALE_POLICIES = ("fail_closed", "fail_open")
REQUIRE_VALUES = ("any", "cert", "token", "cert_or_token")
_AGENT_ID_CAPTURE = r"([A-Za-z0-9_.:@-]{1,128})"
_FP_RE = re.compile(r"^[0-9a-f]{64}$")


class CertError(ValueError):
    """A certificate, anchor, rule or CRL that cannot be accepted. The message
    says why, in words an operator can act on."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── fingerprints and forwarded headers ───────────────────────────────


def normalize_fingerprint(value: Any) -> str:
    """Lowercase hex SHA-256, no separators. Accepts OpenSSL's output
    ("SHA256 Fingerprint=AB:CD:..."), "SHA256:AB:CD...", colons, spaces,
    dashes, any case."""
    if not isinstance(value, str):
        raise CertError("fingerprint: text")
    v = value.strip()
    low = v.lower()
    for prefix in ("sha256 fingerprint=", "sha256:", "sha256="):
        if low.startswith(prefix):
            v = v[len(prefix):]
            break
    v = re.sub(r"[\s:\-]", "", v).lower()
    if not _FP_RE.match(v):
        raise CertError("fingerprint: a SHA-256 fingerprint, 64 hex digits "
                        "(colons and a SHA256: prefix are fine)")
    return v


def fingerprint_of(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def load_pem(pem: Any) -> x509.Certificate:
    if not isinstance(pem, str) or not pem.strip():
        raise CertError("certificate: a PEM certificate")
    if len(pem) > PEM_MAX:
        raise CertError(f"certificate: at most {PEM_MAX // 1024} KB")
    try:
        return x509.load_pem_x509_certificate(pem.strip().encode())
    except Exception:
        raise CertError("certificate: not a readable PEM certificate") from None


def _split_pems(text: str) -> list[str]:
    return re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)


def _xfcc_elements(value: str) -> list[str]:
    """Split an Envoy X-Forwarded-Client-Cert value on commas outside quotes."""
    out, buf, quoted, escaped = [], [], False, False
    for ch in value:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            buf.append(ch)
            escaped = True
        elif ch == '"':
            buf.append(ch)
            quoted = not quoted
        elif ch == "," and not quoted:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return [e.strip() for e in out if e.strip()]


def _xfcc_pairs(element: str) -> dict[str, str]:
    pairs, i, n = {}, 0, len(element)
    while i < n:
        eq = element.find("=", i)
        if eq < 0:
            break
        key = element[i:eq].strip().lower()
        i = eq + 1
        if i < n and element[i] == '"':
            i += 1
            buf = []
            while i < n and element[i] != '"':
                if element[i] == "\\" and i + 1 < n:
                    buf.append(element[i + 1])
                    i += 2
                    continue
                buf.append(element[i])
                i += 1
            value = "".join(buf)
            semi = element.find(";", i)
            i = n if semi < 0 else semi + 1
        else:
            semi = element.find(";", i)
            end = n if semi < 0 else semi
            value = element[i:end]
            i = end + 1
        pairs[key] = value
    return pairs


def parse_forwarded_cert(value: Any) -> Optional[tuple[str, list[str]]]:
    """(leaf PEM, [intermediate PEMs]) from a forwarded-certificate header, or
    None. Understands raw PEM (newlines, or tabs as legacy nginx sends), a
    URL-encoded PEM (nginx $ssl_client_escaped_cert) and Envoy's
    X-Forwarded-Client-Cert (Cert= and Chain=; the last element, which is the
    hop nearest Shield). Never raises."""
    try:
        if not isinstance(value, str) or not value.strip() or len(value) > 4 * PEM_MAX:
            return None
        v = value.strip()
        marker = "-----BEGIN CERTIFICATE-----"
        if marker not in v and not v.lower().startswith(("by=", "hash=", "cert=", "subject=", "uri=", "dns=")):
            # URL-encoded (nginx $ssl_client_escaped_cert). A standard encoder
            # leaves "-" alone, so the value still starts "-----BEGIN" with the
            # space and newlines encoded; some encode "-" too. Either way the
            # marker only appears once decoded.
            decoded = urllib.parse.unquote(v)
            if marker in decoded:
                v = decoded
        if v.startswith("-----BEGIN"):
            pems = _split_pems(v.replace("\t", "\n"))
            return (pems[0], pems[1:]) if pems else None
        elements = _xfcc_elements(value.strip())
        if not elements:
            return None
        pairs = _xfcc_pairs(elements[-1])
        leaf = _split_pems(urllib.parse.unquote(pairs.get("cert", "")))
        if not leaf:
            return None
        chain = _split_pems(urllib.parse.unquote(pairs.get("chain", "")))
        chain = [p for p in chain if p.strip() != leaf[0].strip()]
        return leaf[0], chain
    except Exception:
        return None


# ── what a certificate says ──────────────────────────────────────────


def _utc(cert: x509.Certificate, attr: str) -> _dt.datetime:
    v = getattr(cert, f"{attr}_utc", None)
    return v if v is not None else getattr(cert, attr).replace(tzinfo=_dt.timezone.utc)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _sans(cert: x509.Certificate) -> dict[str, list[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return {"uri": san.get_values_for_type(x509.UniformResourceIdentifier),
                "dns": san.get_values_for_type(x509.DNSName)}
    except x509.ExtensionNotFound:
        return {"uri": [], "dns": []}


def _cns(cert: x509.Certificate) -> list[str]:
    return [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if isinstance(a.value, str)]


def cert_info(cert: x509.Certificate) -> dict:
    sans = _sans(cert)
    return {
        "fingerprint": fingerprint_of(cert),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": int(_utc(cert, "not_valid_before").timestamp()),
        "not_after": int(_utc(cert, "not_valid_after").timestamp()),
        "san_uri": sans["uri"], "san_dns": sans["dns"], "subject_cn": _cns(cert),
        "is_ca": _is_ca(cert),
    }


def strength_problems(cert: x509.Certificate) -> list[str]:
    problems = []
    try:
        alg = cert.signature_hash_algorithm
    except Exception:
        alg = None
    if isinstance(alg, (hashes.SHA1, hashes.MD5)):
        problems.append(f"signed with {alg.name.upper()}, which is broken; reissue with SHA-256 or better")
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < RSA_MIN_BITS:
        problems.append(f"RSA key of {key.key_size} bits; at least {RSA_MIN_BITS} are required")
    return problems


def _validity_problem(cert: x509.Certificate, now: _dt.datetime, what: str) -> Optional[str]:
    if now < _utc(cert, "not_valid_before"):
        return f"{what} is not valid yet"
    if now > _utc(cert, "not_valid_after"):
        return f"{what} has expired"
    return None


def _client_auth_problem(cert: x509.Certificate) -> Optional[str]:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return None
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        return "certificate is not for client authentication (extended key usage lacks clientAuth)"
    return None


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Issuer name match AND a real signature check (a self-signed copy of the
    issuer's name fails here, which a name comparison would not catch)."""
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


# ── storage ──────────────────────────────────────────────────────────


def _kv_get(key: str):
    from storage.tenant_store import kv_get
    return kv_get(key)


def _kv_set(key: str, value) -> None:
    from storage.tenant_store import kv_set
    kv_set(key, value)


def _anchors_key(t: str) -> str:
    return f"cert_anchors:{t}"


def _rules_key(t: str) -> str:
    return f"cert_rules:{t}"


def _crls_key(t: str) -> str:
    return f"cert_crls:{t}"


def _seen_key(t: str) -> str:
    return f"cert_seen:{t}"


def list_anchors(tenant_id: str) -> list[dict]:
    v = _kv_get(_anchors_key(tenant_id))
    return [a for a in v if isinstance(a, dict)] if isinstance(v, list) else []


def add_anchor(tenant_id: str, name: str, pem: str, added_by: str = "") -> dict:
    cert = load_pem(pem)
    if not _is_ca(cert):
        raise CertError("anchor: not a CA certificate (basicConstraints CA:TRUE is required)")
    problem = _validity_problem(cert, _dt.datetime.now(_dt.timezone.utc), "anchor")
    if problem:
        raise CertError(problem)
    weak = strength_problems(cert)
    if weak:
        raise CertError("anchor: " + "; ".join(weak))
    anchors = list_anchors(tenant_id)
    info = cert_info(cert)
    if any(a.get("fingerprint") == info["fingerprint"] for a in anchors):
        raise CertError("anchor: this CA certificate is already a trust anchor", status=409)
    if len(anchors) >= ANCHORS_MAX:
        raise CertError(f"anchor: at most {ANCHORS_MAX} trust anchors per tenant")
    if not isinstance(name, str) or not 0 < len(name.strip()) <= 128:
        name = info["subject"][:128]
    entry = {"id": info["fingerprint"][:16], "name": name.strip(), "pem": pem.strip(),
             "fingerprint": info["fingerprint"], "subject": info["subject"],
             "not_after": info["not_after"], "added_by": added_by, "added_at": int(time.time())}
    _kv_set(_anchors_key(tenant_id), anchors + [entry])
    invalidate(tenant_id)
    return {k: v for k, v in entry.items() if k != "pem"}


def remove_anchor(tenant_id: str, anchor_id: str) -> bool:
    anchors = list_anchors(tenant_id)
    kept = [a for a in anchors if a.get("id") != anchor_id]
    if len(kept) == len(anchors):
        return False
    _kv_set(_anchors_key(tenant_id), kept)
    crls = get_crls(tenant_id)
    if anchor_id in crls:
        crls.pop(anchor_id)
        _kv_set(_crls_key(tenant_id), crls)
    invalidate(tenant_id)
    return True


def get_rules(tenant_id: str) -> list[dict]:
    v = _kv_get(_rules_key(tenant_id))
    rules = v.get("rules") if isinstance(v, dict) else None
    return [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []


def validate_rules(rules: Any, registered: Optional[set[str]] = None) -> list[dict]:
    """Clean rules, or CertError naming every problem. A rule without
    {agent_id} must name an agent_id, and that agent must be registered."""
    if not isinstance(rules, list):
        raise CertError("rules: a list")
    if len(rules) > RULES_MAX:
        raise CertError(f"rules: at most {RULES_MAX}")
    out, problems = [], []
    for i, r in enumerate(rules):
        where = f"rules[{i}]"
        if not isinstance(r, dict):
            problems.append(f"{where}: an object")
            continue
        match, pattern, agent = r.get("match"), r.get("pattern"), r.get("agent_id") or ""
        if match not in RULE_MATCHES:
            problems.append(f"{where}.match: one of {', '.join(RULE_MATCHES)}")
        if not isinstance(pattern, str) or not 0 < len(pattern) <= 512:
            problems.append(f"{where}.pattern: text of 1 to 512 characters")
            continue
        holes = pattern.count("{agent_id}")
        if holes > 1:
            problems.append(f"{where}.pattern: at most one {{agent_id}}")
        if holes == 0 and not agent:
            problems.append(f"{where}: agent_id is required when the pattern has no {{agent_id}}")
        if holes == 1 and agent:
            problems.append(f"{where}: give agent_id or {{agent_id}} in the pattern, not both")
        if agent and registered is not None and agent not in registered:
            problems.append(f"{where}.agent_id: '{agent}' is not a registered agent")
        out.append({"id": r.get("id") or f"r{i + 1}", "match": match, "pattern": pattern,
                    "agent_id": agent})
    if problems:
        raise CertError("; ".join(problems))
    ids = [r["id"] for r in out]
    if len(set(ids)) != len(ids):
        raise CertError("rules: ids must be unique")
    return out


def put_rules(tenant_id: str, rules: Any) -> list[dict]:
    clean = validate_rules(rules, set(_agents(tenant_id, fresh=True)))
    _kv_set(_rules_key(tenant_id), {"rules": clean, "updated_at": int(time.time())})
    invalidate(tenant_id)
    return clean


def _compile(rule: dict) -> Optional[re.Pattern]:
    p = rule.get("pattern") or ""
    if "{agent_id}" not in p:
        return None
    before, after = p.split("{agent_id}", 1)
    return re.compile("^" + re.escape(before) + _AGENT_ID_CAPTURE + re.escape(after) + "$")


def match_rules(info: dict, rules: list[dict], registered: set[str]) -> Optional[tuple[str, str]]:
    """(agent_id, rule_id) for the first rule that maps this certificate to a
    registered agent, or None. A rule naming or capturing an agent that is not
    registered maps nothing."""
    for rule in rules:
        values = info.get(rule.get("match") or "", [])
        rx = _compile(rule)
        for v in values:
            if rx is None:
                if v == rule.get("pattern") and rule.get("agent_id") in registered:
                    return rule["agent_id"], rule["id"]
            else:
                m = rx.match(v)
                if m and m.group(1) in registered:
                    return m.group(1), rule["id"]
    return None


def get_crls(tenant_id: str) -> dict:
    v = _kv_get(_crls_key(tenant_id))
    return {k: c for k, c in v.items() if isinstance(c, dict)} if isinstance(v, dict) else {}


def put_crl(tenant_id: str, anchor_id: str, pem: Any, stale: str = "fail_closed",
            added_by: str = "") -> dict:
    """Store a CRL for one anchor. It must be signed by that anchor."""
    if stale not in STALE_POLICIES:
        raise CertError(f"stale: one of {', '.join(STALE_POLICIES)}")
    anchor = next((a for a in list_anchors(tenant_id) if a.get("id") == anchor_id), None)
    if anchor is None:
        raise CertError("anchor: not one of this tenant's trust anchors", status=404)
    if not isinstance(pem, str) or not pem.strip() or len(pem) > 8 * 1024 * 1024:
        raise CertError("crl: a PEM certificate revocation list, at most 8 MB")
    try:
        crl = x509.load_pem_x509_crl(pem.strip().encode())
    except Exception:
        raise CertError("crl: not a readable PEM CRL") from None
    ca = x509.load_pem_x509_certificate(anchor["pem"].encode())
    if crl.issuer != ca.subject or not crl.is_signature_valid(ca.public_key()):
        raise CertError("crl: not issued and signed by this anchor")
    revoked = [format(r.serial_number, "x") for r in crl]
    if len(revoked) > CRL_REVOKED_MAX:
        raise CertError(f"crl: at most {CRL_REVOKED_MAX} revoked certificates")
    this_update = getattr(crl, "last_update_utc", None) or crl.last_update.replace(tzinfo=_dt.timezone.utc)
    nxt = getattr(crl, "next_update_utc", None) or (
        crl.next_update.replace(tzinfo=_dt.timezone.utc) if crl.next_update else None)
    entry = {"this_update": int(this_update.timestamp()),
             "next_update": int(nxt.timestamp()) if nxt else None,
             "revoked": revoked, "stale": stale, "added_by": added_by, "added_at": int(time.time())}
    crls = get_crls(tenant_id)
    crls[anchor_id] = entry
    _kv_set(_crls_key(tenant_id), crls)
    invalidate(tenant_id)
    return {k: v for k, v in entry.items() if k != "revoked"} | {"revoked_count": len(revoked),
                                                                "anchor_id": anchor_id}


def remove_crl(tenant_id: str, anchor_id: str) -> bool:
    crls = get_crls(tenant_id)
    if anchor_id not in crls:
        return False
    crls.pop(anchor_id)
    _kv_set(_crls_key(tenant_id), crls)
    invalidate(tenant_id)
    return True


# ── registered agents (cached; for rules and identity.require) ───────

_agents_cache: dict[str, tuple[float, dict]] = {}
_AGENTS_TTL_S = 60.0


def _agents(tenant_id: str, fresh: bool = False) -> dict:
    now = time.time()
    hit = _agents_cache.get(tenant_id)
    if hit and not fresh and now - hit[0] < _AGENTS_TTL_S:
        return hit[1]
    v = _kv_get(f"agents:{tenant_id}")
    agents = {k: a for k, a in v.items() if isinstance(a, dict)} if isinstance(v, dict) else {}
    _agents_cache[tenant_id] = (now, agents)
    return agents


def invalidate_agents(tenant_id: str) -> None:
    _agents_cache.pop(tenant_id, None)


# ── verification ─────────────────────────────────────────────────────


def _parsed_anchors(tenant_id: str) -> list[tuple[dict, x509.Certificate]]:
    out = []
    for a in list_anchors(tenant_id):
        try:
            out.append((a, x509.load_pem_x509_certificate(a["pem"].encode())))
        except Exception:
            logger.warning("unreadable trust anchor %s for %s", a.get("id"), tenant_id)
    return out


def _crl_problem(tenant_id: str, anchor: dict, cert: x509.Certificate, now: _dt.datetime,
                 crls: dict) -> Optional[str]:
    crl = crls.get(anchor.get("id") or "")
    if not crl:
        return None
    nxt = crl.get("next_update")
    if nxt and now.timestamp() > nxt and crl.get("stale", "fail_closed") == "fail_closed":
        return (f"the revocation list for anchor '{anchor.get('name')}' is out of date "
                f"(next update was due); upload a current one")
    if format(cert.serial_number, "x") in set(crl.get("revoked") or []):
        return "certificate has been revoked"
    return None


def validate_chain(tenant_id: str, leaf: x509.Certificate, chain: list[x509.Certificate],
                   now: Optional[_dt.datetime] = None) -> dict:
    """The anchor this certificate chains to, or CertError saying why not.
    Every link: validity window, strength, signature; issuers: CA:TRUE; the
    leaf: clientAuth when it restricts its use; each link an anchor issued:
    that anchor's CRL."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    for problem in (_validity_problem(leaf, now, "certificate"), _client_auth_problem(leaf)):
        if problem:
            raise CertError(problem)
    weak = strength_problems(leaf)
    if weak:
        raise CertError("certificate: " + "; ".join(weak))
    anchors = _parsed_anchors(tenant_id)
    if not anchors:
        raise CertError("no trust anchors: upload your CA certificate first")
    crls = get_crls(tenant_id)
    current, pool, path = leaf, list(chain), []
    for _depth in range(CHAIN_DEPTH_MAX):
        for meta, ca in anchors:
            if _issued_by(current, ca):
                if _validity_problem(ca, now, "anchor"):
                    continue
                problem = _crl_problem(tenant_id, meta, current, now, crls)
                if problem:
                    raise CertError(problem)
                return {"anchor_id": meta["id"], "anchor_name": meta.get("name"),
                        "path": [fingerprint_of(c) for c in [leaf] + path]}
        nxt = None
        for c in pool:
            if c is not current and _issued_by(current, c) and _is_ca(c) \
                    and not _validity_problem(c, now, "intermediate") and not strength_problems(c):
                nxt = c
                break
        if nxt is None:
            raise CertError("certificate does not chain to any of your trust anchors")
        pool.remove(nxt)
        path.append(nxt)
        current = nxt
    raise CertError(f"certificate chain is longer than {CHAIN_DEPTH_MAX} links")


def explain(tenant_id: str, leaf_pem: str, chain_pems: Optional[list[str]] = None) -> dict:
    """What Shield concludes about a certificate, and why: for setting up
    anchors and rules without sending traffic (POST .../agent-identity/test)."""
    from guardrails.agentic.identity.cert_registry import resolve_cert
    leaf = load_pem(leaf_pem)
    chain = [load_pem(p) for p in (chain_pems or [])]
    info = cert_info(leaf)
    out = {"certificate": info, "pinned": None, "anchor": None, "rule": None,
           "agent": None, "reasons": []}
    pinned = resolve_cert(tenant_id, info["fingerprint"])
    if pinned:
        out["pinned"] = pinned
        problem = _validity_problem(leaf, _dt.datetime.now(_dt.timezone.utc), "certificate")
        if problem:
            out["reasons"].append(problem)
        else:
            out["agent"] = pinned.get("agent_key")
            return out
    try:
        out["anchor"] = validate_chain(tenant_id, leaf, chain)
    except CertError as e:
        out["reasons"].append(str(e))
        return out
    m = match_rules(info, get_rules(tenant_id), set(_agents(tenant_id)))
    if m:
        out["agent"], out["rule"] = m
    else:
        out["reasons"].append("no mapping rule maps this certificate to a registered agent")
    return out


_cache: "OrderedDict[tuple, tuple[float, Optional[dict]]]" = OrderedDict()
_cache_lock = threading.Lock()


def invalidate(tenant_id: str) -> None:
    with _cache_lock:
        for k in [k for k in _cache if k[0] == tenant_id]:
            _cache.pop(k, None)


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()
    _agents_cache.clear()


def _cache_get(key: tuple):
    with _cache_lock:
        hit = _cache.get(key)
        if hit is None:
            return False, None
        if hit[0] <= time.time():
            _cache.pop(key, None)
            return False, None
        _cache.move_to_end(key)
        return True, hit[1]


def _cache_put(key: tuple, expires: float, value: Optional[dict]) -> None:
    with _cache_lock:
        _cache[key] = (expires, value)
        _cache.move_to_end(key)
        while len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)


def _note_seen(tenant_id: str, fingerprint: str, method: str) -> None:
    """Last seen, for the certificates list. Written when a certificate is
    verified, so at most once per cache lifetime per process."""
    try:
        seen = _kv_get(_seen_key(tenant_id))
        seen = seen if isinstance(seen, dict) else {}
        seen[fingerprint] = {"at": int(time.time()), "method": method}
        if len(seen) > 20_000:
            for k in sorted(seen, key=lambda f: seen[f].get("at", 0))[:len(seen) - 20_000]:
                seen.pop(k, None)
        _kv_set(_seen_key(tenant_id), seen)
    except Exception:
        pass


def last_seen(tenant_id: str) -> dict:
    v = _kv_get(_seen_key(tenant_id))
    return v if isinstance(v, dict) else {}


def verify_forwarded(tenant_id: str, header_value: Any) -> Optional[dict]:
    """The agent a forwarded client certificate identifies, or None.

    Result: {agent_key, fingerprint, method: "pinned" | "anchor", anchor_id,
    rule_id, not_after}. The caller has already decided the header came from
    the trusted proxy. Never raises."""
    if not tenant_id:
        return None
    parsed = parse_forwarded_cert(header_value)
    if not parsed:
        return None
    leaf_pem, chain_pems = parsed
    chain_digest = hashlib.sha256("".join(chain_pems).encode()).hexdigest()[:16]
    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    except Exception:
        return None
    fp = fingerprint_of(leaf)
    key = (tenant_id, fp, chain_digest)
    hit, value = _cache_get(key)
    if hit:
        return value
    now = _dt.datetime.now(_dt.timezone.utc)
    result: Optional[dict] = None
    try:
        from guardrails.agentic.identity.cert_registry import resolve_cert
        pinned = resolve_cert(tenant_id, fp)
        if pinned and not _validity_problem(leaf, now, "certificate"):
            result = {"agent_key": pinned["agent_key"], "fingerprint": fp, "method": "pinned",
                      "anchor_id": None, "rule_id": None,
                      "not_after": int(_utc(leaf, "not_valid_after").timestamp())}
        elif not pinned and list_anchors(tenant_id):
            chain = []
            for p in chain_pems:
                try:
                    chain.append(x509.load_pem_x509_certificate(p.encode()))
                except Exception:
                    pass
            anchor = validate_chain(tenant_id, leaf, chain, now)
            m = match_rules(cert_info(leaf), get_rules(tenant_id), set(_agents(tenant_id)))
            if m:
                result = {"agent_key": m[0], "fingerprint": fp, "method": "anchor",
                          "anchor_id": anchor["anchor_id"], "rule_id": m[1],
                          "not_after": int(_utc(leaf, "not_valid_after").timestamp())}
    except CertError as e:
        logger.info("client certificate %s… not accepted for %s: %s", fp[:12], tenant_id, e)
    except Exception:
        logger.exception("client certificate verification failed for %s", tenant_id)
    if result:
        ttl = min(CACHE_TTL_S, max(1, result["not_after"] - int(time.time())))
        _cache_put(key, time.time() + ttl, result)
        _note_seen(tenant_id, fp, result["method"])
    else:
        _cache_put(key, time.time() + NEGATIVE_TTL_S, None)
    return result


def verify_fingerprint(tenant_id: str, fingerprint: Any) -> Optional[dict]:
    """A forwarded fingerprint alone (no certificate): pinned lookup only,
    normalized, refusing a registration whose recorded expiry has passed."""
    if not tenant_id or not isinstance(fingerprint, str) or not fingerprint.strip():
        return None
    try:
        fp = normalize_fingerprint(fingerprint)
    except CertError:
        return None
    from guardrails.agentic.identity.cert_registry import resolve_cert
    pinned = resolve_cert(tenant_id, fp)
    if not pinned:
        return None
    if pinned.get("not_after") and time.time() > pinned["not_after"]:
        return None
    return {"agent_key": pinned["agent_key"], "fingerprint": fp, "method": "pinned",
            "anchor_id": None, "rule_id": None, "not_after": pinned.get("not_after")}


# ── identity.require (task 4) ────────────────────────────────────────


def requirement(tenant_id: str, agent_key: str) -> str:
    """The agent's identity.require, "any" when unset or unknown. Read from a
    cached copy of the registry (60 s; registry writes on this process clear
    it). If the registry cannot be read, the last cached copy is used; with no
    copy at all the agent is treated as "any" (an outage does not invent a
    requirement), and that is logged."""
    try:
        agents = _agents(tenant_id)
    except Exception:
        hit = _agents_cache.get(tenant_id)
        if not hit:
            logger.warning("identity.require unknown for %s/%s: registry unreadable", tenant_id, agent_key)
            return "any"
        agents = hit[1]
    req = ((agents.get(agent_key) or {}).get("identity") or {}).get("require", "any")
    return req if req in REQUIRE_VALUES else "any"


def verified_cert_agent(request: Any) -> str:
    """The agent a proxy-verified certificate identifies on this request, or ''.
    Only counted with the trusted-proxy boundary on: without it the middleware
    still sets mtls_identity (with a warning) from a header anyone can send."""
    from core.proxy_trust import trusted_proxy_only
    if not trusted_proxy_only():
        return ""
    m = getattr(getattr(request, "state", None), "mtls_identity", None)
    return (m or {}).get("agent_key", "") if isinstance(m, dict) else ""


def verified_token_agent(request: Any) -> str:
    """The agent a verified agent token (X-Agent-Token) names on this request, or ''."""
    ident = getattr(getattr(request, "state", None), "identity", None)
    if ident is not None and getattr(ident, "identity_method", "") == "agent_token":
        return getattr(ident, "agent_id", "") or ""
    return ""


def requirement_failure(request: Any, tenant_id: str, agent_key: str) -> Optional[str]:
    """Why a request claiming `agent_key` does not meet the agent's
    identity.require, or None. Spec: docs/specs/agent-cert-identity.md, task 4."""
    if not tenant_id or not agent_key:
        return None
    req = requirement(tenant_id, agent_key)
    if req == "any":
        return None
    cert_ok = verified_cert_agent(request) == agent_key
    token_ok = verified_token_agent(request) == agent_key
    if req == "cert" and not cert_ok:
        return (f"agent '{agent_key}' must authenticate with a client certificate "
                f"verified by your mTLS proxy")
    if req == "token" and not token_ok:
        return f"agent '{agent_key}' must present a verified agent token (X-Agent-Token)"
    if req == "cert_or_token" and not (cert_ok or token_ok):
        return (f"agent '{agent_key}' must authenticate with a proxy-verified client "
                f"certificate or a verified agent token")
    return None


def enforce_requirement(request: Any, tenant_id: str, agent_key: str, where: str) -> Optional[str]:
    """requirement_failure(), plus a decision-audit row when it blocks. The
    one call every enforcement point makes (guard-path middleware, tool check,
    tool output, agent chat, A2A). Never raises: a failure to evaluate the
    requirement is logged and allows, as an unreadable registry does."""
    try:
        reason = requirement_failure(request, tenant_id, agent_key)
    except Exception:
        logger.exception("identity.require check failed for %s/%s", tenant_id, agent_key)
        return None
    if reason:
        try:
            from storage.decision_audit import log_decision
            log_decision(tenant_id=tenant_id, action="block", guardrail="identity_required",
                         agent_key=agent_key, reason=reason,
                         metadata={"where": where,
                                   "require": requirement(tenant_id, agent_key)})
        except Exception:
            pass
    return reason
