"""Web Bot Auth for the lab (spec 2.5): sign as an agent operator, verify as the edge.

HTTP Message Signatures (RFC 9421) with Ed25519 keys, a `Signature-Agent`
header naming the operator's key directory, and `tag="web-bot-auth"`. The key
id is the RFC 7638 JWK thumbprint. The IETF draft and Cloudflare's docs
reportedly differ on `Signature-Agent` syntax, so both are accepted:

    string form      Signature-Agent: "https://operator-a.agents.example"
                     covered component "signature-agent"
    dictionary form  Signature-Agent: sig1="https://operator-a.agents.example"
                     covered component "signature-agent";key="sig1"

Lab simplification: the verifier never fetches a directory over the network.
Its registry maps directory origins to keys the lab generated (state/wba/),
standing in for a fetched and cached
`/.well-known/http-message-signatures-directory`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TAG = "web-bot-auth"
OPERATORS = {   # lab operators: name -> directory origin (reserved .example names, never fetched)
    "operator-a": "https://operator-a.agents.example",
    "operator-b": "https://operator-b.agents.example",
}
MAX_SKEW_S = 60


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_jwk(pub: Ed25519PublicKey) -> dict:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw)}


def thumbprint(jwk: dict) -> str:
    """RFC 7638: SHA-256 over the required members, sorted, no whitespace."""
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return _b64u(hashlib.sha256(canon.encode()).digest())


def load_or_create(state: Path, name: str) -> Ed25519PrivateKey:
    path = state / "wba" / f"{name}.pem"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        path.chmod(0o600)
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def directory(state: Path, name: str) -> dict:
    """The operator's key directory body (JWKS)."""
    return {"keys": [public_jwk(load_or_create(state, name).public_key())]}


# ── signing (the agent operator) ─────────────────────────────────────────

def _base(components: list[tuple[str, str]], params: str) -> str:
    lines = [f"{cid}: {value}" for cid, value in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def sign_headers(key: Ed25519PrivateKey, agent_url: str, authority: str, *, form: str = "string",
                 created: int | None = None, lifetime_s: int = 3600, label: str = "sig1") -> dict:
    """Headers for a request to `authority`, valid for `lifetime_s` seconds."""
    created = int(time.time()) if created is None else created
    kid = thumbprint(public_jwk(key.public_key()))
    if form == "dict":
        agent_header = f'{label}="{agent_url}"'
        agent_cid, agent_value = f'"signature-agent";key="{label}"', f'"{agent_url}"'
    else:
        agent_header = f'"{agent_url}"'
        agent_cid, agent_value = '"signature-agent"', f'"{agent_url}"'
    params = (f'("@authority" {agent_cid});created={created};expires={created + lifetime_s};'
              f'keyid="{kid}";alg="ed25519";tag="{TAG}"')
    sig = key.sign(_base([('"@authority"', authority), (agent_cid, agent_value)], params).encode())
    return {"Signature-Agent": agent_header, "Signature-Input": f"{label}={params}",
            "Signature": f"{label}=:{base64.b64encode(sig).decode()}:"}


# ── verifying (the edge) ─────────────────────────────────────────────────

_INPUT = re.compile(r'^\s*([A-Za-z0-9_-]+)=(\(([^)]*)\)(.*))$')
_SIG = re.compile(r'([A-Za-z0-9_-]+)=:([A-Za-z0-9+/=]+):')
_DICT_MEMBER = re.compile(r'([A-Za-z0-9_-]+)="([^"]*)"')


def _agent_urls(header: str) -> dict:
    """label -> URL for the dictionary form, '' -> URL for the string form."""
    header = header.strip()
    if header.startswith('"') and header.endswith('"'):
        return {"": header[1:-1]}
    return dict(_DICT_MEMBER.findall(header))


def verify(headers: dict, authority: str, registry: dict, now: float | None = None) -> tuple[str, str]:
    """('valid' | 'invalid' | 'none' | 'unverified', directory URL or '').

    registry: directory origin -> list of JWKs (the cached directories).
    'unverified' means a well-formed signature naming a directory the edge
    has no keys for; 'invalid' means a known directory whose keys don't
    verify it, a stale or malformed signature, or a Signature-Agent with no
    signature at all.
    """
    h = {k.lower(): v for k, v in headers.items()}
    agent_hdr, sig_input, sig_hdr = h.get("signature-agent", ""), h.get("signature-input", ""), h.get("signature", "")
    urls = _agent_urls(agent_hdr) if agent_hdr else {}
    first_url = next(iter(urls.values()), "")
    if not sig_input and not sig_hdr:
        return ("invalid", first_url) if agent_hdr else ("none", "")
    m = _INPUT.match(sig_input)
    sigs = dict(_SIG.findall(sig_hdr))
    if not m or m.group(1) not in sigs:
        return "invalid", first_url
    label, params, inner, tail = m.group(1), m.group(2), m.group(3), m.group(4)
    p = dict(re.findall(r';([a-z]+)=("[^"]*"|\d+)', tail))
    p = {k: v.strip('"') for k, v in p.items()}
    now = time.time() if now is None else now
    try:
        created, expires = int(p.get("created", "0")), int(p.get("expires", "0"))
    except ValueError:
        return "invalid", first_url
    if p.get("tag") != TAG or p.get("alg", "ed25519") != "ed25519" or created > now + MAX_SKEW_S or expires < now:
        return "invalid", first_url
    covered = re.findall(r'"[^"]+"(?:;key="[^"]+")?', inner)
    components, url = [], ""
    for cid in covered:
        if cid == '"@authority"':
            components.append((cid, authority))
        elif cid.startswith('"signature-agent"'):
            key = re.search(r';key="([^"]+)"', cid)
            url = urls.get(key.group(1) if key else "", "")
            if not url:
                return "invalid", first_url
            components.append((cid, f'"{url}"'))
        else:
            return "invalid", first_url          # the lab verifier signs only these two components
    if '"@authority"' not in covered or not url:
        return "invalid", first_url
    keys = registry.get(url)
    if keys is None:
        return "unverified", url
    jwk = next((k for k in keys if thumbprint(k) == p.get("keyid")), None)
    if jwk is None:
        return "invalid", url
    pad = "=" * (-len(jwk["x"]) % 4)
    pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + pad))
    try:
        pub.verify(base64.b64decode(sigs[label]), _base(components, params).encode())
    except (InvalidSignature, ValueError):
        return "invalid", url
    return "valid", url
