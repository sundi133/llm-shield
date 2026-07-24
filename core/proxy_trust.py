"""Trusted-proxy boundary for header-derived workload identity.

`X-Forwarded-Client-Cert` (and any identity derived from it) is only trustworthy
when it comes from the proxy that actually performed mTLS with proof-of-possession
(e.g. the Envoy front door). Shield cannot re-prove possession of the private key
from a header — so header-derived identity MUST be gated to the trusted proxy.

Trust is established by a **shared secret** the proxy injects, NOT by source IP:
under uvicorn's `proxy_headers` + a permissive `forwarded_allow_ips`,
`request.client.host` is derived from the attacker-controlled `X-Forwarded-For`
header and is therefore spoofable. A secret token the client does not know is not.

Config:
  SHIELD_TRUSTED_PROXY_ONLY=true          enable the boundary
  SHIELD_TRUSTED_PROXY_SECRET=<hi-entropy> the proxy sends it as X-Shield-Proxy-Token
                                           (authoritative; IP-independent)
  SHIELD_TRUSTED_PROXY_IPS=<ip/cidr,...>   optional extra constraint; on its own it
                                           is only safe when forwarded_allow_ips is
                                           locked to the proxy.

Fail-closed: trusted-proxy mode with neither a secret nor an IP list trusts nobody.
"""

from __future__ import annotations

import hmac
import ipaddress
import os

from starlette.requests import Request

_SECRET_HEADER = "X-Shield-Proxy-Token"


def trusted_proxy_only() -> bool:
    return os.environ.get("SHIELD_TRUSTED_PROXY_ONLY", "").lower() in ("true", "1", "yes")


def _ip_entries() -> list[str]:
    return [e.strip() for e in os.environ.get("SHIELD_TRUSTED_PROXY_IPS", "").split(",") if e.strip()]


def _ip_matches(request: Request) -> bool:
    """Match the (possibly proxy-header-derived) peer against the IP allowlist.

    NOTE: request.client.host can be spoofed via X-Forwarded-For when uvicorn runs
    with proxy_headers and a permissive forwarded_allow_ips. Use only as an
    additional constraint alongside the secret, or when the forwarded-IP trust is
    locked down.
    """
    entries = _ip_entries()
    if not entries:
        return False
    peer = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in entries:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _secret_matches(request: Request) -> bool:
    secret = os.environ.get("SHIELD_TRUSTED_PROXY_SECRET", "")
    if not secret:
        return False
    provided = request.headers.get(_SECRET_HEADER, "")
    return bool(provided) and hmac.compare_digest(provided, secret)


def peer_is_trusted(request: Request) -> bool:
    """True if the request came from the trusted proxy.

    When SHIELD_TRUSTED_PROXY_SECRET is set it is AUTHORITATIVE and required — a
    spoofed X-Forwarded-For alone cannot satisfy the gate, because the attacker
    does not know the secret (this is the fix for the client.host-spoof bypass).
    An IP allowlist, if also set, further constrains. When no secret is configured,
    fall back to IP-only (reliable only if forwarded-IP trust is locked down).
    """
    secret = os.environ.get("SHIELD_TRUSTED_PROXY_SECRET", "")
    if secret:
        if not _secret_matches(request):
            return False
        return _ip_matches(request) if _ip_entries() else True
    return _ip_matches(request)
