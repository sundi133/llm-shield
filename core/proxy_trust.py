"""Trusted-proxy boundary for header-derived workload identity.

`X-Forwarded-Client-Cert` (and any identity derived from it) is only trustworthy
when it comes from the proxy that actually performed mTLS with proof-of-possession
(e.g. the Envoy front door). Shield cannot re-prove possession of the private key
from a header — so header-derived identity MUST be gated to the trusted proxy.

Enable with SHIELD_TRUSTED_PROXY_ONLY=true and list the proxy sources in
SHIELD_TRUSTED_PROXY_IPS (comma list of IPs / CIDRs). Fail-closed: trusted-proxy
mode with no configured source trusts nobody.
"""

from __future__ import annotations

import ipaddress
import os

from starlette.requests import Request


def trusted_proxy_only() -> bool:
    return os.environ.get("SHIELD_TRUSTED_PROXY_ONLY", "").lower() in ("true", "1", "yes")


def peer_is_trusted(request: Request) -> bool:
    entries = [e.strip() for e in os.environ.get("SHIELD_TRUSTED_PROXY_IPS", "").split(",") if e.strip()]
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
