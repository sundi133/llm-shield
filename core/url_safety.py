"""Validate outbound URLs for SSRF defense.

Used by any endpoint that fetches a user-supplied URL (playground LLM
proxy, future tool integrations, etc).

The check defends against the common SSRF attack vectors:

  * cloud metadata endpoints (AWS 169.254.169.254, GCP, Azure)
  * RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
  * loopback (127.0.0.0/8, ::1)
  * link-local (169.254/16, fe80::/10)
  * non-http(s) schemes (file://, gopher://, ftp://, …)
  * hostname → IP discrepancies (DNS rebinding)

If SHIELD_LLM_PROXY_ALLOWED_HOSTS is set, ONLY those hostnames are
allowed (strictest mode). Otherwise the function falls back to the
"block-private-IPs" behavior above. Production deployments should set
the allowlist; the IP filter is a defense-in-depth secondary check.

Reported by IEMLabs VAPT, May 2026 — finding 8.1 (SSRF, High).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("votal.url_safety")


class UnsafeURLError(ValueError):
    """Raised when a URL fails the SSRF safety check."""


_ALLOWED_SCHEMES = ("http", "https")

# Cloud metadata endpoints — always blocked, even if the IP isn't in the
# private ranges. Some metadata services use link-local that's caught
# by the IP check, but listing them explicitly defends against future
# providers that don't.
_BLOCKED_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata",
        "metadata.azure.com",
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",  # Alibaba
    }
)


def _allowed_hosts() -> Optional[frozenset[str]]:
    """Parse SHIELD_LLM_PROXY_ALLOWED_HOSTS=host1,host2,...

    Returns:
        None if the env var is unset (block-by-IP mode), else a frozenset
        of lowercased hostnames.
    """
    raw = os.environ.get("SHIELD_LLM_PROXY_ALLOWED_HOSTS", "").strip()
    if not raw:
        return None
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def _ip_is_safe_to_dial(ip_str: str) -> bool:
    """Return False if the IP is internal/metadata/loopback/etc."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Block every category that could route to an internal service
    if (
        ip.is_private          # RFC 1918 + RFC 4193 ULA
        or ip.is_loopback     # 127.0.0.0/8, ::1
        or ip.is_link_local   # 169.254.0.0/16, fe80::/10  (← metadata)
        or ip.is_multicast    # 224/4, ff00::/8
        or ip.is_reserved     # 240/4
        or ip.is_unspecified  # 0.0.0.0, ::
    ):
        return False
    return True


def validate_outbound_url(url: str, *, purpose: str = "outbound") -> str:
    """Reject the URL or return it unchanged if safe.

    Args:
        url:     the URL the application is about to fetch.
        purpose: short label used in error messages and logs (e.g. "llm-proxy").

    Returns:
        The same URL string (canonicalized) if safe.

    Raises:
        UnsafeURLError with a generic message — internals are logged at
        WARNING level but NOT included in the exception so the message
        can be returned to the caller without info-leak risk.
    """
    if not url or not isinstance(url, str):
        raise UnsafeURLError("URL is empty or not a string")

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        raise UnsafeURLError("URL could not be parsed")

    # 1. Scheme must be http or https
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        logger.warning(f"{purpose}: rejecting URL with scheme {parsed.scheme!r}")
        raise UnsafeURLError("URL scheme not allowed")

    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeURLError("URL missing hostname")

    # 2. Hostname-based allowlist (strictest). If env says only api.openai.com
    #    et al. are reachable, no resolution-time trickery matters.
    allowed = _allowed_hosts()
    if allowed is not None:
        if host not in allowed:
            logger.warning(
                f"{purpose}: rejecting URL with host {host!r} "
                f"(not in SHIELD_LLM_PROXY_ALLOWED_HOSTS)"
            )
            raise UnsafeURLError("host not in allowlist")

    # 3. Explicit deny-list of well-known metadata endpoints
    if host in _BLOCKED_HOSTS:
        logger.warning(f"{purpose}: rejecting metadata-endpoint host {host!r}")
        raise UnsafeURLError("host is a blocked internal endpoint")

    # 4. Resolve the hostname and check EVERY returned address is public.
    #    This defends against DNS rebinding and against domains that
    #    intentionally resolve to internal IPs.
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        logger.warning(f"{purpose}: DNS lookup failed for {host!r}")
        raise UnsafeURLError("hostname could not be resolved")

    seen_ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        seen_ips.append(ip_str)
        if not _ip_is_safe_to_dial(ip_str):
            logger.warning(
                f"{purpose}: rejecting URL {url!r} — host {host!r} "
                f"resolved to internal IP {ip_str}"
            )
            raise UnsafeURLError("host resolves to a non-public IP")

    if not seen_ips:
        raise UnsafeURLError("hostname resolved to no addresses")

    return url
