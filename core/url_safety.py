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


def validate_outbound_url(
    url: str,
    *,
    purpose: str = "outbound",
    check_env_allowlist: bool = True,
    resolve_dns: bool = True,
) -> str:
    """Reject the URL or return it unchanged if safe.

    Args:
        url:     the URL the application is about to fetch.
        purpose: short label used in error messages and logs (e.g. "llm-proxy").
        check_env_allowlist: when True, also enforce the exact-match
            SHIELD_LLM_PROXY_ALLOWED_HOSTS env allowlist. Callers that
            apply their own (e.g. validate_proxy_base_url) pass False so
            the env var isn't interpreted twice with different semantics.
        resolve_dns: when True, resolve the hostname and verify every
            address is public (the real anti-SSRF guarantee, run right
            before dialing). Pass False for a cheap boundary check at
            store time (validate scheme + IP-literal host + metadata
            denylist) that doesn't depend on DNS being reachable.

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
    allowed = _allowed_hosts() if check_env_allowlist else None
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

    # 3b. If the host is an IP literal, check it directly — no DNS needed.
    #     This is the only IP check performed when resolve_dns=False.
    try:
        literal_ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        if not _ip_is_safe_to_dial(str(literal_ip)):
            logger.warning(f"{purpose}: rejecting non-public IP-literal host {host!r}")
            raise UnsafeURLError("host resolves to a non-public IP")
        return url

    if not resolve_dns:
        return url

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


# ── Playground LLM-proxy allowlist (deny-by-default) ─────────────────
#
# The /playground/llm-proxy handler attaches the caller-supplied
# master_key as `Authorization: Bearer …` to the OUTBOUND request. The
# IEMLabs VAPT PoC (findings 8.1 SSRF + 8.3 Information Disclosure)
# pointed base_url at an attacker-controlled Burp Collaborator host and
# received that bearer token — credential exfiltration. The IP/metadata
# filter above does NOT stop this, because the collaborator host is a
# perfectly public IP.
#
# Defense: the proxy may only dial a vetted set of LLM-provider domains.
# Operators extend the list with SHIELD_LLM_PROXY_ALLOWED_HOSTS (comma-
# separated; entries match the host exactly or as a parent domain, e.g.
# "example.com" also allows "llm.example.com"). Setting
# SHIELD_LLM_PROXY_ALLOW_ANY_HOST=1 reverts to IP-filter-only behavior
# for self-hosted/dev setups that genuinely need arbitrary endpoints.
_DEFAULT_LLM_PROVIDER_DOMAINS: tuple[str, ...] = (
    "openai.com",
    "anthropic.com",
    "openai.azure.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "cohere.ai",
    "cohere.com",
    "mistral.ai",
    "groq.com",
    "together.xyz",
    "together.ai",
    "deepseek.com",
    "openrouter.ai",
    "perplexity.ai",
    "fireworks.ai",
    "x.ai",
    "runpod.ai",
    "railway.app",
)

_TRUTHY = ("1", "true", "yes", "on")


def _allow_any_proxy_host() -> bool:
    return os.environ.get("SHIELD_LLM_PROXY_ALLOW_ANY_HOST", "").strip().lower() in _TRUTHY


def _proxy_allowed_domains() -> tuple[str, ...]:
    """Built-in provider domains plus any from SHIELD_LLM_PROXY_ALLOWED_HOSTS."""
    raw = os.environ.get("SHIELD_LLM_PROXY_ALLOWED_HOSTS", "").strip()
    extra = tuple(h.strip().lower() for h in raw.split(",") if h.strip())
    return _DEFAULT_LLM_PROVIDER_DOMAINS + extra


def _host_in_domains(host: str, domains: tuple[str, ...]) -> bool:
    """True if host equals, or is a subdomain of, any allowed domain."""
    host = host.lower()
    for d in domains:
        if host == d or host.endswith("." + d):
            return True
    return False


def validate_proxy_base_url(url: str, *, purpose: str = "llm-proxy") -> str:
    """Validate a user-supplied LLM base_url for the playground proxy.

    Stricter than validate_outbound_url: enforces a provider allowlist
    (deny-by-default) BEFORE the network-level SSRF checks, so the
    bearer token the proxy attaches can only ever reach a known LLM
    provider. Raises UnsafeURLError (generic message) on rejection.
    """
    if _allow_any_proxy_host():
        return validate_outbound_url(url, purpose=purpose)

    if not url or not isinstance(url, str):
        raise UnsafeURLError("URL is empty or not a string")

    try:
        parsed = urlparse(url.strip())
    except Exception:
        raise UnsafeURLError("URL could not be parsed")

    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeURLError("URL missing hostname")

    if not _host_in_domains(host, _proxy_allowed_domains()):
        logger.warning(
            f"{purpose}: rejecting base_url host {host!r} — not an allowed "
            f"LLM provider (set SHIELD_LLM_PROXY_ALLOWED_HOSTS to permit it)"
        )
        raise UnsafeURLError("LLM provider host is not allowed")

    # Defense in depth: still run the IP/metadata/scheme checks. The env
    # allowlist is disabled here since we just applied the richer one.
    return validate_outbound_url(url, purpose=purpose, check_env_allowlist=False)
