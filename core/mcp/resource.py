"""Tenant-addressed MCP gateway URLs, used as OAuth resource identifiers.

An MCP client that signs a person in starts from nothing but a server URL. For
the authorization server to know which company's identity provider to send the
person to, the URL itself has to name the tenant:

    {gateway}/gateway/t/{tenant}/{route}/mcp

That URL is also the token's audience (RFC 8707), so a token issued for one
server is refused by every other server, and its protected-resource metadata
(RFC 9728) lives at the well-known path with the URL's path appended.

Both planes use this module: the data plane to build the URL it expects in a
token's `aud`, the admin plane to read the tenant and route out of the
`resource` parameter of an authorization request. They agree only if
SHIELD_PUBLIC_GATEWAY_URL is the same on both.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.1)
"""

from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import urlparse

# Tenant ids and route names as they appear in a URL path segment. Anything
# else is not a resource this gateway serves, so it is refused rather than
# escaped.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
_PATH = re.compile(r"^/gateway/t/([^/]+)/([^/]+)/mcp$")

WELL_KNOWN = "/.well-known/oauth-protected-resource"


def configured_gateway_base() -> str:
    """The public gateway origin, if configured. Empty when not."""
    return (os.environ.get("SHIELD_PUBLIC_GATEWAY_URL", "")
            or os.environ.get("SHIELD_PUBLIC_BASE_URL", "")).strip().rstrip("/")


def gateway_base(request=None) -> str:
    """The configured origin, else the request's own (local development)."""
    base = configured_gateway_base()
    if base or request is None:
        return base
    return str(getattr(request, "base_url", "") or "").rstrip("/")


def federated_login_enabled() -> bool:
    """SHIELD_OAUTH_FEDERATED_LOGIN=0 turns MCP sign-in off fleet-wide; the
    authorization endpoint then behaves exactly as before. Each tenant must
    still opt in (storage/identity_policy.py)."""
    return os.environ.get("SHIELD_OAUTH_FEDERATED_LOGIN", "1").strip().lower() not in (
        "0", "off", "false", "no")


def issuer_url() -> str:
    """The authorization server's public URL (the admin plane), if configured."""
    return os.environ.get("SHIELD_OAUTH_ISSUER_URL", "").strip().rstrip("/")


def authorization_server_url(request=None) -> str:
    """What protected-resource metadata names as the authorization server."""
    return (issuer_url()
            or os.environ.get("SHIELD_PORTAL_BASE_URL", "").strip().rstrip("/")
            or (str(getattr(request, "base_url", "") or "").rstrip("/") if request else ""))


def connect_url(tenant_id: str, route: str) -> str:
    """Where a person connects their own account for a per-person server (B3)."""
    base = authorization_server_url()
    return f"{base}/connect/{tenant_id}/{route}" if base else f"/connect/{tenant_id}/{route}"


def valid_segment(value: str) -> bool:
    return bool(value) and bool(_SEGMENT.match(value))


def resource_path(tenant_id: str, route: str) -> str:
    return f"/gateway/t/{tenant_id}/{route}/mcp"


def resource_url(tenant_id: str, route: str, request=None) -> str:
    return gateway_base(request) + resource_path(tenant_id, route)


def metadata_url(tenant_id: str, route: str, request=None) -> str:
    return gateway_base(request) + WELL_KNOWN + resource_path(tenant_id, route)


def parse_resource(resource: str) -> Optional[tuple[str, str]]:
    """(tenant, route) if `resource` is a tenant-addressed gateway URL, else None.

    When a gateway origin is configured the resource must be on it, so the
    authorization server never mints a token naming some other host. The
    scheme must be https, except on localhost for development.
    """
    try:
        p = urlparse(resource or "")
    except Exception:
        return None
    if p.query or p.fragment or p.params or not p.netloc:
        return None
    if p.scheme != "https" and not (p.scheme == "http" and p.hostname in
                                    ("localhost", "127.0.0.1", "::1")):
        return None
    base = configured_gateway_base()
    if base and f"{p.scheme}://{p.netloc}".rstrip("/") != base:
        return None
    m = _PATH.match(p.path)
    if not m or not valid_segment(m.group(1)) or not valid_segment(m.group(2)):
        return None
    return m.group(1), m.group(2)
