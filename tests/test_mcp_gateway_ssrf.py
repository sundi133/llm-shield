"""SSRF defense on MCP upstream registration (spec-mcp-gateway-enterprise G2).

An admin registers a URL the gateway will DIAL. Without validation a route could
be aimed at cloud metadata (169.254.169.254), a loopback admin port, or an
internal service. assert_upstream_url_safe() is the shared choke point both
registration handlers call; allow_private permits an explicitly-approved
enterprise-internal (RFC 1918) destination while STILL blocking loopback,
link-local and metadata.

IP-literal URLs are used throughout so the checks never touch DNS.
"""
import inspect

import pytest
from fastapi import HTTPException

from core.url_safety import _ip_is_safe_to_dial, validate_outbound_url, UnsafeURLError
import api.routes_mcp_admin as adm
import api.routes_mcp_gateway as gw


# ── the IP primitive ─────────────────────────────────────────────────────


@pytest.mark.parametrize("ip,allow,expected", [
    ("8.8.8.8", False, True),            # public
    ("1.1.1.1", True, True),             # public, allow_private irrelevant
    ("10.0.0.5", False, False),          # RFC1918 blocked by default
    ("10.0.0.5", True, True),            # RFC1918 permitted when asked
    ("192.168.1.9", True, True),
    ("172.16.4.4", True, True),
    ("127.0.0.1", True, False),          # loopback NEVER allowed
    ("169.254.169.254", True, False),    # link-local/metadata NEVER allowed
    ("0.0.0.0", True, False),            # unspecified
    ("::1", True, False),                # ipv6 loopback
])
def test_ip_safety(ip, allow, expected):
    assert _ip_is_safe_to_dial(ip, allow_private=allow) is expected


def test_metadata_host_blocked_even_with_allow_private():
    with pytest.raises(UnsafeURLError):
        validate_outbound_url("http://metadata.google.internal/latest",
                              check_env_allowlist=False, allow_private=True)


# ── the shared registration guard ────────────────────────────────────────


def _bad(cfg):
    with pytest.raises(HTTPException) as e:
        adm.assert_upstream_url_safe(cfg)
    assert e.value.status_code == 400
    return e.value


def _ok(cfg):
    adm.assert_upstream_url_safe(cfg)   # must not raise


def test_loopback_url_rejected():
    _bad({"transport": "http", "url": "http://127.0.0.1:3000/mcp"})


def test_metadata_url_rejected():
    _bad({"transport": "http", "url": "http://169.254.169.254/latest/meta-data/"})


def test_private_url_rejected_by_default():
    _bad({"transport": "http", "url": "http://10.0.0.5:8080/mcp"})


def test_private_url_allowed_when_explicitly_permitted():
    _ok({"transport": "http", "url": "http://10.0.0.5:8080/mcp", "allow_private": True})


def test_allow_private_does_not_unblock_metadata():
    _bad({"transport": "sse", "url": "http://169.254.169.254/", "allow_private": True})


def test_public_ip_url_allowed():
    _ok({"transport": "http", "url": "http://8.8.8.8/mcp"})


def test_stdio_has_no_url_to_check():
    _ok({"transport": "stdio", "command": "docker", "args": ["run", "x"]})


def test_http_enforcement_backend_shield_url_is_checked():
    _bad({"transport": "stdio", "command": "x",
          "enforcement_backend": "http", "shield_url": "http://127.0.0.1:9000"})


def test_inprocess_shield_url_not_dialed_so_not_checked():
    _ok({"transport": "stdio", "command": "x",
         "enforcement_backend": "inprocess", "shield_url": "http://127.0.0.1:9000"})


# ── both handlers must actually call the guard ───────────────────────────


def test_admin_register_calls_the_guard():
    assert "assert_upstream_url_safe" in inspect.getsource(adm.register_server)


def test_tenant_upstream_put_calls_the_guard():
    assert "assert_upstream_url_safe" in inspect.getsource(gw.put_route)


# ── dial-time guard (the anti-rebinding check) ───────────────────────────


def test_connect_upstream_refuses_a_loopback_url():
    import asyncio
    from core.mcp.upstream import connect_upstream
    with pytest.raises(ValueError, match="SSRF"):
        asyncio.run(connect_upstream({"transport": "http", "url": "http://127.0.0.1:9/mcp"}))


def test_connect_upstream_refuses_a_metadata_url():
    import asyncio
    from core.mcp.upstream import connect_upstream
    with pytest.raises(ValueError, match="SSRF"):
        asyncio.run(connect_upstream({"transport": "sse", "url": "http://169.254.169.254/"}))
