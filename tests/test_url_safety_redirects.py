"""Outbound OAuth requests must not be bounced to internal addresses.

validate_outbound_url checked only the URL a request started from, while the
HTTP clients used for OAuth discovery, client registration and token calls
followed redirects unchecked. A tenant could register a server whose
discovery URL answers with a redirect to the cloud metadata address, and
Shield would make that request (blind SSRF). guarded_async_client validates
every redirect target before following it.
"""
import asyncio

import httpx
import pytest

from core.url_safety import UnsafeURLError, guarded_async_client

PUBLIC = "https://93.184.215.14"


def _serve(location):
    def handler(request):
        if request.url.host == "93.184.215.14" and request.url.path == "/start":
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(200, json={"issuer": "ok"})
    return httpx.MockTransport(handler)


def _get(location):
    async def go():
        async with guarded_async_client(transport=_serve(location)) as c:
            return await c.get(f"{PUBLIC}/start")
    return asyncio.run(go())


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/",      # cloud metadata
    "http://127.0.0.1:6379/",                        # local Redis
    "http://10.0.0.5/admin",                         # private network
])
def test_a_redirect_to_an_internal_address_is_refused(target):
    with pytest.raises(UnsafeURLError):
        _get(target)


def test_a_redirect_to_a_public_address_is_followed():
    assert _get(f"{PUBLIC}/elsewhere").json() == {"issuer": "ok"}


def test_the_oauth_clients_use_the_guarded_client():
    import inspect

    import api.routes_mcp_admin as admin
    import core.mcp_credentials as creds
    for mod in (admin, creds):
        src = inspect.getsource(mod)
        assert "follow_redirects=True" not in src, mod.__name__
        assert "guarded_async_client()" in src, mod.__name__
