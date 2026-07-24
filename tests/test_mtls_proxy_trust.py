"""mTLS middleware must gate header-derived identity to a trusted proxy.

Audit finding: MTLSMiddleware fingerprints a header-carried cert with no
proof-of-possession (a cert is public), so it is only safe behind a proxy that
performed real mTLS. These tests assert the trusted-proxy guard applies, and that
the shared proxy_trust helpers back both middlewares.
"""

import types

from core.proxy_trust import peer_is_trusted, trusted_proxy_only
import core.mtls_middleware as mtls_mw
import core.oauth.spiffe_middleware as spiffe_mw


def _req(peer):
    r = types.SimpleNamespace()
    r.client = types.SimpleNamespace(host=peer) if peer else None
    return r


def test_mtls_uses_shared_proxy_trust():
    # Both middlewares import the same boundary implementation.
    assert mtls_mw.trusted_proxy_only is trusted_proxy_only
    assert mtls_mw.peer_is_trusted is peer_is_trusted
    assert spiffe_mw._trusted_proxy_only is trusted_proxy_only
    assert spiffe_mw._peer_is_trusted is peer_is_trusted


def test_trusted_proxy_gate(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.9.9.9")
    assert peer_is_trusted(_req("10.9.9.9")) is True     # the proxy
    assert peer_is_trusted(_req("10.9.9.10")) is False   # a direct client
