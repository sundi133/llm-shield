"""XFCC trust boundary: honor X-Forwarded-Client-Cert only from a trusted proxy.

Closes the direct-spoof bypass — a client reaching Shield directly must not be
able to set XFCC and impersonate a workload.
"""

import types

from core.oauth.spiffe_middleware import _peer_is_trusted, _trusted_proxy_only


def _req(peer):
    r = types.SimpleNamespace()
    r.client = types.SimpleNamespace(host=peer) if peer else None
    return r


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SHIELD_TRUSTED_PROXY_ONLY", raising=False)
    assert _trusted_proxy_only() is False


def test_enabled_flag(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    assert _trusted_proxy_only() is True


def test_exact_ip_trusted(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.0.0.5")
    assert _peer_is_trusted(_req("10.0.0.5")) is True
    assert _peer_is_trusted(_req("10.0.0.6")) is False


def test_cidr_trusted(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.0.0.0/24")
    assert _peer_is_trusted(_req("10.0.0.42")) is True
    assert _peer_is_trusted(_req("10.0.1.1")) is False


def test_no_config_trusts_nobody(monkeypatch):
    monkeypatch.delenv("SHIELD_TRUSTED_PROXY_IPS", raising=False)
    assert _peer_is_trusted(_req("10.0.0.5")) is False


def test_missing_peer_not_trusted(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.0.0.5")
    assert _peer_is_trusted(_req(None)) is False


def test_garbage_peer_not_trusted(monkeypatch):
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.0.0.5")
    assert _peer_is_trusted(_req("not-an-ip")) is False


# ── shared-secret boundary (fix for the client.host / XFF-spoof bypass) ──────

def _req_hdr(peer, headers=None):
    r = types.SimpleNamespace()
    r.client = types.SimpleNamespace(host=peer) if peer else None
    r.headers = headers or {}
    return r


def test_secret_required_when_configured(monkeypatch):
    from core.oauth.spiffe_middleware import _peer_is_trusted
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", "s3cr3t-token")
    monkeypatch.delenv("SHIELD_TRUSTED_PROXY_IPS", raising=False)
    # correct secret -> trusted (IP-independent)
    assert _peer_is_trusted(_req_hdr("1.2.3.4", {"X-Shield-Proxy-Token": "s3cr3t-token"})) is True
    # missing / wrong secret -> NOT trusted
    assert _peer_is_trusted(_req_hdr("1.2.3.4", {})) is False
    assert _peer_is_trusted(_req_hdr("1.2.3.4", {"X-Shield-Proxy-Token": "wrong"})) is False


def test_spoofed_xff_ip_without_secret_is_rejected(monkeypatch):
    """The regression: attacker spoofs client.host to the proxy IP but lacks the
    secret. With a secret configured, IP match alone must NOT grant trust."""
    from core.oauth.spiffe_middleware import _peer_is_trusted
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", "s3cr3t-token")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.0.0.5")   # the real proxy
    # attacker's request.client.host spoofed to 10.0.0.5 via X-Forwarded-For,
    # but no valid secret header:
    assert _peer_is_trusted(_req_hdr("10.0.0.5", {})) is False
    # only secret + IP together pass:
    assert _peer_is_trusted(_req_hdr("10.0.0.5", {"X-Shield-Proxy-Token": "s3cr3t-token"})) is True
    # secret ok but wrong source IP -> rejected
    assert _peer_is_trusted(_req_hdr("10.9.9.9", {"X-Shield-Proxy-Token": "s3cr3t-token"})) is False


def test_no_secret_falls_back_to_ip(monkeypatch):
    from core.oauth.spiffe_middleware import _peer_is_trusted
    monkeypatch.delenv("SHIELD_TRUSTED_PROXY_SECRET", raising=False)
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", "10.0.0.5")
    assert _peer_is_trusted(_req_hdr("10.0.0.5", {})) is True
    assert _peer_is_trusted(_req_hdr("10.0.0.6", {})) is False
