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
