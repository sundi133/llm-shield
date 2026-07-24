"""Unit tests for the modular workload-identity provider layer."""

import types
from unittest.mock import patch

import pytest

from core.workload_identity.base import WorkloadIdentity
from core.workload_identity.providers import (
    AdminKeyProvider,
    MTLSProvider,
    SpiffeProvider,
)
from core.workload_identity.registry import enabled_providers, resolve_workload_identity


def _req(headers=None, **state):
    """A minimal stand-in for a Starlette Request: .headers + .state."""
    r = types.SimpleNamespace()
    r.headers = headers or {}
    r.state = types.SimpleNamespace(**state)
    return r


# ── providers ──────────────────────────────────────────────────────────────

def test_admin_key_valid(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "s3cret")
    ident = AdminKeyProvider().verify(_req({"X-Admin-Key": "s3cret"}))
    assert ident and ident.provider == "admin_key" and ident.trust_level == "medium"


def test_admin_key_wrong(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "s3cret")
    assert AdminKeyProvider().verify(_req({"X-Admin-Key": "nope"})) is None


def test_admin_key_unset(monkeypatch):
    monkeypatch.delenv("SHIELD_ADMIN_KEY", raising=False)
    assert AdminKeyProvider().verify(_req({"X-Admin-Key": "anything"})) is None


def test_spiffe_reads_middleware_state():
    req = _req(spiffe_identity={"user_sub": "spiffe://d/agent/x", "trust_level": "high", "agent_id": "x"})
    ident = SpiffeProvider().verify(req)
    assert ident.provider == "spiffe" and ident.subject == "spiffe://d/agent/x"
    assert ident.trust_level == "high"


def test_spiffe_absent():
    assert SpiffeProvider().verify(_req()) is None


def test_mtls_reads_middleware_state():
    ident = MTLSProvider().verify(_req(mtls_identity={"subject": "CN=bot", "trust_level": "high"}))
    assert ident.provider == "mtls" and ident.subject == "CN=bot"


# ── registry ───────────────────────────────────────────────────────────────

def test_default_provider_order(monkeypatch):
    monkeypatch.delenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", raising=False)
    names = [p.name for p in enabled_providers()]
    # mtls is NOT in the default (header-spoofable without the proxy guard).
    assert names == ["admin_key", "spiffe"]


def test_config_selects_and_orders(monkeypatch):
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "spiffe,admin_key")
    assert [p.name for p in enabled_providers()] == ["spiffe", "admin_key"]


def test_unknown_provider_skipped_then_fallback(monkeypatch):
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "bogus")
    assert [p.name for p in enabled_providers()] == ["admin_key"]  # fallback


def test_first_match_wins(monkeypatch):
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "spiffe,mtls")
    req = _req(
        spiffe_identity={"user_sub": "spiffe://d/a", "trust_level": "high"},
        mtls_identity={"subject": "CN=bot"},
    )
    ident = resolve_workload_identity(req)
    assert ident.provider == "spiffe"  # earlier in the list


def test_resolve_none_when_nothing(monkeypatch):
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "spiffe,mtls")
    assert resolve_workload_identity(_req()) is None


def test_broken_provider_does_not_bypass_or_raise(monkeypatch):
    class Boom:
        name = "boom"

        def verify(self, request):
            raise RuntimeError("kaboom")

    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "boom_only")
    with patch.dict("core.workload_identity.registry._REGISTRY", {"boom_only": Boom}):
        # provider raises -> treated as no-match -> None, never propagates
        assert resolve_workload_identity(_req()) is None


def test_admin_key_end_to_end(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "k")
    monkeypatch.delenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", raising=False)
    assert resolve_workload_identity(_req({"X-Admin-Key": "k"})).provider == "admin_key"
    assert resolve_workload_identity(_req({"X-Admin-Key": "x"})) is None


# ── oidc_sa provider ─────────────────────────────────────────────────────────

def _rsa_jwt(claims, kid="k1"):
    """Sign a JWT with a throwaway RSA key; return (token, public_key)."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = pyjwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})
    return token, key.public_key()


def _bearer(token):
    return _req({"Authorization": f"Bearer {token}"})


def test_oidc_sa_valid(monkeypatch):
    import datetime
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://kube.local")
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "shield")
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    token, pub = _rsa_jwt({"iss": "https://kube.local", "sub": "system:serviceaccount:ns:bot",
                           "aud": "shield", "exp": exp})
    with patch("core.workload_identity.providers._resolve_signing_key", return_value=pub):
        ident = OIDCServiceAccountProvider().verify(_bearer(token))
    assert ident and ident.provider == "oidc_sa"
    assert ident.subject == "system:serviceaccount:ns:bot" and ident.trust_level == "high"


def test_oidc_sa_untrusted_issuer(monkeypatch):
    import datetime
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://trusted")
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "shield")
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    token, pub = _rsa_jwt({"iss": "https://evil", "sub": "x", "aud": "shield", "exp": exp})
    with patch("core.workload_identity.providers._resolve_signing_key", return_value=pub):
        assert OIDCServiceAccountProvider().verify(_bearer(token)) is None


def test_oidc_sa_wrong_audience(monkeypatch):
    import datetime
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://kube.local")
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "shield")
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    token, pub = _rsa_jwt({"iss": "https://kube.local", "sub": "x", "aud": "other", "exp": exp})
    with patch("core.workload_identity.providers._resolve_signing_key", return_value=pub):
        assert OIDCServiceAccountProvider().verify(_bearer(token)) is None


def test_oidc_sa_expired(monkeypatch):
    import datetime
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://kube.local")
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "shield")
    exp = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    token, pub = _rsa_jwt({"iss": "https://kube.local", "sub": "x", "aud": "shield", "exp": exp})
    with patch("core.workload_identity.providers._resolve_signing_key", return_value=pub):
        assert OIDCServiceAccountProvider().verify(_bearer(token)) is None


def test_oidc_sa_no_bearer(monkeypatch):
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://kube.local")
    assert OIDCServiceAccountProvider().verify(_req()) is None


def test_oidc_sa_disabled_without_issuers(monkeypatch):
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.delenv("SHIELD_WORKLOAD_OIDC_ISSUERS", raising=False)
    assert OIDCServiceAccountProvider().verify(_bearer("x.y.z")) is None


def test_oidc_sa_requires_audience(monkeypatch):
    """Audience is mandatory: without it, any signed token from the issuer would
    pass, so the provider refuses rather than silently accept."""
    import datetime
    from core.workload_identity.providers import OIDCServiceAccountProvider
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "https://kube.local")
    monkeypatch.delenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", raising=False)
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    token, pub = _rsa_jwt({"iss": "https://kube.local", "sub": "x", "aud": "anything", "exp": exp})
    with patch("core.workload_identity.providers._resolve_signing_key", return_value=pub):
        assert OIDCServiceAccountProvider().verify(_bearer(token)) is None
