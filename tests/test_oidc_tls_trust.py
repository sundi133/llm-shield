"""Outbound TLS trust, so OIDC works against an on-prem IdP.

httpx does not use the system trust store — it builds its context from the
bundled certifi CAs. An on-prem Keycloak or ADFS behind the organisation's own
CA therefore fails every discovery and JWKS fetch with "certificate verify
failed", on exactly the deployments this product is sold into, and the error
never mentions the setting that fixes it.

The two tests that matter are `test_both_outbound_calls_pass_verify` — fixing
one call just moves the failure — and `test_a_missing_bundle_is_a_clear_error`,
because Python's default behaviour is to ignore a bad CA path and fall back to
the system store, turning a typo into a TLS mystery.

Spec: docs/spec-portal-sso.md (on-prem)
"""
import ssl

import pytest

from core.oauth import tls_trust


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("SHIELD_OIDC_CA_BUNDLE", raising=False)
    tls_trust._context_cache.clear()


@pytest.fixture
def ca_file(tmp_path):
    """A real, loadable CA bundle: the certifi one, which is guaranteed to
    parse. A file of arbitrary bytes would fail for the wrong reason."""
    import certifi
    p = tmp_path / "internal-ca.pem"
    p.write_bytes(open(certifi.where(), "rb").read())
    return str(p)


# ── default behaviour is unchanged ───────────────────────────────────────


def test_no_bundle_means_default_trust(clean):
    assert tls_trust.httpx_verify() is True
    assert tls_trust.ssl_context() is None


def test_an_empty_value_is_treated_as_unset(monkeypatch):
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", "   ")
    assert tls_trust.httpx_verify() is True


# ── a configured bundle is used ──────────────────────────────────────────


def test_a_configured_bundle_is_passed_to_httpx(monkeypatch, ca_file):
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", ca_file)
    assert tls_trust.httpx_verify() == ca_file


def test_a_configured_bundle_builds_an_ssl_context(monkeypatch, ca_file):
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", ca_file)
    ctx = tls_trust.ssl_context()
    assert isinstance(ctx, ssl.SSLContext)


def test_the_context_is_cached_per_path(monkeypatch, ca_file):
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", ca_file)
    assert tls_trust.ssl_context() is tls_trust.ssl_context()


# ── failures must be legible ─────────────────────────────────────────────


def test_a_missing_bundle_is_a_clear_error(monkeypatch):
    """Python's ssl silently ignores a bad SSL_CERT_FILE and falls back to the
    system store, so a typo presents as "certificate verify failed" with
    nothing pointing at the path. Refusing loudly is the whole point."""
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", "/nonexistent/internal-ca.pem")
    with pytest.raises(tls_trust.CABundleError) as e:
        tls_trust.httpx_verify()
    assert "does not exist" in str(e.value)
    assert "SHIELD_OIDC_CA_BUNDLE" in str(e.value)


def test_a_directory_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", str(tmp_path))
    with pytest.raises(tls_trust.CABundleError):
        tls_trust.httpx_verify()


def test_an_unreadable_bundle_is_refused(monkeypatch, tmp_path):
    import os
    p = tmp_path / "ca.pem"
    p.write_text("x")
    os.chmod(p, 0o000)
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", str(p))
    try:
        if os.access(str(p), os.R_OK):
            pytest.skip("running as root — chmod does not restrict reads")
        with pytest.raises(tls_trust.CABundleError) as e:
            tls_trust.httpx_verify()
        assert "readable" in str(e.value)
    finally:
        os.chmod(p, 0o600)


def test_verification_is_never_disabled():
    """An on-prem deployment that cannot verify its own IdP has a config
    problem. Turning verification off would hide it behind a working login."""
    import inspect
    src = inspect.getsource(tls_trust)
    assert "verify=False" not in src
    assert "CERT_NONE" not in src
    assert "check_hostname = False" not in src


# ── both call sites, not just one ────────────────────────────────────────


def test_both_outbound_calls_pass_verify():
    """Discovery and JWKS are separate fetches. Fixing one moves the failure
    from login to token validation instead of removing it."""
    import inspect
    from core.oauth import oidc_client, jwks_cache

    for mod in (oidc_client, jwks_cache):
        for line in inspect.getsource(mod).splitlines():
            if "httpx.AsyncClient(" in line:
                assert "verify=" in line, (
                    f"{mod.__name__}: {line.strip()} does not set verify=, so "
                    f"it ignores SHIELD_OIDC_CA_BUNDLE and fails behind a "
                    f"private CA")


@pytest.mark.parametrize("issuer,expected", [
    ("https://keycloak.internal/realms/acme", True),
    ("https://sso.corp/realms/acme", True),
    ("https://keycloak/realms/acme", True),
    ("https://auth.example.com/realms/acme", False),
])
def test_an_internal_looking_issuer_hints_at_the_setting(monkeypatch, caplog,
                                                         issuer, expected):
    """A hint, not a check: it turns the commonest on-prem failure from a bare
    TLS error into a line naming the variable to set."""
    import logging
    with caplog.at_level(logging.INFO, logger="votal.oauth.tls"):
        tls_trust.warn_if_unset_and_issuer_is_private(issuer)
    assert ("SHIELD_OIDC_CA_BUNDLE" in caplog.text) is expected


def test_no_hint_once_the_bundle_is_configured(monkeypatch, caplog, ca_file):
    import logging
    monkeypatch.setenv("SHIELD_OIDC_CA_BUNDLE", ca_file)
    with caplog.at_level(logging.INFO, logger="votal.oauth.tls"):
        tls_trust.warn_if_unset_and_issuer_is_private("https://kc.internal/x")
    assert "SHIELD_OIDC_CA_BUNDLE" not in caplog.text


# ── air gap ──────────────────────────────────────────────────────────────


def test_nothing_in_the_oidc_path_contacts_a_vendor_endpoint():
    """The only hosts reached are the issuer configured for the tenant. A
    hardcoded vendor URL would break an air-gapped deployment and would not
    show up in any functional test."""
    import inspect
    from core.oauth import oidc_client, jwks_cache

    banned = ("votal.ai", "amazonaws.com", "googleapis.com", "okta.com",
              "microsoftonline.com", "auth0.com")
    for mod in (oidc_client, jwks_cache, tls_trust):
        src = inspect.getsource(mod)
        for host in banned:
            assert host not in src, f"{mod.__name__} references {host}"
