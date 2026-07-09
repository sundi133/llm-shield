"""Opt-in CORS (SHIELD_CORS_ALLOW_ORIGINS) and the /docs CSP exception.

The browser extension calls /guardrails/input and /v1/edge/policy-bundle from
a chrome-extension:// origin; without CORS headers every such call fails at
the browser's preflight check, and the extension's fail-open escalation then
silently allows everything. CORS stays OFF by default (no env var -> no
middleware -> byte-identical responses); deployments opt in with an explicit
origin list, never "*".

Separately, FastAPI's Swagger UI at /docs loads its assets from
cdn.jsdelivr.net, which the strict default CSP blocked -- /docs rendered
blank. Only /docs and /redoc get the relaxed CSP; all other routes keep the
strict one.
"""

import pytest
from starlette.testclient import TestClient

_EXT_ORIGIN = "chrome-extension://jjgakdilhkihhkaecagkkmlicioegjjd"


@pytest.fixture(autouse=True)
def _restore_config_singleton():
    """create_app() -> load_config() overwrites the config.schema.config
    module singleton; restore it so this file doesn't pollute other tests.
    NOTE: core.app is imported lazily inside _client, never at module level --
    several existing test files (test_auth.py, test_audit_authz.py) rely on
    being the first to import core.app inside a patch of
    config.schema.load_config, and a collection-time import here would
    silently defeat their patching for the whole session."""
    import config.schema as cs
    original = cs.config
    yield
    cs.config = original


def _client(monkeypatch, cors_origins=None):
    if cors_origins is None:
        monkeypatch.delenv("SHIELD_CORS_ALLOW_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("SHIELD_CORS_ALLOW_ORIGINS", cors_origins)
    monkeypatch.delenv("SHIELD_GUARD_MODEL_MODE", raising=False)
    from core.app import create_app
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# CORS default-off (regression guard)
# ---------------------------------------------------------------------------


def test_cors_off_by_default(monkeypatch):
    client = _client(monkeypatch)
    r = client.options(
        "/guardrails/input",
        headers={
            "Origin": _EXT_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-api-key",
        },
    )
    assert "access-control-allow-origin" not in r.headers


def test_cors_off_get_has_no_acao(monkeypatch):
    client = _client(monkeypatch)
    r = client.get("/health", headers={"Origin": _EXT_ORIGIN})
    assert "access-control-allow-origin" not in r.headers


# ---------------------------------------------------------------------------
# CORS opt-in
# ---------------------------------------------------------------------------


def test_preflight_allowed_for_configured_origin(monkeypatch):
    client = _client(monkeypatch, cors_origins=_EXT_ORIGIN)
    r = client.options(
        "/guardrails/input",
        headers={
            "Origin": _EXT_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-api-key",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == _EXT_ORIGIN
    allow_headers = r.headers.get("access-control-allow-headers", "").lower()
    assert "x-api-key" in allow_headers


def test_preflight_policy_bundle(monkeypatch):
    client = _client(monkeypatch, cors_origins=_EXT_ORIGIN)
    r = client.options(
        "/v1/edge/policy-bundle",
        headers={
            "Origin": _EXT_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-api-key",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == _EXT_ORIGIN


def test_preflight_rejects_unlisted_origin(monkeypatch):
    client = _client(monkeypatch, cors_origins=_EXT_ORIGIN)
    r = client.options(
        "/guardrails/input",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.headers.get("access-control-allow-origin") != "https://evil.example.com"


def test_actual_response_carries_acao_when_opted_in(monkeypatch):
    client = _client(monkeypatch, cors_origins=_EXT_ORIGIN)
    r = client.get("/health", headers={"Origin": _EXT_ORIGIN})
    assert r.headers.get("access-control-allow-origin") == _EXT_ORIGIN


def test_cors_never_wildcards_credential_headers(monkeypatch):
    """Even opted in, the middleware must echo the configured origin, not '*'
    -- /guardrails/input is tenant-key-authenticated."""
    client = _client(monkeypatch, cors_origins=_EXT_ORIGIN)
    r = client.options(
        "/guardrails/input",
        headers={
            "Origin": _EXT_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.headers["access-control-allow-origin"] == _EXT_ORIGIN


# ---------------------------------------------------------------------------
# /docs CSP exception
# ---------------------------------------------------------------------------


def test_docs_csp_allows_swagger_cdn(monkeypatch):
    client = _client(monkeypatch)
    r = client.get("/docs")
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy", "")
    assert "cdn.jsdelivr.net" in csp


def test_non_docs_routes_keep_strict_csp(monkeypatch):
    client = _client(monkeypatch)
    r = client.get("/health")
    csp = r.headers.get("content-security-policy", "")
    assert "cdn.jsdelivr.net" not in csp
    assert "default-src 'self'" in csp


def test_docs_csp_still_denies_framing(monkeypatch):
    client = _client(monkeypatch)
    r = client.get("/docs")
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp
    assert r.headers.get("x-frame-options") == "DENY"
