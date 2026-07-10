"""hCaptcha verification hardening (Pepper CWE-288, captcha bypass).

Keeps the deliberate "disabled when unconfigured" behavior (non-breaking for
deployments that don't use captcha) but makes the configured path robust:
bounded upstream call, fail-closed on error/malformed response, strict
success check, and optional hostname pinning.
"""

import pytest
from starlette.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("SHIELD_GUARD_MODEL_MODE", raising=False)
    monkeypatch.delenv("LLM_BACKEND_URL", raising=False)
    from core.app import create_app
    import config.schema as cs
    original = cs.config
    try:
        yield TestClient(create_app())
    finally:
        cs.config = original


class _StubClient:
    """Async context-manager stub for httpx.AsyncClient."""

    def __init__(self, body=None, raises=False):
        self._body = body
        self._raises = raises

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        if self._raises:
            raise RuntimeError("timeout")

        class _R:
            def __init__(self, b):
                self._b = b

            def json(self):
                return self._b

        return _R(self._body)


def test_captcha_disabled_when_unconfigured(client, monkeypatch):
    monkeypatch.delenv("HCAPTCHA_SECRET_KEY", raising=False)
    r = client.post("/verify-captcha", json={"token": ""})
    assert r.status_code == 200
    assert r.json()["success"] is True


def test_captcha_missing_token_is_400(client, monkeypatch):
    monkeypatch.setenv("HCAPTCHA_SECRET_KEY", "secret")
    r = client.post("/verify-captcha", json={})
    assert r.status_code == 400


def test_captcha_success_true(client, monkeypatch):
    monkeypatch.setenv("HCAPTCHA_SECRET_KEY", "secret")
    monkeypatch.delenv("HCAPTCHA_EXPECTED_HOSTNAME", raising=False)
    monkeypatch.setattr("core.app.httpx.AsyncClient", _StubClient(body={"success": True}))
    r = client.post("/verify-captcha", json={"token": "t"})
    assert r.status_code == 200


def test_captcha_failure_is_403(client, monkeypatch):
    monkeypatch.setenv("HCAPTCHA_SECRET_KEY", "secret")
    monkeypatch.setattr("core.app.httpx.AsyncClient", _StubClient(body={"success": False}))
    r = client.post("/verify-captcha", json={"token": "t"})
    assert r.status_code == 403


def test_captcha_upstream_error_fails_closed(client, monkeypatch):
    """A slow/unreachable hCaptcha must NOT be treated as a valid token."""
    monkeypatch.setenv("HCAPTCHA_SECRET_KEY", "secret")
    monkeypatch.setattr("core.app.httpx.AsyncClient", _StubClient(raises=True))
    r = client.post("/verify-captcha", json={"token": "t"})
    assert r.status_code == 503
    assert r.json()["success"] is False


def test_captcha_hostname_mismatch_is_403(client, monkeypatch):
    monkeypatch.setenv("HCAPTCHA_SECRET_KEY", "secret")
    monkeypatch.setenv("HCAPTCHA_EXPECTED_HOSTNAME", "shield.votal.ai")
    monkeypatch.setattr(
        "core.app.httpx.AsyncClient",
        _StubClient(body={"success": True, "hostname": "evil.example.com"}),
    )
    r = client.post("/verify-captcha", json={"token": "t"})
    assert r.status_code == 403
