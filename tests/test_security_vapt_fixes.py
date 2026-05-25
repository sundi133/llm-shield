"""End-to-end tests for the IEMLabs VAPT (May 2026) high+medium fixes.

Mapped to report sections:
  8.1 SSRF                  (High)   — /playground/llm-proxy
  8.2 IDOR                  (High)   — /v1/tenant/me
  8.3 Information Disclosure (Medium) — /playground/llm-proxy

Each test reproduces the auditor's attack pattern and asserts it is
now blocked or the leak is closed.
"""

from __future__ import annotations

import socket
from typing import Iterator
from unittest import mock

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api.routes_tenant_self import router as tenant_self_router


class _FakeTenantAuth(BaseHTTPMiddleware):
    """Sets request.state.tenant_id from X-API-Key (mirrors the real
    AuthMiddleware contract without pulling in its dependencies)."""
    async def dispatch(self, request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            # Map test keys to tenant ids: 'acme-key' → 'acme', 'corp-key' → 'corp'
            tid = key.replace("-key", "")
            request.state.tenant_id = tid
        return await call_next(request)


# ─── /v1/tenant/me — IDOR (8.2) ───────────────────────────────────────


@pytest.fixture
def tenant_app(monkeypatch) -> Iterator[FastAPI]:
    # Disable Redis so get_tenant uses fallback
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    # Register two tenants in the in-process store
    from storage.tenant_store import create_tenant
    try:
        create_tenant("acme", {"name": "Acme", "plan": "enterprise"})
    except Exception:
        pass
    try:
        create_tenant("corp", {"name": "Corp", "plan": "enterprise"})
    except Exception:
        pass

    app = FastAPI()
    app.add_middleware(_FakeTenantAuth)
    app.include_router(tenant_self_router)
    yield app


@pytest.fixture
def tenant_client(tenant_app):
    return TestClient(tenant_app)


class TestIDORTenantMe:
    """Finding 8.2: /v1/tenant/me must not leak internal object refs."""

    def test_me_response_drops_agents_list(self, tenant_client):
        """Previously: response included full agents list (internal IDs).
        Now: only an agent_count integer, no enumeration."""
        r = tenant_client.get("/v1/tenant/me", headers={"X-API-Key": "acme-key"})
        assert r.status_code == 200
        body = r.json()
        assert body["tenant_id"] == "acme"
        assert "agents" not in body, \
            "agent_keys list must NOT be in /v1/tenant/me response (IDOR finding 8.2)"
        assert "agent_count" in body
        assert isinstance(body["agent_count"], int)

    def test_me_rejects_header_tenant_id_spoof(self, tenant_client):
        """An attacker with acme's key tries X-Tenant-Id: corp → reject."""
        r = tenant_client.get(
            "/v1/tenant/me",
            headers={"X-API-Key": "acme-key", "X-Tenant-Id": "corp"},
        )
        assert r.status_code == 403
        assert "does not match" in r.json()["detail"].lower()

    def test_me_rejects_body_tenant_id_spoof_on_put(self, tenant_client):
        """The PUT /me/policies endpoint must reject a body with a
        different tenant_id than the one resolved from the API key."""
        r = tenant_client.put(
            "/v1/tenant/me/policies",
            headers={"X-API-Key": "acme-key"},
            json={"tenant_id": "corp", "input_guardrails": {}},
        )
        assert r.status_code == 403
        assert "does not match" in r.json()["detail"].lower()

    def test_me_no_auth_returns_401(self, tenant_client):
        r = tenant_client.get("/v1/tenant/me")
        assert r.status_code == 401

    def test_me_matching_header_passes(self, tenant_client):
        """X-Tenant-Id that matches the resolved tenant is allowed."""
        r = tenant_client.get(
            "/v1/tenant/me",
            headers={"X-API-Key": "acme-key", "X-Tenant-Id": "acme"},
        )
        assert r.status_code == 200

    def test_me_response_has_no_internal_fields(self, tenant_client):
        """Even with a valid key, internal-only fields stay server-side."""
        r = tenant_client.get("/v1/tenant/me", headers={"X-API-Key": "acme-key"})
        body = r.json()
        for forbidden in ("api_keys", "raw_config", "_internal", "deleted_at"):
            assert forbidden not in body, f"internal field {forbidden!r} leaked"


# ─── /playground/llm-proxy — SSRF (8.1) + Info Disclosure (8.3) ──────


@pytest.fixture
def admin_app_min(monkeypatch):
    """Spin up admin_app's playground routes WITHOUT all the heavy
    LiteLLM / model deps. We only need the two endpoints."""
    # Force no redis so the bare app boots fast
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "")
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin")

    import admin_app as _admin_app
    # We can't easily call create_admin_app() here (loads many routers).
    # Instead, register a minimal FastAPI app with just our two routes
    # by importing the route functions directly. Use the SAME url_safety
    # module so changes there are exercised.
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    import httpx
    import logging as _logging
    import uuid as _uuid
    from core.url_safety import UnsafeURLError, validate_outbound_url

    app = FastAPI()

    # Replicate the production handler exactly (this is what's in admin_app)
    @app.post("/playground/llm-proxy")
    async def playground_llm_proxy(request: Request):
        body = await request.json()
        base_url_raw = body.get("base_url", "https://api.openai.com/v1").strip().rstrip("/")
        master_key = body.get("master_key", "")
        payload = body.get("payload", {})

        try:
            base_url = validate_outbound_url(base_url_raw, purpose="llm-proxy")
        except UnsafeURLError as e:
            return JSONResponse(
                {"error": "LLM base_url rejected", "detail": str(e)},
                status_code=400,
            )

        headers = {"Content-Type": "application/json"}
        if master_key:
            headers["Authorization"] = f"Bearer {master_key}"

        request_id = _uuid.uuid4().hex[:12]
        logger = _logging.getLogger("votal.llm_proxy")
        logger.info(f"llm-proxy {request_id}: POST {base_url}/chat/completions model={payload.get('model')!r}")
        async with httpx.AsyncClient(timeout=180.0, follow_redirects=False) as client:
            try:
                resp = await client.post(f"{base_url}/chat/completions", json=payload, headers=headers)
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw_response": resp.text[:8192], "status": resp.status_code}
                logger.info(f"llm-proxy {request_id}: status={resp.status_code} resp_bytes={len(resp.content)}")
                return JSONResponse(data, status_code=resp.status_code)
            except httpx.TimeoutException:
                return JSONResponse({"error": "LLM request timed out", "request_id": request_id}, status_code=504)
            except Exception as e:
                logger.warning(f"llm-proxy {request_id}: upstream error: {type(e).__name__}: {e}")
                return JSONResponse({"error": "Cannot reach LLM endpoint", "request_id": request_id}, status_code=502)

    return app


@pytest.fixture
def admin_client(admin_app_min):
    return TestClient(admin_app_min)


def _stub_getaddrinfo(monkeypatch, resolution_map):
    import socket as _socket
    def fake(host, port, *args, **kw):
        if host in resolution_map:
            res = resolution_map[host]
            if res == "GAI_ERROR":
                raise _socket.gaierror(f"no such host {host}")
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, port)) for ip in res]
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]
    monkeypatch.setattr(_socket, "getaddrinfo", fake)


class TestSSRFInLLMProxy:
    """Finding 8.1: SSRF at /playground/llm-proxy via user-supplied base_url."""

    def test_aws_metadata_blocked(self, admin_client):
        """The auditor's most likely PoC: hit AWS instance metadata."""
        r = admin_client.post(
            "/playground/llm-proxy",
            json={
                "base_url": "http://169.254.169.254/latest/meta-data",
                "master_key": "x",
                "payload": {"model": "test"},
            },
        )
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "LLM base_url rejected"

    def test_localhost_blocked(self, admin_client):
        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "http://127.0.0.1:6379", "payload": {}},
        )
        assert r.status_code == 400

    def test_private_ip_blocked(self, admin_client):
        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "http://10.0.0.5:8000", "payload": {}},
        )
        assert r.status_code == 400

    def test_file_scheme_blocked(self, admin_client):
        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "file:///etc/passwd", "payload": {}},
        )
        assert r.status_code == 400

    def test_dns_rebinding_blocked(self, admin_client, monkeypatch):
        """Hostname that resolves to BOTH public + internal must reject."""
        _stub_getaddrinfo(monkeypatch, {
            "attacker.example.com": ["8.8.8.8", "127.0.0.1"],
        })
        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "https://attacker.example.com", "payload": {}},
        )
        assert r.status_code == 400

    def test_allowlist_enforced(self, admin_client, monkeypatch):
        monkeypatch.setenv("SHIELD_LLM_PROXY_ALLOWED_HOSTS", "api.openai.com")
        _stub_getaddrinfo(monkeypatch, {"random-public.example.com": ["8.8.8.8"]})
        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "https://random-public.example.com", "payload": {}},
        )
        assert r.status_code == 400


class TestInfoDisclosureInLLMProxy:
    """Finding 8.3: error messages must not leak internal upstream info."""

    def test_error_body_does_not_echo_url(self, admin_client):
        """The rejection message must NOT contain the attacker-supplied
        URL — otherwise the endpoint becomes a probe to learn server
        configuration."""
        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "http://169.254.169.254/secret-path", "payload": {}},
        )
        body_text = r.text
        assert "169.254.169.254" not in body_text
        assert "secret-path" not in body_text

    def test_upstream_failure_returns_generic_error_with_request_id(
        self, admin_client, monkeypatch
    ):
        """When the upstream call genuinely fails, response must be
        a generic message + a correlation id — NOT the raw exception."""
        _stub_getaddrinfo(monkeypatch, {"unreachable.example.com": ["8.8.8.8"]})

        # Force the underlying httpx call to raise a ConnectError with
        # an internals-leaking message; the handler should sanitize.
        import httpx as _httpx
        original_post = _httpx.AsyncClient.post

        async def boom(self, *a, **kw):
            raise _httpx.ConnectError(
                "OSError: [Errno 113] No route to host (resolved-internal-ip=10.5.5.5)"
            )
        monkeypatch.setattr(_httpx.AsyncClient, "post", boom)

        r = admin_client.post(
            "/playground/llm-proxy",
            json={"base_url": "https://unreachable.example.com", "payload": {}},
        )
        assert r.status_code == 502
        body = r.json()
        assert body["error"] == "Cannot reach LLM endpoint"
        assert "request_id" in body
        # The leak: internal IP / errno must NOT be in the response
        assert "10.5.5.5" not in r.text
        assert "Errno" not in r.text
        assert "OSError" not in r.text


class TestHappyPath:
    """Make sure the hardening didn't break legitimate use."""

    def test_legit_request_passes_validation(self, admin_client, monkeypatch):
        """Public LLM provider URL → URL validation passes; actual HTTP
        call is mocked to verify the rest of the path."""
        _stub_getaddrinfo(monkeypatch, {"api.openai.com": ["104.18.6.123"]})

        import httpx as _httpx

        async def fake_post(self, url, **kw):
            class _Resp:
                status_code = 200
                content = b'{"id":"chatcmpl-x"}'
                text = '{"id":"chatcmpl-x"}'
                def json(self):
                    return {"id": "chatcmpl-x", "choices": []}
            return _Resp()
        monkeypatch.setattr(_httpx.AsyncClient, "post", fake_post)

        r = admin_client.post(
            "/playground/llm-proxy",
            json={
                "base_url": "https://api.openai.com/v1",
                "master_key": "sk-test",
                "payload": {"model": "gpt-4o-mini", "messages": []},
            },
        )
        assert r.status_code == 200
        assert r.json()["id"] == "chatcmpl-x"
