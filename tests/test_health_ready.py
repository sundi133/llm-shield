"""GET /health/ready on both planes (docs/specs/onprem-release-bundle.md, task 1b).

When Redis is configured but unreachable the stores fall back to per-process
memory, so a pod keeps serving from a store no other pod sees. Readiness says
so (503), and Kubernetes takes the pod out of the Service. /health stays the
liveness check and never touches Redis.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import storage.tenant_store as ts

LIVE_URL = os.environ.get("SHIELD_TEST_REDIS_URL", "").strip()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ("REDIS_URL", "UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(ts, "_ready_client", None)
    monkeypatch.setattr(ts, "_ready_client_url", "")


def _forbid_app_client(monkeypatch):
    """The probe must never go through the app's client (no socket timeouts).

    Patched only around redis_ready() calls, never while apps are built:
    a module first imported during the patch would keep the stand-in for the
    rest of the run (`from storage.tenant_store import _get_redis`)."""
    def _no(*a, **k):
        raise AssertionError("redis_ready must not call _get_redis()")
    monkeypatch.setattr(ts, "_get_redis", _no)


@pytest.mark.parametrize("env", [
    {},
    {"REDIS_URL": "redis://127.0.0.1:1/0"},
])
def test_probe_never_uses_the_app_client(monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    _forbid_app_client(monkeypatch)
    ts.redis_ready()        # would raise if it went through _get_redis()


def test_probe_never_uses_the_app_client_on_upstash(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json={"result": "PONG"}))
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://example.upstash.io")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "tok")
    _forbid_app_client(monkeypatch)
    assert ts.redis_ready() is True


def _data_plane():
    import api.routes_health as h
    app = FastAPI()
    app.include_router(h.router)
    return TestClient(app)


# ── the check itself ─────────────────────────────────────────────────────────

def test_no_redis_configured_is_ready():
    assert ts.redis_ready() is None
    r = _data_plane().get("/health/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready" and r.json()["redis"] == "not_configured"


def test_unreachable_redis_is_not_ready_fast_and_names_nothing(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")      # nothing listens there
    start = time.monotonic()
    r = _data_plane().get("/health/ready")
    assert time.monotonic() - start < ts.READY_TIMEOUT_S * 2 + 1
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready" and body["reason"] == "redis_unreachable"
    assert "127.0.0.1" not in r.text and "6379" not in r.text


def test_reachable_redis_uses_its_own_client_with_timeouts(monkeypatch):
    import redis
    seen = {}

    class FakeRedis:
        def ping(self):
            return True

    def from_url(url, **kw):
        seen.update(kw, url=url)
        return FakeRedis()

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(from_url))
    monkeypatch.setenv("REDIS_URL", "redis://redis:6379/0")
    r = _data_plane().get("/health/ready")
    assert r.status_code == 200 and r.json()["redis"] == "ok"
    assert seen["socket_connect_timeout"] == ts.READY_TIMEOUT_S
    assert seen["socket_timeout"] == ts.READY_TIMEOUT_S


def test_probe_client_is_reused_until_the_url_changes(monkeypatch):
    import redis
    made = []

    class FakeRedis:
        def ping(self):
            return True

    monkeypatch.setattr(redis.Redis, "from_url",
                        staticmethod(lambda url, **kw: made.append(url) or FakeRedis()))
    monkeypatch.setenv("REDIS_URL", "redis://a:6379/0")
    ts.redis_ready(); ts.redis_ready()
    monkeypatch.setenv("REDIS_URL", "redis://b:6379/0")
    ts.redis_ready()
    assert made == ["redis://a:6379/0", "redis://b:6379/0"]


@pytest.mark.parametrize("reply, ok", [
    ((200, {"result": "PONG"}), True),
    ((401, {"error": "Unauthorized"}), False),
    ((200, {"result": "nope"}), False),
])
def test_upstash_rest_ping(monkeypatch, reply, ok):
    calls = []

    def fake_get(url, timeout, headers):
        calls.append((url, timeout, headers))
        return httpx.Response(reply[0], json=reply[1])

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://example.upstash.io/")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "tok")
    monkeypatch.setenv("REDIS_URL", "redis://ignored:6379/0")   # Upstash wins, like _get_redis()
    assert ts.redis_ready() is ok
    assert calls == [("https://example.upstash.io/ping", ts.READY_TIMEOUT_S,
                      {"Authorization": "Bearer tok"})]


def test_upstash_network_error_is_not_ready(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectTimeout("slow")
    monkeypatch.setattr(httpx, "get", boom)
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://example.upstash.io")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "tok")
    assert ts.redis_ready() is False


def test_liveness_never_touches_redis(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    r = _data_plane().get("/health")
    assert r.status_code == 200 and r.json()["status"] == "healthy"


# ── reachable without credentials on both planes ─────────────────────────────

def test_skip_lists_name_the_path_exactly():
    from core.middleware import ShieldMiddleware
    from core.telemetry_middleware import TelemetryMiddleware
    assert "/health/ready" in ShieldMiddleware._SKIP_PATHS
    assert "/health/ready" in TelemetryMiddleware._SKIP_PATHS


def test_data_plane_answers_without_a_key_under_enforce(monkeypatch):
    monkeypatch.setenv("SHIELD_GUARD_REQUIRE_KEY", "enforce")
    from core.app import create_app
    r = TestClient(create_app()).get("/health/ready")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ready"


def test_admin_plane_answers_without_credentials(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    import admin_app
    c = TestClient(admin_app.create_admin_app())
    assert c.get("/health").status_code == 200
    r = c.get("/health/ready")
    assert r.status_code == 503 and r.json() == {"status": "not_ready", "reason": "redis_unreachable"}


# ── live ─────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not LIVE_URL, reason="set SHIELD_TEST_REDIS_URL to a throwaway Redis")
def test_live_redis_is_ready(monkeypatch):
    monkeypatch.setenv("REDIS_URL", LIVE_URL)
    r = _data_plane().get("/health/ready")
    assert r.status_code == 200 and r.json()["redis"] == "ok"
