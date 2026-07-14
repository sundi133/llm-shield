"""GET /health exposes a build/commit marker so a deployed image is identifiable."""
import importlib

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _client(monkeypatch, **env):
    for k in ("SHIELD_BUILD_SHA", "RAILWAY_GIT_COMMIT_SHA"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import api.routes_health as h
    importlib.reload(h)  # BUILD_SHA is resolved at import
    app = FastAPI()
    app.include_router(h.router)
    return TestClient(app)


def test_health_includes_build_field(monkeypatch):
    c = _client(monkeypatch)
    body = c.get("/health").json()
    assert body["status"] == "healthy"
    assert body["build"] == "unknown"  # neither env set


def test_health_prefers_explicit_build_sha(monkeypatch):
    c = _client(monkeypatch, SHIELD_BUILD_SHA="abc123", RAILWAY_GIT_COMMIT_SHA="railwaysha")
    assert c.get("/health").json()["build"] == "abc123"


def test_health_falls_back_to_railway_sha(monkeypatch):
    c = _client(monkeypatch, RAILWAY_GIT_COMMIT_SHA="railwaysha")
    assert c.get("/health").json()["build"] == "railwaysha"


def test_ping_unchanged(monkeypatch):
    c = _client(monkeypatch)
    assert c.get("/ping").json() == {"status": "healthy"}
