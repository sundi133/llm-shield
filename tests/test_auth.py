"""Tests for API key authentication."""

import hashlib
import pytest
from unittest.mock import patch

from config.schema import ShieldConfig, AuthConfig
from core.auth import _extract_api_key, _validate_key


# --- Unit tests for key validation ---


def test_validate_plaintext_key_matches():
    assert _validate_key("my-secret-key", ["my-secret-key"]) is True


def test_validate_plaintext_key_no_match():
    assert _validate_key("wrong-key", ["my-secret-key"]) is False


def test_validate_hashed_key_matches():
    key = "my-secret-key"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    assert _validate_key(key, [f"sha256:{key_hash}"]) is True


def test_validate_hashed_key_no_match():
    key_hash = hashlib.sha256(b"other-key").hexdigest()
    assert _validate_key("wrong-key", [f"sha256:{key_hash}"]) is False


def test_validate_mixed_keys():
    """Test that validation works when config has both plaintext and hashed keys."""
    hashed = f"sha256:{hashlib.sha256(b'hashed-key').hexdigest()}"
    keys = ["plaintext-key", hashed]
    assert _validate_key("plaintext-key", keys) is True
    assert _validate_key("hashed-key", keys) is True
    assert _validate_key("unknown-key", keys) is False


def test_validate_empty_key_list():
    assert _validate_key("any-key", []) is False


# --- Integration tests with FastAPI TestClient ---


@pytest.fixture
def auth_config():
    """ShieldConfig with auth enabled and one test key."""
    return ShieldConfig(
        auth=AuthConfig(
            enabled=True,
            api_keys=["test-key-123"],
            public_paths=["/health", "/ping", "/docs", "/playground", "/static"],
        ),
    )


@pytest.fixture
def no_auth_config():
    """ShieldConfig with auth disabled."""
    return ShieldConfig(
        auth=AuthConfig(enabled=False),
    )


def _make_app(cfg):
    """Create app with a specific config, preventing load_config from overwriting."""
    import config.schema as cs
    original = cs.config
    # Set config before app creation so middleware sees it
    cs.config = cfg
    # Prevent load_config from overwriting
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        app = create_app()
    return app, original


@pytest.fixture
def app_with_auth(auth_config):
    """Create a test app with auth enabled."""
    import config.schema as cs
    app, original = _make_app(auth_config)
    yield app
    cs.config = original


@pytest.fixture
def app_without_auth(no_auth_config):
    """Create a test app with auth disabled."""
    import config.schema as cs
    app, original = _make_app(no_auth_config)
    yield app
    cs.config = original


def test_public_path_no_key_required(app_with_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.get("/health")
    assert resp.status_code == 200


def test_protected_path_rejected_without_key(app_with_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.get("/v1/shield/guardrails")
    assert resp.status_code == 401
    assert "Missing API key" in resp.json()["error"]


def test_protected_path_rejected_with_wrong_key(app_with_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.get(
        "/v1/shield/guardrails",
        headers={"Authorization": "Bearer wrong-key"},
    )
    assert resp.status_code == 403
    assert "Invalid API key" in resp.json()["error"]


def test_protected_path_allowed_with_bearer(app_with_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.get(
        "/v1/shield/guardrails",
        headers={"Authorization": "Bearer test-key-123"},
    )
    assert resp.status_code == 200


def test_protected_path_allowed_with_x_api_key(app_with_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.get(
        "/v1/shield/guardrails",
        headers={"X-API-Key": "test-key-123"},
    )
    assert resp.status_code == 200


def test_classify_requires_auth(app_with_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.post("/classify", json={"message": "hello"})
    assert resp.status_code == 401


def test_classify_with_valid_key(app_with_auth):
    """Classify endpoint works with valid key (will fail at LLM call, but auth passes)."""
    from starlette.testclient import TestClient
    client = TestClient(app_with_auth)
    resp = client.post(
        "/classify",
        json={"message": "hello"},
        headers={"Authorization": "Bearer test-key-123"},
    )
    # 500 is expected because LLM backend isn't running, but auth passed (not 401/403)
    assert resp.status_code == 500


def test_auth_disabled_allows_all(app_without_auth):
    from starlette.testclient import TestClient
    client = TestClient(app_without_auth)
    resp = client.get("/v1/shield/guardrails")
    assert resp.status_code == 200


def test_auth_enabled_no_keys_configured():
    """Auth enabled but no keys = server error."""
    import config.schema as cs
    broken_config = ShieldConfig(
        auth=AuthConfig(enabled=True, api_keys=[]),
    )
    app, original = _make_app(broken_config)
    try:
        from starlette.testclient import TestClient
        client = TestClient(app)
        resp = client.get("/v1/shield/guardrails")
        assert resp.status_code == 500
        assert "no API keys configured" in resp.json()["error"]
    finally:
        cs.config = original
