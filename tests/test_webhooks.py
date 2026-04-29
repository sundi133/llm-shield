"""Tests for Webhook / Event Notifications feature."""

import pytest
import json
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

from storage.webhook_store import (
    create_webhook,
    get_webhooks,
    get_webhook,
    update_webhook,
    delete_webhook,
    get_webhooks_for_event,
)
from core.webhook_dispatcher import dispatch_event, _sign_payload


@pytest.fixture(autouse=True)
def clear_fallback():
    """Clear webhook entries between tests."""
    from storage.tenant_store import _fallback_store
    keys_to_remove = [k for k in _fallback_store if k.startswith("webhooks:")]
    for k in keys_to_remove:
        del _fallback_store[k]
    yield
    keys_to_remove = [k for k in _fallback_store if k.startswith("webhooks:")]
    for k in keys_to_remove:
        del _fallback_store[k]


@patch("storage.webhook_store._get_redis", return_value=None)
class TestWebhookStore:
    """Test webhook CRUD storage."""

    def test_create_webhook(self, mock_redis):
        wh = create_webhook("t1", {
            "url": "https://example.com/hook",
            "secret": "s3cr3t",
            "events": ["guardrail_blocked"],
        })
        assert wh["url"] == "https://example.com/hook"
        assert "webhook_id" in wh
        assert wh["tenant_id"] == "t1"
        assert wh["enabled"] is True

    def test_get_webhooks(self, mock_redis):
        create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})
        create_webhook("t1", {"url": "https://b.com", "events": ["tool_disabled"]})

        webhooks = get_webhooks("t1")
        assert len(webhooks) == 2

    def test_get_webhook_by_id(self, mock_redis):
        wh = create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})
        found = get_webhook("t1", wh["webhook_id"])
        assert found is not None
        assert found["url"] == "https://a.com"

    def test_get_webhook_not_found(self, mock_redis):
        found = get_webhook("t1", "nonexistent")
        assert found is None

    def test_update_webhook(self, mock_redis):
        wh = create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})
        updated = update_webhook("t1", wh["webhook_id"], {"url": "https://b.com"})
        assert updated["url"] == "https://b.com"
        assert "updated_at" in updated

    def test_update_webhook_not_found(self, mock_redis):
        result = update_webhook("t1", "nonexistent", {"url": "https://b.com"})
        assert result is None

    def test_delete_webhook(self, mock_redis):
        wh = create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})
        assert delete_webhook("t1", wh["webhook_id"]) is True
        assert get_webhooks("t1") == []

    def test_delete_webhook_not_found(self, mock_redis):
        assert delete_webhook("t1", "nonexistent") is False

    def test_get_webhooks_for_event(self, mock_redis):
        create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})
        create_webhook("t1", {"url": "https://b.com", "events": ["tool_disabled"]})
        create_webhook("t1", {"url": "https://c.com", "events": ["guardrail_blocked", "tool_disabled"]})

        blocked_hooks = get_webhooks_for_event("t1", "guardrail_blocked")
        assert len(blocked_hooks) == 2

        disabled_hooks = get_webhooks_for_event("t1", "tool_disabled")
        assert len(disabled_hooks) == 2

    def test_get_webhooks_for_event_respects_enabled(self, mock_redis):
        create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"], "enabled": False})
        create_webhook("t1", {"url": "https://b.com", "events": ["guardrail_blocked"], "enabled": True})

        hooks = get_webhooks_for_event("t1", "guardrail_blocked")
        assert len(hooks) == 1
        assert hooks[0]["url"] == "https://b.com"

    def test_tenant_isolation(self, mock_redis):
        create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})
        create_webhook("t2", {"url": "https://b.com", "events": ["guardrail_blocked"]})

        assert len(get_webhooks("t1")) == 1
        assert len(get_webhooks("t2")) == 1


class TestWebhookDispatcher:
    """Test webhook dispatch logic."""

    def test_sign_payload(self):
        payload = b'{"event": "test"}'
        sig = _sign_payload(payload, "secret123")
        assert len(sig) == 64  # SHA256 hex

    @pytest.mark.asyncio
    @patch("storage.webhook_store._get_redis", return_value=None)
    @patch("core.webhook_dispatcher.httpx.AsyncClient")
    async def test_dispatch_event_sends_to_webhooks(self, mock_client_cls, mock_redis):
        # Setup webhook
        create_webhook("t1", {
            "url": "https://hook.example.com",
            "secret": "mysecret",
            "events": ["guardrail_blocked"],
        })

        # Mock httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        await dispatch_event(
            tenant_id="t1",
            event_type="guardrail_blocked",
            payload={"agent": "agent1", "tool": "tool1"},
        )

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert b"guardrail_blocked" in call_kwargs.kwargs.get("content", call_kwargs[1].get("content", b""))

    @pytest.mark.asyncio
    @patch("storage.webhook_store._get_redis", return_value=None)
    async def test_dispatch_event_no_webhooks(self, mock_redis):
        # Should not raise even with no webhooks configured
        await dispatch_event(
            tenant_id="t1",
            event_type="guardrail_blocked",
            payload={"test": True},
        )


class TestWebhookRoutes:
    """Test webhook CRUD routes."""

    @pytest.fixture
    def app(self):
        from unittest.mock import patch as p
        import config.schema as cs
        from config.schema import ShieldConfig, GuardrailConfig, RBACConfig, PipelineConfig, AuthConfig

        test_config = ShieldConfig(
            guardrails={},
            rbac=RBACConfig(),
            pipeline=PipelineConfig(),
            auth=AuthConfig(enabled=False),
            telemetry={},
            llm_backend={},
        )
        original = cs.config
        cs.config = test_config

        with p("config.schema.load_config", return_value=test_config):
            from core.app import create_app
            application = create_app()
        yield application
        cs.config = original

    @pytest.fixture
    def client(self, app):
        from starlette.testclient import TestClient
        return TestClient(app)

    @patch("storage.webhook_store._get_redis", return_value=None)
    def test_create_webhook_route(self, mock_redis, client):
        resp = client.post("/v1/shield/webhooks/t1", json={
            "url": "https://hook.example.com",
            "secret": "s3cr3t",
            "events": ["guardrail_blocked"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "created"
        assert data["webhook"]["url"] == "https://hook.example.com"

    @patch("storage.webhook_store._get_redis", return_value=None)
    def test_create_webhook_invalid_event(self, mock_redis, client):
        resp = client.post("/v1/shield/webhooks/t1", json={
            "url": "https://hook.example.com",
            "events": ["invalid_event"],
        })
        assert resp.status_code == 400

    @patch("storage.webhook_store._get_redis", return_value=None)
    def test_list_webhooks_route(self, mock_redis, client):
        client.post("/v1/shield/webhooks/t1", json={
            "url": "https://a.com",
            "secret": "secret",
            "events": ["guardrail_blocked"],
        })
        resp = client.get("/v1/shield/webhooks/t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        # Secret should be redacted
        assert data["webhooks"][0]["secret"] == "***"

    @patch("storage.webhook_store._get_redis", return_value=None)
    def test_delete_webhook_route(self, mock_redis, client):
        create_resp = client.post("/v1/shield/webhooks/t1", json={
            "url": "https://a.com",
            "events": ["guardrail_blocked"],
        })
        wh_id = create_resp.json()["webhook"]["webhook_id"]

        resp = client.delete(f"/v1/shield/webhooks/t1/{wh_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
