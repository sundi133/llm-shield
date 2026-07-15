"""Tests for SIEM integration — event-status filter and Elastic/Wazuh targets."""

import json
import pytest
from unittest.mock import patch, AsyncMock

from core.siem_dispatcher import (
    dispatch_to_siem,
    dispatch_to_elastic,
    dispatch_to_wazuh,
    format_ecs_event,
    _event_status,
)


BLOCK_EVENT = {"event_type": "guardrail_blocked", "tenant_id": "t1", "payload": {"a": 1}}
WARN_EVENT = {"event_type": "guardrail_warning", "tenant_id": "t1", "payload": {"a": 1}}
SHADOW_EVENT = {"event_type": "shadow_agent_detected", "tenant_id": "t1", "payload": {"a": 1}}


def _cfg(**over):
    base = {"siem_id": "s1", "type": "generic", "url": "https://siem", "token": "", "enabled": True}
    base.update(over)
    return base


# ── Event-status filter ────────────────────────────────────────────────────

class TestStatusFilter:
    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    @patch("storage.siem_store.get_siem_configs")
    async def test_block_only_forwards_block_drops_warn(self, mock_cfgs, mock_post):
        mock_post.return_value = True
        mock_cfgs.return_value = [_cfg(statuses=["block"])]

        await dispatch_to_siem("t1", BLOCK_EVENT)
        assert mock_post.await_count == 1

        await dispatch_to_siem("t1", WARN_EVENT)
        assert mock_post.await_count == 1  # warn dropped

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    @patch("storage.siem_store.get_siem_configs")
    async def test_warn_only_forwards_warn_drops_block(self, mock_cfgs, mock_post):
        mock_post.return_value = True
        mock_cfgs.return_value = [_cfg(statuses=["warn"])]

        await dispatch_to_siem("t1", BLOCK_EVENT)
        assert mock_post.await_count == 0  # block dropped

        await dispatch_to_siem("t1", WARN_EVENT)
        assert mock_post.await_count == 1

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    @patch("storage.siem_store.get_siem_configs")
    async def test_empty_statuses_forwards_all(self, mock_cfgs, mock_post):
        mock_post.return_value = True
        mock_cfgs.return_value = [_cfg(statuses=[])]

        await dispatch_to_siem("t1", BLOCK_EVENT)
        await dispatch_to_siem("t1", WARN_EVENT)
        assert mock_post.await_count == 2

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    @patch("storage.siem_store.get_siem_configs")
    async def test_legacy_config_without_statuses_is_block_only(self, mock_cfgs, mock_post):
        """Configs created before this feature (no 'statuses' key) keep old behavior."""
        mock_post.return_value = True
        mock_cfgs.return_value = [_cfg()]  # no statuses key

        await dispatch_to_siem("t1", BLOCK_EVENT)
        assert mock_post.await_count == 1

        await dispatch_to_siem("t1", WARN_EVENT)
        assert mock_post.await_count == 1  # legacy endpoint never receives warn

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    @patch("storage.siem_store.get_siem_configs")
    async def test_non_guardrail_event_bypasses_status_filter(self, mock_cfgs, mock_post):
        mock_post.return_value = True
        mock_cfgs.return_value = [_cfg(statuses=["block"])]

        # shadow_agent_detected has no block/warn status -> always forwarded
        await dispatch_to_siem("t1", SHADOW_EVENT)
        assert mock_post.await_count == 1

    def test_event_status_mapping(self):
        assert _event_status("guardrail_blocked") == "block"
        assert _event_status("guardrail_warning") == "warn"
        assert _event_status("shadow_agent_detected") is None
        assert _event_status("test_event") is None


# ── Elastic / Wazuh targets ────────────────────────────────────────────────

class TestElasticWazuh:
    def test_format_ecs_event(self):
        doc = format_ecs_event(BLOCK_EVENT)
        assert doc["event"]["action"] == "guardrail_blocked"
        assert doc["event"]["module"] == "llm-shield"
        assert doc["tenant_id"] == "t1"
        assert doc["shield"] == {"a": 1}
        assert doc["@timestamp"].endswith("Z")

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    async def test_elastic_uses_apikey_auth(self, mock_post):
        mock_post.return_value = True
        await dispatch_to_elastic(BLOCK_EVENT, "https://es:9200/idx/_doc", "APIKEY")

        url, headers, body = mock_post.await_args.args
        assert url == "https://es:9200/idx/_doc"
        assert headers["Authorization"] == "ApiKey APIKEY"
        assert json.loads(body)["event"]["action"] == "guardrail_blocked"

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    async def test_wazuh_uses_bearer_auth(self, mock_post):
        mock_post.return_value = True
        await dispatch_to_wazuh(BLOCK_EVENT, "https://wazuh:9200/idx/_doc", "TOKEN")

        url, headers, body = mock_post.await_args.args
        assert url == "https://wazuh:9200/idx/_doc"
        assert headers["Authorization"] == "Bearer TOKEN"

    @pytest.mark.asyncio
    @patch("core.siem_dispatcher._post", new_callable=AsyncMock)
    @patch("storage.siem_store.get_siem_configs")
    async def test_dispatcher_routes_by_type(self, mock_cfgs, mock_post):
        mock_post.return_value = True
        mock_cfgs.return_value = [
            _cfg(siem_id="e", type="elastic", url="https://es/_doc", token="K", statuses=[]),
            _cfg(siem_id="w", type="wazuh", url="https://wz/_doc", token="T", statuses=[]),
        ]
        await dispatch_to_siem("t1", BLOCK_EVENT)

        auths = {
            call.args[0]: call.args[1]["Authorization"]
            for call in mock_post.await_args_list
        }
        assert auths["https://es/_doc"] == "ApiKey K"
        assert auths["https://wz/_doc"] == "Bearer T"


# ── API validation ─────────────────────────────────────────────────────────

class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v


class TestSIEMRoutes:
    @pytest.fixture
    def client(self):
        from fastapi import FastAPI, Request
        from starlette.testclient import TestClient
        from api.routes_siem import router

        app = FastAPI()

        @app.middleware("http")
        async def _tenant(request: Request, call_next):
            request.state.tenant_id = "t1"
            return await call_next(request)

        app.include_router(router)
        return TestClient(app)

    def test_create_elastic_requires_token(self, client):
        with patch("storage.siem_store._get_redis", return_value=FakeRedis()):
            resp = client.post("/v1/tenant/me/siem", json={"type": "elastic", "url": "https://es/_doc"})
        assert resp.status_code == 400

    def test_create_wazuh_requires_url(self, client):
        with patch("storage.siem_store._get_redis", return_value=FakeRedis()):
            resp = client.post("/v1/tenant/me/siem", json={"type": "wazuh", "token": "T"})
        assert resp.status_code == 400

    def test_create_rejects_bad_status(self, client):
        with patch("storage.siem_store._get_redis", return_value=FakeRedis()):
            resp = client.post("/v1/tenant/me/siem", json={
                "type": "generic", "url": "https://s", "statuses": ["pass"],
            })
        assert resp.status_code == 400

    def test_create_elastic_persists_statuses(self, client):
        fake = FakeRedis()
        with patch("storage.siem_store._get_redis", return_value=fake):
            resp = client.post("/v1/tenant/me/siem", json={
                "type": "elastic", "url": "https://es/_doc", "token": "KEY",
                "statuses": ["block", "warn"],
            })
            assert resp.status_code == 200
            assert resp.json()["siem"]["statuses"] == ["block", "warn"]

            listed = client.get("/v1/tenant/me/siem").json()
        assert listed["total"] == 1
        assert listed["integrations"][0]["statuses"] == ["block", "warn"]
        # token redacted in list response
        assert listed["integrations"][0]["token"].endswith("...")


# ── Webhook non-regression ─────────────────────────────────────────────────

class TestWebhookNonRegression:
    @patch("storage.webhook_store._get_redis", return_value=None)
    def test_warning_not_delivered_to_blocked_subscriber(self, mock_redis):
        from storage.tenant_store import _fallback_store
        from storage.webhook_store import create_webhook, get_webhooks_for_event

        for k in [k for k in _fallback_store if k.startswith("webhooks:")]:
            del _fallback_store[k]
        create_webhook("t1", {"url": "https://a.com", "events": ["guardrail_blocked"]})

        # A subscriber to guardrail_blocked must not receive the new warning type
        assert get_webhooks_for_event("t1", "guardrail_warning") == []
        assert len(get_webhooks_for_event("t1", "guardrail_blocked")) == 1
