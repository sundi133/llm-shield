"""Tenants register their own OIDC providers without the admin key.

Mode B for sovereign customers: the platform operator (admin key) is not
in the loop when a tenant points Shield at their on-prem Keycloak / Dex
/ ADFS. They use their tenant API key, the same one they use for every
other tenant-self-serve operation.
"""

from __future__ import annotations

import asyncio

import pytest

from api.routes_oidc_tenant import (
    _require_tenant,
    delete_provider,
    list_providers,
    register_provider,
)
from core.oauth.oidc_client import oidc_registry


class _Body:
    def __init__(self, payload: dict):
        self._payload = payload

    async def json(self):
        return self._payload


class _State:
    pass


class _Req:
    def __init__(self, tenant_id: str = "", body: dict | None = None):
        self.state = _State()
        if tenant_id:
            self.state.tenant_id = tenant_id
        self._body = body or {}

    async def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _reset_registry():
    oidc_registry._providers.clear() if hasattr(oidc_registry, "_providers") else None
    yield
    oidc_registry._providers.clear() if hasattr(oidc_registry, "_providers") else None


# ── Auth gating ────────────────────────────────────────────────────────


def test_no_tenant_key_is_rejected():
    from fastapi import HTTPException

    req = _Req()  # no tenant_id on state
    with pytest.raises(HTTPException) as exc:
        _require_tenant(req)
    assert exc.value.status_code == 401


# ── Register / list / delete with tenant key only ──────────────────────


def test_register_provider_with_tenant_key_only(monkeypatch):
    # Skip outbound discovery
    from api import routes_oidc_tenant as mod

    async def _no_discovery(_issuer):
        return {"jwks_uri": ""}

    monkeypatch.setattr(mod, "discover_openid_config", _no_discovery)

    req = _Req(tenant_id="acme", body={
        "name": "keycloak",
        "issuer": "https://keycloak.corp.local/realms/main",
        "client_id": "shield",
        "audience": "shield",
        "claim_mapping": {"sub": "user_sub", "preferred_username": "agent_id"},
    })

    result = asyncio.run(register_provider(req))
    assert result["status"] == "registered"
    assert result["tenant_id"] == "acme"
    assert result["name"] == "keycloak"


def test_list_only_shows_calling_tenants_providers(monkeypatch):
    from api import routes_oidc_tenant as mod

    async def _no_discovery(_issuer):
        return {"jwks_uri": ""}

    monkeypatch.setattr(mod, "discover_openid_config", _no_discovery)

    asyncio.run(register_provider(_Req(tenant_id="acme", body={
        "name": "kc-acme",
        "issuer": "https://keycloak.acme.corp/realms/main",
        "client_id": "shield",
    })))
    asyncio.run(register_provider(_Req(tenant_id="globex", body={
        "name": "kc-globex",
        "issuer": "https://keycloak.globex.corp/realms/main",
        "client_id": "shield",
    })))

    acme_view = asyncio.run(list_providers(_Req(tenant_id="acme")))
    globex_view = asyncio.run(list_providers(_Req(tenant_id="globex")))

    assert set(acme_view["providers"]) == {"kc-acme"}
    assert set(globex_view["providers"]) == {"kc-globex"}


def test_register_rejects_missing_required_fields():
    req = _Req(tenant_id="acme", body={"name": "kc"})
    resp = asyncio.run(register_provider(req))
    assert getattr(resp, "status_code", None) == 400


def test_delete_provider(monkeypatch):
    from api import routes_oidc_tenant as mod

    async def _no_discovery(_issuer):
        return {"jwks_uri": ""}

    monkeypatch.setattr(mod, "discover_openid_config", _no_discovery)

    asyncio.run(register_provider(_Req(tenant_id="acme", body={
        "name": "kc", "issuer": "https://kc/realms/m", "client_id": "shield",
    })))
    result = asyncio.run(delete_provider("kc", _Req(tenant_id="acme")))
    assert result["status"] == "removed"


def test_delete_unknown_returns_404():
    resp = asyncio.run(delete_provider("nope", _Req(tenant_id="acme")))
    assert getattr(resp, "status_code", None) == 404
