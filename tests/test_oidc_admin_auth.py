"""OIDC provider admin endpoints must fail closed on the admin key.

Regression guard: registering/listing/deleting OIDC providers establishes
which IdPs a tenant trusts. The admin gate must reject when SHIELD_ADMIN_KEY
is unset (rather than treating "unconfigured" as open access) and must
reject a missing or wrong X-Admin-Key, matching the fail-closed admin gate
used elsewhere in the codebase.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.routes_oidc_admin import router as oidc_admin_router

TENANT = "tenant-1"
PATH = f"/v1/admin/oidc-providers/{TENANT}"


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(oidc_admin_router)
    return TestClient(app)


def test_list_rejected_when_admin_key_unset(client, monkeypatch):
    # No SHIELD_ADMIN_KEY configured must NOT mean open access.
    monkeypatch.delenv("SHIELD_ADMIN_KEY", raising=False)
    resp = client.get(PATH)
    assert resp.status_code == 403


def test_register_rejected_when_admin_key_unset(client, monkeypatch):
    monkeypatch.delenv("SHIELD_ADMIN_KEY", raising=False)
    resp = client.post(PATH, json={"name": "x", "issuer": "https://i", "client_id": "c"})
    assert resp.status_code == 403


def test_rejected_with_wrong_key(client, monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "correct-key")
    resp = client.get(PATH, headers={"X-Admin-Key": "wrong-key"})
    assert resp.status_code == 403


def test_rejected_with_missing_header(client, monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "correct-key")
    resp = client.get(PATH)
    assert resp.status_code == 403


def test_allowed_with_correct_key(client, monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "correct-key")
    resp = client.get(PATH, headers={"X-Admin-Key": "correct-key"})
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == TENANT
