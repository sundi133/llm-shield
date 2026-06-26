"""Edge fast-path Task 1: GET /v1/edge/policy-bundle.

Read-only, tenant-scoped bundle of regex rules + blocklists for an on-device
client to run locally. Model-free (mock the policy store + tenant config).
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_edge as edge
from core.auth import get_tenant_from_request


POLICIES = {
    "lookup_employee": {"sanitization_rules": [
        {"pattern_id": "ssn", "regex": r"\d{3}-\d{2}-\d{4}", "replacement": "[SSN]",
         "severity": "critical", "enabled": True},          # critical -> block
        {"pattern_id": "phone", "regex": r"\+1-\d{3}-\d{3}-\d{4}", "replacement": "[PHONE]",
         "severity": "medium", "enabled": True},            # default -> redact
        {"pattern_id": "off", "regex": r"NEVERMATCH", "enabled": False},  # disabled -> skipped
    ]},
    "get_compensation": {"sanitization_rules": [
        {"pattern_id": "ssn2", "regex": r"\d{3}-\d{2}-\d{4}", "severity": "high", "enabled": True},  # dup regex -> deduped
    ]},
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(edge, "_load_all", lambda t: POLICIES)
    monkeypatch.setattr("storage.tenant_store.get_tenant",
                        lambda t: {"input_guardrails": {"keyword-blocklist": {"blocklist": ["wire", "ssn"]}}})
    app = FastAPI()
    app.include_router(edge.router)
    app.dependency_overrides[get_tenant_from_request] = lambda: "acme"
    return TestClient(app)


def test_bundle_flattens_dedups_and_defaults_actions(client):
    r = client.get("/v1/edge/policy-bundle")
    assert r.status_code == 200
    b = r.json()
    assert b["tenant_id"] == "acme"
    by_id = {x["id"]: x for x in b["rules"]}
    # critical -> block; medium -> redact; disabled -> absent
    assert by_id["ssn"]["action"] == "block"
    assert by_id["phone"]["action"] == "redact"
    assert "off" not in by_id
    # duplicate regex (ssn2 shares ssn's pattern) is deduped
    regexes = [x["regex"] for x in b["rules"]]
    assert regexes.count(r"\d{3}-\d{2}-\d{4}") == 1
    # blocklists from tenant input guardrails
    assert set(b["blocklists"]) == {"wire", "ssn"}
    assert b["version"]


def test_etag_304_when_unchanged(client):
    first = client.get("/v1/edge/policy-bundle")
    etag = first.headers["ETag"]
    again = client.get("/v1/edge/policy-bundle", headers={"If-None-Match": etag})
    assert again.status_code == 304


def test_empty_tenant_returns_empty_bundle(monkeypatch):
    monkeypatch.setattr(edge, "_load_all", lambda t: {})
    monkeypatch.setattr("storage.tenant_store.get_tenant", lambda t: {})
    app = FastAPI()
    app.include_router(edge.router)
    app.dependency_overrides[get_tenant_from_request] = lambda: "empty"
    c = TestClient(app)
    b = c.get("/v1/edge/policy-bundle").json()
    assert b["rules"] == [] and b["blocklists"] == [] and b["version"]
