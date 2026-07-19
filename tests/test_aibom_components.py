"""Declared-components API (Task 2 of docs/spec-aibom.md).

PUT/GET/DELETE /v1/tenant/me/aibom/components — apps declare the parts
Shield can't observe (models, prompts, knowledge sources, memory, supply
chain, metadata); the generator merges them into view=full|declared.
"""
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_aibom as aibom_api
import storage.aibom as aibom


@pytest.fixture
def env(monkeypatch):
    kv: dict = {}
    audits: list = []
    monkeypatch.setattr(aibom_api, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(aibom_api, "load_declared",
                        lambda t: copy.deepcopy(kv.get(f"aibom:declared:{t}", {})))
    monkeypatch.setattr(aibom_api, "save_declared",
                        lambda t, d: kv.__setitem__(f"aibom:declared:{t}", d))
    monkeypatch.setattr(aibom_api, "log_admin_action", lambda **kw: audits.append(kw))
    # generator side reads through the same backing store
    monkeypatch.setattr(aibom, "kv_get", lambda k: copy.deepcopy(kv.get(k)))
    monkeypatch.setattr(aibom, "get_tenant", lambda t: {"name": "Acme App"})
    return {"kv": kv, "audits": audits}


@pytest.fixture
def client(env):
    app = FastAPI()
    app.include_router(aibom_api.router)
    return TestClient(app)


GPT = {"name": "gpt-5", "provider": "openai", "version": "latest",
       "context_window": 200000, "supports_tools": True}


def test_declare_and_read_back(client, env):
    r = client.put("/v1/tenant/me/aibom/components/models", json={"components": {"gpt-5": GPT}})
    assert r.status_code == 200
    assert r.json()["count"] == 1

    comps = client.get("/v1/tenant/me/aibom/components").json()
    assert comps["declared"]["models"]["gpt-5"]["provider"] == "openai"
    assert comps["updated_at"]

    bom = client.get("/v1/tenant/me/aibom").json()
    assert bom["models"] == [{**GPT, "component_id": "gpt-5"}]
    assert not any(n == "no declared components" for n in bom["generation_notes"])
    assert env["audits"] and env["audits"][0]["metadata"]["section"] == "models"


def test_merge_by_id_and_null_deletes(client):
    client.put("/v1/tenant/me/aibom/components/prompts",
               json={"components": {"sys-1": {"version": 1}, "sys-2": {"version": 1}}})
    r = client.put("/v1/tenant/me/aibom/components/prompts",
                   json={"components": {"sys-1": {"version": 2}, "sys-2": None}})
    stored = r.json()["components"]
    assert stored == {"sys-1": {"version": 2}}


def test_delete_endpoint(client):
    client.put("/v1/tenant/me/aibom/components/memory",
               json={"components": {"redis-session": {"ttl": 3600}}})
    r = client.delete("/v1/tenant/me/aibom/components/memory/redis-session")
    assert r.status_code == 200 and r.json()["deleted"] is True
    assert client.get("/v1/tenant/me/aibom/components").json()["declared"]["memory"] == {}
    assert client.delete("/v1/tenant/me/aibom/components/memory/redis-session").status_code == 404


def test_validation_rejects(client):
    put = lambda section, comps: client.put(
        f"/v1/tenant/me/aibom/components/{section}", json={"components": comps})

    assert put("agents", {"x": {}}).status_code == 422          # observed section not declarable
    assert put("models", {"bad id!": {}}).status_code == 422    # id charset
    assert put("models", {"m": "not-an-object"}).status_code == 422
    assert client.put("/v1/tenant/me/aibom/components/models", json={}).status_code == 422

    # count cap applies to the post-merge section
    many = {f"m{i}": {} for i in range(201)}
    assert put("models", many).status_code == 422
    # size cap
    assert put("models", {"big": {"blob": "x" * (64 * 1024)}}).status_code == 422


def test_credential_shaped_values_rejected(client):
    put = lambda comps: client.put("/v1/tenant/me/aibom/components/models",
                                   json={"components": comps})
    assert put({"m": {"api_key": "sk-abc123def"}}).status_code == 422
    assert put({"m": {"config": {"aws": "AKIAIOSFODNN7EXAMPLE"}}}).status_code == 422
    assert put({"m": {"pem": "-----BEGIN PRIVATE KEY-----"}}).status_code == 422
    assert put({"m": {"gh": ["ghp_abcdef123"]}}).status_code == 422
    # names of secrets are fine — only values that look like credentials fail
    r = put({"m": {"secrets_used": ["OPENAI_API_KEY"]}})
    assert r.status_code == 200


def test_metadata_overlay_respects_protected_fields(client):
    r = client.put("/v1/tenant/me/aibom/components/metadata",
                   json={"components": {"environment": "production", "owner": "platform-team",
                                        "tenant_id": "evil-tenant"}})
    assert r.status_code == 200
    meta = client.get("/v1/tenant/me/aibom").json()["metadata"]
    assert meta["environment"] == "production"
    assert meta["owner"] == "platform-team"
    assert meta["tenant_id"] == "acme"  # generator-owned, never overridden


def test_views_include_or_exclude_declared(client):
    client.put("/v1/tenant/me/aibom/components/knowledge_sources",
               json={"components": {"docs-index": {"type": "vector_db", "encryption": "aes256"}}})
    declared = client.get("/v1/tenant/me/aibom?view=declared").json()
    assert declared["knowledge_sources"][0]["component_id"] == "docs-index"
    assert declared["agents"] == []

    observed = client.get("/v1/tenant/me/aibom?view=observed").json()
    assert observed["knowledge_sources"] == []


def test_tenant_scoped_key(client, env):
    client.put("/v1/tenant/me/aibom/components/models", json={"components": {"m": {}}})
    assert list(env["kv"].keys()) == ["aibom:declared:acme"]
