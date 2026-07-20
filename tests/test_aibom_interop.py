"""AIBOM interop (spec addendum PRs 5-7): manifest upload, CycloneDX 1.6
export, and external-BOM ingest.
"""
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_aibom as aibom_api
import storage.aibom as aibom
from storage.aibom_interop import from_cyclonedx, to_cyclonedx


@pytest.fixture
def env(monkeypatch):
    kv: dict = {}
    monkeypatch.setattr(aibom_api, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(aibom_api, "log_admin_action", lambda **kw: None)
    monkeypatch.setattr(aibom_api, "load_declared",
                        lambda t: copy.deepcopy(kv.get(f"aibom:declared:{t}", {})))
    monkeypatch.setattr(aibom_api, "save_declared",
                        lambda t, d: kv.__setitem__(f"aibom:declared:{t}", d))
    monkeypatch.setattr(aibom, "kv_get", lambda k: copy.deepcopy(kv.get(k)))
    monkeypatch.setattr(aibom, "get_tenant", lambda t: {"name": "Acme App"})
    return kv


@pytest.fixture
def client(env):
    app = FastAPI()
    app.include_router(aibom_api.router)
    return TestClient(app)


# ── PR 5: manifest upload ─────────────────────────────────────────────────

def test_manifest_uploads_multiple_sections(client):
    r = client.put("/v1/tenant/me/aibom/components", json={"components": {
        "models": {"gpt-5": {"provider": "openai"}},
        "prompts": {"sys-1": {"version": 1}},
        "metadata": {"environment": "production"},
    }})
    assert r.status_code == 200
    assert r.json()["sections"] == {"models": 1, "prompts": 1, "metadata": 1}

    declared = client.get("/v1/tenant/me/aibom/components").json()["declared"]
    assert declared["models"]["gpt-5"]["provider"] == "openai"
    assert declared["metadata"]["environment"] == "production"


def test_manifest_is_all_or_nothing(client, env):
    r = client.put("/v1/tenant/me/aibom/components", json={"components": {
        "models": {"good": {"provider": "openai"}},
        "agents": {"x": {}},                        # not a declarable section
    }})
    assert r.status_code == 422
    assert env == {}                                # nothing was written

    r = client.put("/v1/tenant/me/aibom/components", json={"components": {
        "models": {"good": {}, "bad": {"key": "sk-secret123"}},
    }})
    assert r.status_code == 422
    assert env == {}


# ── PR 6: CycloneDX export ────────────────────────────────────────────────

def test_cyclonedx_export_shape(client):
    client.put("/v1/tenant/me/aibom/components", json={"components": {
        "models": {"gpt-5": {"name": "gpt-5", "provider": "openai", "version": "2026-01"}},
        "knowledge_sources": {"docs-index": {"type": "vector_db"}},
    }})
    r = client.get("/v1/tenant/me/aibom?format=cyclonedx")
    assert r.status_code == 200
    doc = r.json()
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["name"] == "Acme App"

    by_ref = {c["bom-ref"]: c for c in doc["components"]}
    model = by_ref["models/gpt-5"]
    assert model["type"] == "machine-learning-model"
    assert model["version"] == "2026-01"
    assert {"name": "shield:provider", "value": "openai"} in model["properties"]
    assert by_ref["knowledge_sources/docs-index"]["type"] == "data"

    # property values are always strings (CycloneDX requirement)
    for c in doc["components"]:
        for p in c.get("properties", []):
            assert isinstance(p["value"], str)

    assert client.get("/v1/tenant/me/aibom?format=spdx").status_code == 422


def test_cyclonedx_maps_observed_sections():
    bom = {
        "metadata": {"application": "Acme App", "tenant_id": "acme", "generated_at": "t"},
        "agents": [{"agent_id": "billing-agent", "name": "Billing", "source": "registered",
                    "allowed_tools": ["get_invoice"]}],
        "tools": [{"name": "get_invoice", "has_policy": True, "disabled": False}],
        "guardrails": [{"name": "prompt_injection", "stage": "input", "enabled": True}],
        "mcp_servers": [{"name": "github", "endpoint": "https://mcp.example.com",
                         "has_credentials": True}],
    }
    doc = to_cyclonedx(bom)
    refs = {c["bom-ref"] for c in doc["components"]}
    assert {"agents/billing-agent", "tools/get_invoice",
            "guardrails/input/prompt_injection"} <= refs
    svc = doc["services"][0]
    assert svc["bom-ref"] == "mcp_servers/github"
    assert svc["endpoints"] == ["https://mcp.example.com"]


# ── PR 7: ingest ──────────────────────────────────────────────────────────

K8S_AIBOM_DOC = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [
        {"type": "machine-learning-model", "name": "llama-3-70b", "version": "3.0",
         "bom-ref": "model/llama-3-70b",
         "properties": [{"name": "k8s-aibom:runtime", "value": "vllm"}]},
        {"type": "data", "name": "qdrant-collection", "bom-ref": "vector/qdrant"},
        {"type": "library", "name": "langchain", "version": "0.3.1", "purl": "pkg:pypi/langchain@0.3.1"},
        {"type": "container", "name": "vllm-server", "version": "0.6"},
    ],
}


def test_ingest_maps_by_type(client):
    r = client.post("/v1/tenant/me/aibom/ingest", json=K8S_AIBOM_DOC)
    assert r.status_code == 200
    assert r.json()["ingested"] == {"models": 1, "knowledge_sources": 1, "supply_chain": 2}

    declared = client.get("/v1/tenant/me/aibom/components").json()["declared"]
    model = declared["models"]["model-llama-3-70b"]
    assert model["source"] == "cyclonedx-ingest"
    assert model["properties"]["k8s-aibom:runtime"] == "vllm"
    assert declared["supply_chain"]["langchain-0.3.1"]["purl"] == "pkg:pypi/langchain@0.3.1"

    # ingested components appear in the generated BOM and round-trip to CycloneDX
    bom = client.get("/v1/tenant/me/aibom").json()
    assert any(m["component_id"] == "model-llama-3-70b" for m in bom["models"])


def test_ingest_skips_credential_shaped_components(client):
    doc = copy.deepcopy(K8S_AIBOM_DOC)
    doc["components"].append(
        {"type": "library", "name": "leaky", "version": "1",
         "properties": [{"name": "token", "value": "ghp_abc123secret"}]})
    r = client.post("/v1/tenant/me/aibom/ingest", json=doc)
    assert r.status_code == 200
    assert any("credential-shaped" in n for n in r.json()["notes"])
    declared = client.get("/v1/tenant/me/aibom/components").json()["declared"]
    assert "leaky-1" not in declared["supply_chain"]


def test_ingest_rejects_non_cyclonedx_and_oversize(client, monkeypatch):
    assert client.post("/v1/tenant/me/aibom/ingest", json={"hello": "world"}).status_code == 422
    monkeypatch.setattr(aibom_api, "MAX_INGEST_BYTES", 10)
    assert client.post("/v1/tenant/me/aibom/ingest", json=K8S_AIBOM_DOC).status_code == 422


def test_from_cyclonedx_pure_mapping():
    mapped, notes = from_cyclonedx(K8S_AIBOM_DOC)
    assert set(mapped) == {"models", "knowledge_sources", "supply_chain"}
    with pytest.raises(ValueError):
        from_cyclonedx({"bomFormat": "SPDX"})
    # component with no usable id is skipped with a note
    mapped, notes = from_cyclonedx(
        {"bomFormat": "CycloneDX", "components": [{"type": "library"}]})
    assert mapped == {} and any("no usable id" in n for n in notes)
