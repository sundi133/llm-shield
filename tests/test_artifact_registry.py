"""Tests for the unified artifact registry."""

import importlib
import os
import tempfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.artifacts import Artifact, ArtifactKind, ArtifactStatus, Provenance
from core.artifact_policy import evaluate_for_approval
import storage.artifact_store as artifact_store


@pytest.fixture
def file_store(monkeypatch, tmp_path):
    """Force the file backend with an isolated path per test."""
    path = tmp_path / "artifacts.json"
    monkeypatch.setenv("ARTIFACT_STORE_BACKEND", "file")
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(path))
    artifact_store.reset_store_for_tests(None)
    importlib.reload(artifact_store)  # picks up new env
    store = artifact_store.FileArtifactStore(str(path))
    artifact_store.reset_store_for_tests(store)
    yield store
    artifact_store.reset_store_for_tests(None)


@pytest.fixture
def client(file_store, monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_ARTIFACT_REGISTRY", "true")
    # reload feature_flags to pick up env
    import core.feature_flags as ff
    importlib.reload(ff)

    # rebuild routers AFTER flag flip so the gate evaluates true
    import api.routes_artifacts_common as common
    importlib.reload(common)
    import api.routes_models as rm
    importlib.reload(rm)
    import api.routes_skills as rs
    importlib.reload(rs)
    import api.routes_software as rsw
    importlib.reload(rsw)
    import api.routes_mcp as rmcp
    importlib.reload(rmcp)

    app = FastAPI()
    app.include_router(rm.router)
    app.include_router(rs.router)
    app.include_router(rsw.router)
    app.include_router(rmcp.governance_router)
    return TestClient(app)


def _register(client, kind_prefix: str, name="thing", version="1.0.0", **overrides):
    body = {
        "tenant_id": "t1",
        "name": name,
        "version": version,
        "source_uri": "oci://example/thing:1.0.0",
        "sha256": "abc",
        "provenance": {"license": "Apache-2.0"},
        "scopes": ["read"],
        "owners": ["alice"],
        "metadata": {},
    }
    body.update(overrides)
    return client.post(f"{kind_prefix}/register", json=body)


# ---------------- Pure store ----------------


def test_store_put_get_delete(file_store):
    a = Artifact(
        kind=ArtifactKind.MODEL, name="llama", version="1.0.0",
        tenant_id="t1", source_uri="hf://foo/bar",
    )
    file_store.put(a)
    got = file_store.get("t1", ArtifactKind.MODEL, "llama", "1.0.0")
    assert got is not None and got.name == "llama"
    assert file_store.delete("t1", ArtifactKind.MODEL, "llama", "1.0.0") is True
    assert file_store.get("t1", ArtifactKind.MODEL, "llama", "1.0.0") is None


def test_store_pin_clear(file_store):
    a = Artifact(
        kind=ArtifactKind.SKILL, name="soc2", version="2.1.0",
        tenant_id="t1", source_uri="git://x", status=ArtifactStatus.APPROVED,
    )
    file_store.put(a)
    file_store.set_pin("t1", ArtifactKind.SKILL, "soc2", "2.1.0")
    assert file_store.get_pin("t1", ArtifactKind.SKILL, "soc2") == "2.1.0"
    file_store.set_pin("t1", ArtifactKind.SKILL, "soc2", None)
    assert file_store.get_pin("t1", ArtifactKind.SKILL, "soc2") is None


# ---------------- Approval policy ----------------


def test_approval_policy_permissive_by_default(monkeypatch):
    monkeypatch.delenv("SHIELD_ARTIFACT_REQUIRE_SIGNATURE", raising=False)
    monkeypatch.delenv("SHIELD_ARTIFACT_REQUIRE_SBOM", raising=False)
    monkeypatch.delenv("SHIELD_ARTIFACT_LICENSE_ALLOWLIST", raising=False)
    a = Artifact(kind=ArtifactKind.MODEL, name="x", version="1", tenant_id="t", source_uri="s")
    assert evaluate_for_approval(a).allowed is True


def test_approval_policy_requires_signature(monkeypatch):
    monkeypatch.setenv("SHIELD_ARTIFACT_REQUIRE_SIGNATURE", "true")
    a = Artifact(
        kind=ArtifactKind.MODEL, name="x", version="1", tenant_id="t", source_uri="s",
        provenance=Provenance(signature=None, signature_status="absent"),
    )
    d = evaluate_for_approval(a)
    assert d.allowed is False
    assert any("signature_status" in r for r in d.reasons)


def test_approval_policy_license_allowlist(monkeypatch):
    monkeypatch.setenv("SHIELD_ARTIFACT_LICENSE_ALLOWLIST", "Apache-2.0,MIT")
    a = Artifact(
        kind=ArtifactKind.MODEL, name="x", version="1", tenant_id="t", source_uri="s",
        provenance=Provenance(license="GPL-3.0"),
    )
    d = evaluate_for_approval(a)
    assert d.allowed is False
    assert any("license" in r for r in d.reasons)


# ---------------- HTTP API ----------------


def test_register_and_list_model(client):
    r = _register(client, "/v1/shield/models")
    assert r.status_code == 200, r.text
    assert r.json()["artifact"]["status"] == "draft"

    r = client.get("/v1/shield/models", params={"tenant_id": "t1"})
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_approve_then_pin_then_revoke(client):
    _register(client, "/v1/shield/models", name="m", version="1.0.0")

    r = client.post("/v1/shield/models/m/1.0.0/approve", json={"tenant_id": "t1"})
    assert r.status_code == 200
    assert r.json()["artifact"]["status"] == "approved"

    r = client.post("/v1/shield/models/m/pin", json={"tenant_id": "t1", "version": "1.0.0"})
    assert r.status_code == 200
    assert r.json()["pinned_version"] == "1.0.0"

    r = client.post("/v1/shield/models/m/1.0.0/revoke",
                    json={"tenant_id": "t1", "reason": "compromised"})
    assert r.status_code == 200
    assert r.json()["artifact"]["status"] == "revoked"


def test_cannot_pin_draft(client):
    _register(client, "/v1/shield/skills", name="s", version="0.1.0")
    r = client.post("/v1/shield/skills/s/pin", json={"tenant_id": "t1", "version": "0.1.0"})
    assert r.status_code == 409


def test_approval_blocked_by_policy(client, monkeypatch):
    monkeypatch.setenv("SHIELD_ARTIFACT_REQUIRE_SBOM", "true")
    _register(client, "/v1/shield/artifacts", name="img", version="1")
    r = client.post("/v1/shield/artifacts/img/1/approve", json={"tenant_id": "t1"})
    assert r.status_code == 409
    assert "sbom_uri missing" in r.json()["detail"]["reasons"][0]


def test_mcp_governance_endpoints_exist(client):
    _register(client, "/v1/shield/mcp/governance", name="gmail-mcp", version="1.0.0")
    r = client.get("/v1/shield/mcp/governance",
                   params={"tenant_id": "t1", "name": "gmail-mcp"})
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_registry_disabled_returns_503(monkeypatch, tmp_path):
    monkeypatch.setenv("ARTIFACT_STORE_BACKEND", "file")
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(tmp_path / "a.json"))
    monkeypatch.delenv("SHIELD_ENABLE_ARTIFACT_REGISTRY", raising=False)
    monkeypatch.delenv("SHIELD_ENABLE_ENTERPRISE", raising=False)
    import core.feature_flags as ff
    importlib.reload(ff)
    import api.routes_artifacts_common as common
    importlib.reload(common)
    import api.routes_models as rm
    importlib.reload(rm)
    app = FastAPI()
    app.include_router(rm.router)
    c = TestClient(app)
    r = c.get("/v1/shield/models", params={"tenant_id": "t1"})
    assert r.status_code == 503


# ---------------- Runtime resolver ----------------


def test_resolver_off_by_default_returns_none(file_store, monkeypatch):
    monkeypatch.delenv("SHIELD_ENABLE_ARTIFACT_ENFORCEMENT", raising=False)
    monkeypatch.delenv("SHIELD_ENABLE_ENTERPRISE", raising=False)
    import core.feature_flags as ff
    importlib.reload(ff)
    import core.artifact_resolver as ar
    importlib.reload(ar)
    assert ar.resolve("t1", ArtifactKind.MODEL, "anything") is None


def test_resolver_blocks_revoked(file_store, monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_ARTIFACT_ENFORCEMENT", "true")
    import core.feature_flags as ff
    importlib.reload(ff)
    import core.artifact_resolver as ar
    importlib.reload(ar)

    a = Artifact(
        kind=ArtifactKind.MODEL, name="m", version="1",
        tenant_id="t1", source_uri="s", status=ArtifactStatus.REVOKED,
    )
    file_store.put(a)
    file_store.set_pin("t1", ArtifactKind.MODEL, "m", "1")

    with pytest.raises(ar.ArtifactNotPermitted):
        ar.resolve("t1", ArtifactKind.MODEL, "m")


def test_resolver_allows_approved(file_store, monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_ARTIFACT_ENFORCEMENT", "true")
    import core.feature_flags as ff
    importlib.reload(ff)
    import core.artifact_resolver as ar
    importlib.reload(ar)

    a = Artifact(
        kind=ArtifactKind.MODEL, name="m", version="2",
        tenant_id="t1", source_uri="s", status=ArtifactStatus.APPROVED,
    )
    file_store.put(a)
    file_store.set_pin("t1", ArtifactKind.MODEL, "m", "2")

    got = ar.resolve("t1", ArtifactKind.MODEL, "m")
    assert got is not None and got.version == "2"
