"""Infrastructure guardrails, task 6: runtime attestation at cap/mint, drift,
the profile's token-TTL cap and its verified-identity requirement.
Spec: docs/specs/infra-guardrails.md §4.3."""

import asyncio
import copy
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from core.identity import IdentityTuple
from core.jwt_utils import decode_jwt_unverified, encode_jwt
from core.runtime_policy import attest
from core.runtime_policy import check as rc
from core.runtime_policy import store as rt_store
from core.runtime_policy.model import TEMPLATES, profile_hash, validate_profile
from core.signers import LocalEd25519Signer
from storage.tenant_store import kv_set

_SIGNER = LocalEd25519Signer(kid="attest-test", private_key_hex="41" * 32)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", "52" * 32)
    rt_store.reset_memory()
    attest.reset_memory()
    rc.invalidate()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    rt_store.reset_memory()
    attest.reset_memory()
    rc.invalidate()


def _setup(mode="enforce", **identity):
    tenant = "at" + uuid.uuid4().hex[:8]
    prof = copy.deepcopy(TEMPLATES["research-agent"])
    prof["identity"] = {"require_agent_token": True, "max_token_ttl_seconds": 600,
                        "require_attestation": mode, **identity}
    normalized = rt_store.save_profile(tenant, "research-agent", prof)
    kv_set(f"agents:{tenant}", {"bot": {"agent_id": "bot", "runtime_profile": "research-agent"}})
    rc.invalidate(tenant)
    return tenant, profile_hash(normalized)


def _token(**claims) -> str:
    return encode_jwt({"agent_id": "bot", **claims}, _SIGNER)


def _mint(tenant, token=None):
    from api import routes_agent_auth as aa
    from api.routes_agent_auth import CapMintRequest

    ident = IdentityTuple(user_sub="alice@corp.com", agent_id="bot", agent_instance_id="sbx-1",
                          tenant_id=tenant, build_hash="h", model_version="m", session_id="s1")
    req = SimpleNamespace(headers={"X-Agent-Token": token} if token else {})
    body = CapMintRequest(tool="fetch", resource="r/1", session_id="s1")
    with patch.object(aa, "rate_limit_cap_mint", return_value=(True, None)), \
         patch.object(aa, "_decide_authz", return_value={
             "allowed": True, "tool": "fetch", "resource": "r/1", "reasons": []}):
        return asyncio.run(aa.mint_capability(body, ident, req))


# ── token claims ─────────────────────────────────────────────────────


def test_claims_are_added_only_when_set(monkeypatch):
    from core.agent_tokens import mint_agent_token
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "63" * 32)
    kw = dict(user_sub="u", agent_id="bot", agent_instance_id="i", tenant_id="t",
              build_hash="h", model_version="m", session_id="s")
    plain = decode_jwt_unverified(mint_agent_token(**kw))
    assert "runtime_profile" not in plain and "runtime_profile_hash" not in plain
    h = "sha256:" + "a" * 64
    bound = decode_jwt_unverified(mint_agent_token(**kw, runtime_profile="research-agent",
                                                   runtime_profile_hash=h))
    assert bound["runtime_profile"] == "research-agent" and bound["runtime_profile_hash"] == h


def test_ttl_is_capped_by_the_profile():
    from api.routes_agent_auth import _profile_capped_ttl
    tenant, _ = _setup()
    assert _profile_capped_ttl(tenant, "bot", 900) == 600
    assert _profile_capped_ttl(tenant, "bot", 300) == 300
    assert _profile_capped_ttl(tenant, "someone-else", 900) == 900


# ── cap/mint attestation ─────────────────────────────────────────────


def test_enforce_refuses_missing_and_stale_hashes_and_accepts_the_current_one():
    tenant, h = _setup("enforce")
    with pytest.raises(HTTPException) as e:
        _mint(tenant, _token())
    assert e.value.status_code == 403
    with pytest.raises(HTTPException):
        _mint(tenant, _token(runtime_profile_hash="sha256:" + "0" * 64))
    assert _mint(tenant, _token(runtime_profile_hash=h)).cap_token


def test_warn_mints_but_audits_and_records_drift():
    from storage.decision_audit import query_decisions
    tenant, h = _setup("warn")
    assert _mint(tenant, _token(runtime_profile_hash="sha256:" + "1" * 64)).cap_token
    rows = query_decisions(tenant_id=tenant, guardrail="runtime_attestation")
    assert rows and rows[0]["action"] == "warn"
    drift = attest.list_drift(tenant, "research-agent", h)
    assert drift[0]["instance"] == "sbx-1" and drift[0]["attested_hash"].startswith("sha256:1111")


def test_off_and_unbound_agents_are_unchanged():
    tenant, _ = _setup("off")
    assert _mint(tenant, None).cap_token
    other = "at" + uuid.uuid4().hex[:8]
    assert _mint(other, None).cap_token


def test_a_profile_change_makes_running_sandboxes_stale():
    tenant, h1 = _setup("enforce")
    assert _mint(tenant, _token(runtime_profile_hash=h1)).cap_token
    changed = copy.deepcopy(TEMPLATES["research-agent"])
    changed["network"]["allow"].append({"host": "api.example.org"})
    changed["identity"] = {"require_attestation": "enforce"}
    h2 = profile_hash(rt_store.save_profile(tenant, "research-agent", changed))
    rc.invalidate(tenant)
    with pytest.raises(HTTPException):
        _mint(tenant, _token(runtime_profile_hash=h1))
    stale = attest.list_drift(tenant, "research-agent", h2)
    assert [s["attested_hash"] for s in stale] == [h1]
    assert _mint(tenant, _token(runtime_profile_hash=h2)).cap_token


# ── verified identity requirement ────────────────────────────────────


def test_identity_requirement():
    tenant, _ = _setup()
    blocked = attest.identity_requirement(tenant, "bot", agent_verified=False)
    assert blocked["action"] == "block" and "verified identity" in blocked["message"]
    assert attest.identity_requirement(tenant, "bot", agent_verified=True) is None
    assert attest.identity_requirement(tenant, "unbound", agent_verified=False) is None


# ── through the app ──────────────────────────────────────────────────


@pytest.fixture
def app():
    from core.app import create_app
    return create_app()


def test_tool_check_refuses_an_asserted_identity_and_drift_endpoint(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "at" + uuid.uuid4().hex[:8]
    key = "sk-at-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key, "X-User-Role": "dev"})
    prof = copy.deepcopy(TEMPLATES["research-agent"])
    prof["identity"] = {"require_agent_token": True, "require_attestation": "warn"}
    c.put("/v1/tenant/me/runtime-profiles/research-agent", json=prof)
    c.post("/v1/agents/registry", json={"agent_id": "bot", "tools": ["fetch"],
                                        "role_permissions": {"dev": ["fetch"]},
                                        "runtime_profile": "research-agent"})
    r = c.post("/v1/shield/tool/check", json={"agent_key": "bot", "tool_name": "fetch",
                                             "tool_params": {"url": "https://api.github.com/x"},
                                             "user_role": "dev"}).json()
    assert r["allowed"] is False
    assert "verified identity" in next(g for g in r["guardrail_results"]
                                       if g["guardrail"] == "runtime_boundary")["message"]
    d = c.get("/v1/tenant/me/runtime-profiles/research-agent/drift").json()
    assert d["attestation"] == "warn" and d["stale_count"] == 0
