"""CAEP / SSF: SET emission, emit-on-auto-revoke, and the secured receiver."""

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core import caep, auto_revoke
from core.identity import IdentityTuple
from core.jwt_utils import decode_jwt_unverified
from storage import revocation, agent_auth_stats as stats
from api.routes_ssf import router as ssf_router


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    revocation.clear_all_for_tests()
    stats.clear_for_tests()
    caep.reset_set_signer_cache_for_tests()
    for v in ("SHIELD_ENABLE_AUTO_REVOKE", "SHIELD_SSF_PUSH_URL",
              "SHIELD_SSF_RECEIVER_TOKEN", "SHIELD_SSF_TRUSTED_ISSUERS",
              "SHIELD_SSF_PRIVATE_KEY"):
        monkeypatch.delenv(v, raising=False)
    yield
    revocation.clear_all_for_tests()
    stats.clear_for_tests()


def _run(c):
    return asyncio.run(c)


def test_build_set_is_valid_caep_session_revoked():
    token = caep.build_set(
        caep.EVT_SESSION_REVOKED,
        {"format": "opaque", "id": "inst-1", "agent_instance_id": "inst-1"},
        {"reason": "prompt injection"},
    )
    claims = decode_jwt_unverified(token)
    assert claims["iss"] and claims["jti"] and claims["aud"]
    assert caep.EVT_SESSION_REVOKED in claims["events"]
    ev = claims["events"][caep.EVT_SESSION_REVOKED]
    assert ev["subject"]["agent_instance_id"] == "inst-1"
    assert ev["reason"] == "prompt injection"


def test_auto_revoke_emits_session_revoked(monkeypatch):
    monkeypatch.setenv("SHIELD_ENABLE_AUTO_REVOKE", "true")
    captured = {}

    async def fake_emit(*, agent_instance_id=None, user_sub=None, agent_id=None,
                        tenant_id=None, reason=""):
        captured.update(dict(agent_instance_id=agent_instance_id, reason=reason))
        return "set"

    monkeypatch.setattr(caep, "emit_session_revoked", fake_emit)
    out = _run(auto_revoke.maybe_auto_revoke(
        tenant_id="t1", agent_instance_id="inst-7", agent_id="bot",
        trigger="adversarial_detection", reason="prompt injection",
    ))
    assert out["revoked"] is True
    assert captured["agent_instance_id"] == "inst-7"


# ── receiver ────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(ssf_router)
    return TestClient(app)


def test_receiver_disabled_by_default(client):
    r = client.post("/v1/shield/ssf/events", content="{}")
    assert r.status_code == 503


def test_receiver_requires_bearer(client, monkeypatch):
    monkeypatch.setenv("SHIELD_SSF_RECEIVER_TOKEN", "s3cret")
    r = client.post("/v1/shield/ssf/events", content="{}",
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_receiver_session_revoked_revokes_instance(client, monkeypatch):
    monkeypatch.setenv("SHIELD_SSF_RECEIVER_TOKEN", "s3cret")
    body = json.dumps({
        "iss": "https://okta.example", "jti": "x", "iat": 1,
        "events": {caep.EVT_SESSION_REVOKED: {
            "subject": {"format": "opaque", "agent_instance_id": "inst-ext-1"}}},
    })
    r = client.post("/v1/shield/ssf/events", content=body,
                    headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 202, r.text
    assert revocation.is_instance_revoked("inst-ext-1") is True
    assert any(a["id"] == "inst-ext-1" for a in r.json()["applied"])


def test_receiver_device_compliant_is_ignored(client, monkeypatch):
    monkeypatch.setenv("SHIELD_SSF_RECEIVER_TOKEN", "s3cret")
    body = json.dumps({
        "iss": "https://edr.example", "jti": "y", "iat": 1,
        "events": {caep.EVT_DEVICE_COMPLIANCE: {
            "current_status": "compliant",
            "subject": {"agent_instance_id": "inst-ok"}}},
    })
    r = client.post("/v1/shield/ssf/events", content=body,
                    headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 202
    assert revocation.is_instance_revoked("inst-ok") is False


def test_receiver_untrusted_issuer_blocked(client, monkeypatch):
    monkeypatch.setenv("SHIELD_SSF_RECEIVER_TOKEN", "s3cret")
    monkeypatch.setenv("SHIELD_SSF_TRUSTED_ISSUERS", "https://okta.example")
    body = json.dumps({
        "iss": "https://evil.example", "jti": "z", "iat": 1,
        "events": {caep.EVT_SESSION_REVOKED: {"subject": {"agent_instance_id": "inst-bad"}}},
    })
    r = client.post("/v1/shield/ssf/events", content=body,
                    headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 403
    assert revocation.is_instance_revoked("inst-bad") is False


def test_ssf_configuration_lists_events(client):
    r = client.get("/v1/shield/ssf/.well-known/ssf-configuration")
    assert r.status_code == 200
    assert caep.EVT_SESSION_REVOKED in r.json()["events_supported"]
