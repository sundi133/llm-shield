"""Proof-of-possession for agent tokens: a stolen token is useless.

`grep -c cnf core/agent_tokens.py` used to return 0. Shield's own agent
credential was a bearer token — a copy in a log file, crash dump, or proxy
access log worked until it expired. Meanwhile core/dpop.py was a complete DPoP
implementation, applied to *external* IdP tokens and never to Shield's own.

The load-bearing test here is `test_a_stolen_token_is_useless_without_the_key`.
Everything else supports it.

Spec: docs/spec-agent-token-pop.md
"""
from __future__ import annotations

import base64
import json
import time
from typing import Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api.routes_agent_auth import (router as agent_auth_router,
                                   tenant_router as agent_auth_tenant_router)
from core import dpop
from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import (POP_FAILED, POP_UNBOUND, POP_VERIFIED,
                               agent_token_pop_mode, decode_claims_unverified,
                               pop_allow_unbound, reset_signer_cache_for_tests,
                               verify_agent_token,
                               warn_if_allow_unbound_is_inert)
from storage.revocation import clear_all_for_tests

TENANT = "t1"
PROXY_SECRET = "pop-proxy-secret"

_ENV_KEYS = ("SHIELD_AGENT_TOKEN_POP", "SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND",
             "SHIELD_TRUSTED_PROXY_ONLY", "SHIELD_TRUSTED_PROXY_SECRET",
             "SHIELD_MAX_DELEGATION_DEPTH", "SHIELD_DELEGATION_PARENT_PROOF")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Keypair:
    """An Ed25519 keypair the 'agent' holds. Only the public half is sent."""

    def __init__(self):
        self.sk = ed25519.Ed25519PrivateKey.generate()
        raw = self.sk.public_key().public_bytes_raw()
        self.jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw)}

    def proof(self, method="POST", url="http://testserver/v1/shield/cap/mint",
              *, jti=None, iat=None):
        header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": self.jwk}
        payload = {"htm": method, "htu": url,
                   "jti": jti or _b64(str(time.time_ns()).encode()),
                   "iat": int(iat if iat is not None else time.time())}
        signing_input = f"{_b64(json.dumps(header).encode())}." \
                        f"{_b64(json.dumps(payload).encode())}"
        sig = self.sk.sign(signing_input.encode())
        return f"{signing_input}.{_b64(sig)}"


class _FakeTenantAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


@pytest.fixture
def app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "admin")
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)

    reset_signer_cache_for_tests()
    clear_all_for_tests()
    dpop.clear_jti_store_for_tests()

    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    from core.rbac import enforcer
    monkeypatch.setattr(enforcer, "_agents", {})
    monkeypatch.setattr(enforcer, "_roles", {})

    application = FastAPI()
    application.add_middleware(_FakeTenantAuthMiddleware)
    application.add_middleware(AgentIdentityMiddleware)
    application.include_router(agent_auth_router)
    application.include_router(agent_auth_tenant_router)

    @application.get("/probe")
    async def probe(request: Request):
        ident = getattr(request.state, "identity", None)
        return {"agent_id": getattr(ident, "agent_id", None),
                "cnf_jkt": getattr(ident, "cnf_jkt", ""),
                "pop_verified": getattr(ident, "pop_verified", None)}

    yield application

    reset_signer_cache_for_tests()
    clear_all_for_tests()
    dpop.clear_jti_store_for_tests()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def key():
    return Keypair()


def _mint(client, **body):
    payload = dict(user_sub="alice", agent_id="billing-bot",
                   agent_instance_id="inst-1", tenant_id=TENANT,
                   build_hash="b", model_version="m", session_id="s",
                   ttl_seconds=300)
    payload.update(body)
    r = client.post("/v1/shield/auth/agent-token",
                    headers={"X-Admin-Key": "admin"}, json=payload)
    assert r.status_code == 200, r.text
    return r.json()["agent_token"]


PROBE = "http://testserver/probe"


def _probe(client, token, proof=None, proxy_token=None):
    headers = {"X-Agent-Token": token}
    if proof:
        headers["X-Agent-DPoP"] = proof
    if proxy_token:
        headers["X-Shield-Proxy-Token"] = proxy_token
    return client.get("/probe", headers=headers)


# ── Minting ──────────────────────────────────────────────────────────────


def test_no_jwk_means_no_cnf(client):
    """Byte-compatible with every token issued before this existed."""
    assert "cnf" not in decode_claims_unverified(_mint(client))


def test_public_jwk_binds_the_thumbprint(client, key):
    claims = decode_claims_unverified(_mint(client, agent_jwk=key.jwk))
    assert claims["cnf"]["jkt"] == dpop.jwk_thumbprint(key.jwk)


def test_cnf_is_minted_even_when_enforcement_is_off(client, key, monkeypatch):
    """Rung 1 of the migration: a fleet starts binding while nothing is
    enforced, so the operator can watch the audit before flipping the mode."""
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP", "off")
    assert "cnf" in decode_claims_unverified(_mint(client, agent_jwk=key.jwk))


def test_private_jwk_is_refused(client, key):
    """A client SDK bug that posts the full JWK is far likelier than an attack,
    and accepting it would put private key material in Shield's logs."""
    private = dict(key.jwk, d="c2VjcmV0LWtleS1tYXRlcmlhbA")
    r = client.post("/v1/shield/auth/agent-token",
                    headers={"X-Admin-Key": "admin"},
                    json=dict(user_sub="a", agent_id="billing-bot",
                              agent_instance_id="i", tenant_id=TENANT,
                              build_hash="b", model_version="m",
                              session_id="s", agent_jwk=private))
    assert r.status_code == 400
    assert "c2VjcmV0" not in r.text, "the key was echoed back into the response"


def test_malformed_jwk_is_refused(client):
    r = client.post("/v1/shield/auth/agent-token",
                    headers={"X-Admin-Key": "admin"},
                    json=dict(user_sub="a", agent_id="billing-bot",
                              agent_instance_id="i", tenant_id=TENANT,
                              build_hash="b", model_version="m",
                              session_id="s", agent_jwk={"kty": "nonsense"}))
    assert r.status_code == 400


def test_tenant_route_binds_too(client, key):
    """Both mint endpoints, or the second is a way to get an unbound token."""
    r = client.post("/v1/tenant/me/agent-auth/agent-token",
                    headers={"X-API-Key": TENANT},
                    json=dict(user_sub="a", agent_id="billing-bot",
                              agent_instance_id="i", build_hash="b",
                              model_version="m", session_id="s",
                              agent_jwk=key.jwk))
    assert r.status_code == 200
    assert "cnf" in decode_claims_unverified(r.json()["agent_token"])


def test_identity_carries_the_thumbprint(client, key):
    identity = verify_agent_token(_mint(client, agent_jwk=key.jwk))
    assert identity.cnf_jkt == dpop.jwk_thumbprint(key.jwk)


# ── required: the point of the feature ───────────────────────────────────


@pytest.fixture
def required(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP", "required")
    return monkeypatch


def test_a_stolen_token_is_useless_without_the_key(client, key, required):
    """THE test.

    The attacker has the complete token string — everything that leaks in a log
    file, a crash dump, or a proxy access log. They do not have the private key,
    which never left the agent process.
    """
    token = _mint(client, agent_jwk=key.jwk)

    legitimate = _probe(client, token, key.proof(method="GET", url=PROBE))
    assert legitimate.status_code == 200
    assert legitimate.json()["pop_verified"] is True

    stolen = _probe(client, token)          # same token, no private key
    assert stolen.status_code == 401
    assert stolen.json()["error"] == "agent_pop_required"


def test_a_proof_from_a_different_key_is_refused(client, key, required):
    token = _mint(client, agent_jwk=key.jwk)
    attacker = Keypair()
    r = _probe(client, token, attacker.proof(method="GET", url=PROBE))
    assert r.status_code == 401


def test_a_proof_for_a_different_method_is_refused(client, key, required):
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token, key.proof(method="DELETE", url=PROBE))
    assert r.status_code == 401


def test_a_proof_for_a_different_url_is_refused(client, key, required):
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token, key.proof(method="GET",
                                        url="http://evil.example/probe"))
    assert r.status_code == 401


def test_a_replayed_proof_is_refused(client, key, required):
    """A proof captured in flight must not be reusable."""
    token = _mint(client, agent_jwk=key.jwk)
    proof = key.proof(method="GET", url=PROBE)
    assert _probe(client, token, proof).status_code == 200
    assert _probe(client, token, proof).status_code == 401


def test_a_stale_proof_is_refused(client, key, required):
    token = _mint(client, agent_jwk=key.jwk)
    old = key.proof(method="GET", url=PROBE, iat=time.time() - 600)
    assert _probe(client, token, old).status_code == 401


def test_garbage_proof_is_refused(client, key, required):
    token = _mint(client, agent_jwk=key.jwk)
    assert _probe(client, token, "not-a-proof").status_code == 401


def test_unbound_legacy_token_is_refused(client, required):
    assert _probe(client, _mint(client)).status_code == 401


def test_allow_unbound_keeps_legacy_clients_working(client, required):
    """The migration rung. Going straight from 'deny nothing' to 'deny every
    legacy token' is where outages live."""
    required.setenv("SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND", "true")
    r = _probe(client, _mint(client))
    assert r.status_code == 200
    assert r.json()["pop_verified"] is False


def test_allow_unbound_does_not_excuse_a_bound_token(client, key, required):
    """It waives the requirement for tokens that never had a key, not for one
    that has a key and failed to prove it."""
    required.setenv("SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND", "true")
    assert _probe(client, _mint(client, agent_jwk=key.jwk)).status_code == 401


# ── optional: observe, deny nothing ──────────────────────────────────────


@pytest.fixture
def optional(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP", "optional")
    return monkeypatch


def test_optional_records_but_never_denies(client, key, optional):
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token)                       # no proof at all
    assert r.status_code == 200
    assert r.json()["pop_verified"] is False


def test_optional_records_a_success(client, key, optional):
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token, key.proof(method="GET", url=PROBE))
    assert r.json()["pop_verified"] is True


def test_optional_tolerates_a_bad_proof(client, key, optional):
    token = _mint(client, agent_jwk=key.jwk)
    assert _probe(client, token, "garbage").status_code == 200


# ── off: costs nothing ───────────────────────────────────────────────────


def test_off_never_calls_the_verifier(client, key, monkeypatch):
    """Proves the zero-cost claim, not merely the behaviour."""
    import core.agent_identity_middleware as mw

    calls = []
    monkeypatch.setattr(mw, "verify_agent_pop",
                        lambda *a, **k: calls.append(1) or (POP_FAILED, "x"))
    token = _mint(client, agent_jwk=key.jwk)
    assert _probe(client, token).status_code == 200
    assert calls == []


def test_off_is_the_default():
    assert agent_token_pop_mode() == "off"


def test_unknown_mode_falls_back_to_off(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP", "reqiured")
    assert agent_token_pop_mode() == "off"


# ── The gateway exemption ────────────────────────────────────────────────


def test_trusted_proxy_is_exempt_in_required(client, key, required):
    """Behind an LLM gateway a proof CANNOT exist: DPoP binds htm/htu, the
    agent signs for the gateway's URL, Shield receives its own. The gateway
    authenticates itself with a shared secret instead."""
    required.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    required.setenv("SHIELD_TRUSTED_PROXY_SECRET", PROXY_SECRET)
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token, proxy_token=PROXY_SECRET)
    assert r.status_code == 200
    assert r.json()["pop_verified"] is False, "vouched is not proven"


def test_the_exemption_needs_the_secret(client, key, required):
    required.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    required.setenv("SHIELD_TRUSTED_PROXY_SECRET", PROXY_SECRET)
    token = _mint(client, agent_jwk=key.jwk)
    assert _probe(client, token, proxy_token="wrong").status_code == 401


def test_the_exemption_needs_the_boundary_enabled(client, key, required):
    """A matching secret with the boundary off must not exempt anything."""
    required.setenv("SHIELD_TRUSTED_PROXY_SECRET", PROXY_SECRET)
    token = _mint(client, agent_jwk=key.jwk)
    assert _probe(client, token, proxy_token=PROXY_SECRET).status_code == 401


def test_a_valid_proof_from_the_proxy_still_counts_as_proven(client, key, required):
    """The exemption relaxes the requirement; it does not skip verification."""
    required.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    required.setenv("SHIELD_TRUSTED_PROXY_SECRET", PROXY_SECRET)
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token, key.proof(method="GET", url=PROBE),
               proxy_token=PROXY_SECRET)
    assert r.json()["pop_verified"] is True


# ── Independence and hygiene ─────────────────────────────────────────────


def test_no_agent_token_is_untouched(client, required):
    """The middleware returns early when the header is absent. PoP must not
    turn 'no token' into a rejection."""
    assert client.get("/probe").status_code == 200


def test_workload_token_binding_is_unaffected(client, key, required, monkeypatch):
    """SHIELD_TOKEN_BINDING governs external IdP tokens and keeps its meaning.
    Separate headers exist precisely so the two can be enabled independently."""
    monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
    token = _mint(client, agent_jwk=key.jwk)
    r = _probe(client, token, key.proof(method="GET", url=PROBE))
    assert r.status_code == 200


def test_allow_unbound_outside_required_warns(monkeypatch, caplog):
    import logging
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP", "optional")
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND", "true")
    with caplog.at_level(logging.WARNING):
        assert warn_if_allow_unbound_is_inert() is True
    assert "no effect" in caplog.text


def test_no_warning_when_allow_unbound_is_meaningful(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP", "required")
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND", "true")
    assert warn_if_allow_unbound_is_inert() is False


def test_allow_unbound_defaults_off():
    assert pop_allow_unbound() is False
