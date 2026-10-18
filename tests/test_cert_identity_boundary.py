"""Certificate identity, task 1: close the bypass.
Spec: docs/specs/agent-cert-identity.md.

A certificate, and so its fingerprint, is public. Before this, any caller could
send a registered agent's fingerprint in X-Client-Cert-Fingerprint and be
recorded as that agent with trust "high"; and A2A, which no middleware labels,
fell back to the registry's "high" for any agent with a registered certificate
that the caller merely named. Both passed tool gates that require "high"."""

import asyncio
import logging
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes

from core import cert_identity as ci
from core.identity import IdentityTuple
from guardrails.agentic.identity import cert_registry as reg
from guardrails.agentic.identity.cert_identity import CertIdentityGuardrail
from storage.tenant_store import kv_set
from tests.test_agent_cert_identity import _cert, _pem, _xfcc, pki  # noqa: F401

SECRET = "proxy-secret"
PROXY = {"X-Shield-Proxy-Token": SECRET}
ENV = ("SHIELD_TRUSTED_PROXY_ONLY", "SHIELD_TRUSTED_PROXY_SECRET", "SHIELD_TRUSTED_PROXY_IPS",
       "SHIELD_MTLS_ENABLED", "SHIELD_SPIFFE_ENABLED", "SHIELD_CERT_IDENTITY_TRUST_HEADER",
       "SHIELD_REGISTRY_WRITE_SCOPE")


@pytest.fixture(scope="module", autouse=True)
def _memory():
    with patch("storage.tenant_store._get_redis", return_value=None), \
            patch("guardrails.agentic.identity.cert_registry._get_redis", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ci.reset_cache()
    ci._warned.clear()
    for k in ENV:
        monkeypatch.delenv(k, raising=False)
    yield
    ci.reset_cache()


def boundary(monkeypatch, on=True):
    if on:
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", SECRET)


def hatch(monkeypatch):
    monkeypatch.setenv("SHIELD_CERT_IDENTITY_TRUST_HEADER", "true")


def fp_colon(cert):
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


class _Gated(CertIdentityGuardrail):
    """The guardrail as a tenant configures it: "refund" requires high trust."""
    _temp_config = {"enabled": True, "action": "block",
                    "settings": {"min_trust_for_tools": {"refund": "high"}}}


def gate(ctx):
    return asyncio.run(_Gated().check("", {"tool_name": "refund", **ctx}))


# ── the apps ─────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    import config.schema as cs
    from fastapi import Request
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    seen = {}

    @application.get("/v1/shield/_trust_probe")
    async def _probe(request: Request):
        s = request.state
        seen.clear()
        seen.update(agent=getattr(s, "agent_key", None), trust=getattr(s, "trust_level", None),
                    method=getattr(s, "identity_method", None),
                    by=getattr(s, "identity_verified_by", None),
                    mtls=getattr(s, "mtls_identity", None),
                    spiffe=getattr(s, "spiffe_identity", None))
        return {}

    application.seen = seen
    yield application
    cs.config = original


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid = "cb" + uuid.uuid4().hex[:10]
    kv_set(f"agents:{tid}", {a: {"agent_id": a, "status": "active"} for a in ("billing-bot", "support-bot")})
    key = "sk-cb-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid

    def probe(headers=None):
        c.get("/v1/shield/_trust_probe", headers=headers or {})
        return dict(app.seen)
    c.probe = probe
    return c


@pytest.fixture
def pinned(client, pki):
    reg.register_cert(client.tenant_id, "billing-bot", cert_pem=_pem(pki.leaf))
    return fp_colon(pki.leaf)


# ── 1. the guard path's fingerprint header ──────────────────────────


@pytest.fixture
def cert_feature(monkeypatch):
    monkeypatch.setattr("core.middleware.CERT_IDENTITY_ENABLED", True)


def test_a_spoofed_fingerprint_no_longer_identifies_anyone(client, pinned, cert_feature):
    s = client.probe({"X-Client-Cert-Fingerprint": pinned})
    assert (s["agent"], s["trust"], s["method"]) == (None, "low", "anonymous")
    s = client.probe({"X-Client-Cert-Fingerprint": pinned, "X-Agent-Key": "billing-bot"})
    assert (s["trust"], s["method"]) == ("medium", "string_key")


def test_the_boundary_on_without_the_secret_is_still_ignored(client, pinned, cert_feature, monkeypatch):
    boundary(monkeypatch)
    s = client.probe({"X-Client-Cert-Fingerprint": pinned, "X-Shield-Proxy-Token": "wrong"})
    assert s["trust"] == "low" and s["agent"] is None


def test_from_the_trusted_proxy_it_is_honored_and_says_how(client, pinned, cert_feature, monkeypatch):
    boundary(monkeypatch)
    s = client.probe({"X-Client-Cert-Fingerprint": pinned, **PROXY})
    assert (s["agent"], s["trust"], s["method"], s["by"]) == ("billing-bot", "high", "cert", "pinned")


def test_the_escape_hatch_restores_the_old_behavior_and_logs_once(client, pinned, cert_feature,
                                                                   monkeypatch, caplog):
    hatch(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="votal.cert_identity"):
        a = client.probe({"X-Client-Cert-Fingerprint": pinned})
        b = client.probe({"X-Client-Cert-Fingerprint": pinned})
    assert a["trust"] == b["trust"] == "high" and a["agent"] == "billing-bot"
    assert len([r for r in caplog.records if "SHIELD_CERT_IDENTITY_TRUST_HEADER is on" in r.getMessage()]) == 1


def test_the_escape_hatch_also_covers_untrusted_peers_with_the_boundary_on(client, pinned, cert_feature,
                                                                            monkeypatch):
    boundary(monkeypatch)
    hatch(monkeypatch)
    assert client.probe({"X-Client-Cert-Fingerprint": pinned})["trust"] == "high"


def test_an_ignored_header_says_what_to_set_once(client, pinned, cert_feature, caplog):
    with caplog.at_level(logging.WARNING, logger="votal.cert_identity"):
        client.probe({"X-Client-Cert-Fingerprint": pinned})
        client.probe({"X-Client-Cert-Fingerprint": pinned})
    msgs = [r.getMessage() for r in caplog.records if "header was ignored" in r.getMessage()]
    assert len(msgs) == 1 and "SHIELD_TRUSTED_PROXY_SECRET" in msgs[0]


def test_colon_sha256_and_plain_forms_all_match(client, pki, cert_feature, monkeypatch):
    boundary(monkeypatch)
    raw = pki.leaf.fingerprint(hashes.SHA256()).hex()
    reg.register_cert(client.tenant_id, "billing-bot", fingerprint=fp_colon(pki.leaf))   # legacy form
    for given in (raw, raw.upper(), fp_colon(pki.leaf), "SHA256:" + fp_colon(pki.leaf)):
        assert client.probe({"X-Client-Cert-Fingerprint": given, **PROXY})["agent"] == "billing-bot", given


# ── 2. the mTLS and SPIFFE middlewares ──────────────────────────────


def test_mtls_without_the_boundary_is_ignored_now(client, pki, monkeypatch):
    monkeypatch.setenv("SHIELD_MTLS_ENABLED", "true")
    reg.register_cert(client.tenant_id, "billing-bot", cert_pem=_pem(pki.leaf))
    s = client.probe({"X-Forwarded-Client-Cert": _xfcc(pki.leaf), "X-Agent-Key": "billing-bot"})
    assert s["mtls"] is None and s["trust"] == "medium"


def test_mtls_from_the_trusted_proxy_earns_high(client, pki, monkeypatch):
    monkeypatch.setenv("SHIELD_MTLS_ENABLED", "true")
    boundary(monkeypatch)
    reg.register_cert(client.tenant_id, "billing-bot", cert_pem=_pem(pki.leaf))
    s = client.probe({"X-Forwarded-Client-Cert": _xfcc(pki.leaf), **PROXY})
    assert (s["agent"], s["trust"], s["method"], s["by"]) == ("billing-bot", "high", "mtls", "pinned")


def test_mtls_under_the_escape_hatch_is_honored_but_never_satisfies_identity_require(client, pki,
                                                                                     monkeypatch):
    monkeypatch.setenv("SHIELD_MTLS_ENABLED", "true")
    hatch(monkeypatch)
    reg.register_cert(client.tenant_id, "billing-bot", cert_pem=_pem(pki.leaf))
    s = client.probe({"X-Forwarded-Client-Cert": _xfcc(pki.leaf)})
    assert s["mtls"]["agent_key"] == "billing-bot"
    req = SimpleNamespace(state=SimpleNamespace(mtls_identity=s["mtls"]))
    assert ci.verified_cert_agent(req) == ""          # the boundary is off


def test_spiffe_without_the_boundary_ignores_the_header(monkeypatch):
    from core.oauth.spiffe_middleware import SPIFFEMiddleware
    monkeypatch.setenv("SHIELD_SPIFFE_ENABLED", "true")
    called = {}

    async def validate(self, cert, request):
        called["validated"] = True
        return {"agent_id": "x"}

    async def nxt(request):
        return "ok"
    req = SimpleNamespace(headers={"X-Client-Cert": "-----BEGIN CERTIFICATE-----"},
                          state=SimpleNamespace(), client=None)
    with patch.object(SPIFFEMiddleware, "_validate_x509_svid", validate):
        mw = SPIFFEMiddleware(app=None)
        asyncio.run(mw.dispatch(req, nxt))
        assert "validated" not in called and not hasattr(req.state, "spiffe_identity")
        boundary(monkeypatch)
        req.headers = {"X-Client-Cert": "-----BEGIN CERTIFICATE-----", **PROXY}
        asyncio.run(mw.dispatch(req, nxt))
        assert called["validated"] and req.state.spiffe_identity == {"agent_id": "x"}


# ── 3. verified agent tokens ───────────────────────────────────────


def _token(agent="billing-bot", pop=False):
    return IdentityTuple(user_sub="u1", agent_id=agent, agent_instance_id="i1", tenant_id="t",
                         build_hash="b", model_version="m", session_id="s", trust_level="high",
                         identity_method="agent_token", pop_verified=pop)


@pytest.mark.parametrize("pop,claim,want", [
    (True, "billing-bot", ("high", "agent_token", "dpop")),
    (False, "billing-bot", ("medium", "agent_token", "bearer")),
    (True, "support-bot", ("medium", "string_key", None)),     # the token names someone else
    (True, None, ("low", "anonymous", None)),
])
def test_a_dpop_verified_token_earns_high_and_a_bearer_token_does_not(pop, claim, want):
    req = SimpleNamespace(state=SimpleNamespace(identity=_token(pop=pop)), headers={})
    t = ci.request_trust(req, claim)
    assert (t["trust_level"], t["identity_method"], t["verified_by"]) == want


def test_an_mtls_synthesized_identity_is_not_a_token():
    from dataclasses import replace
    req = SimpleNamespace(state=SimpleNamespace(identity=replace(_token(pop=True), identity_method="mtls")),
                          headers={})
    assert ci.request_trust(req, "billing-bot")["trust_level"] == "medium"


# ── 4. the tool gate, end to end ───────────────────────────────────


def test_the_spoof_is_blocked_and_the_proxy_passes_at_a_high_gate(client, pinned, cert_feature,
                                                                   monkeypatch):
    boundary(monkeypatch)
    spoof = client.probe({"X-Client-Cert-Fingerprint": pinned, "X-Agent-Key": "billing-bot"})
    r = gate({"agent_key": "billing-bot", "trust_level": spoof["trust"],
              "identity_method": spoof["method"], "tenant_id": client.tenant_id})
    assert not r.passed and r.details["agent_trust_level"] == "medium"
    proxied = client.probe({"X-Client-Cert-Fingerprint": pinned, **PROXY})
    r = gate({"agent_key": proxied["agent"], "trust_level": proxied["trust"],
              "identity_method": proxied["method"], "verified_by": proxied["by"],
              "tenant_id": client.tenant_id})
    assert r.passed and r.details["verified_by"] == "pinned"


# ── 5. A2A ──────────────────────────────────────────────────────────


def _a2a(tenant_id, agent="billing-bot", state=None):
    from api.routes_a2a import _run_a2a_authz
    st = state or SimpleNamespace(agent_key=agent, trust_level=None, identity_method=None)
    req = SimpleNamespace(state=st, headers={"X-Agent-Key": agent})
    with patch("api.routes_a2a._A2A_AUTHZ_GUARDS", [("cert_identity", _Gated)]):
        return asyncio.run(_run_a2a_authz(req, tenant_id, {"metadata": {"tool_name": "refund"}}, "s1"))


@pytest.fixture
def cert_agent(pki):
    tid = "a2a" + uuid.uuid4().hex[:8]
    kv_set(f"agents:{tid}", {"billing-bot": {"agent_id": "billing-bot", "status": "active"}})
    reg.register_cert(tid, "billing-bot", cert_pem=_pem(pki.leaf))
    assert reg.get_agent_trust(tid, "billing-bot")["trust_level"] == "high"   # the old fallback
    return tid


def test_a2a_naming_a_cert_agent_no_longer_borrows_its_high_trust(cert_agent):
    out = _a2a(cert_agent)
    assert out["blocked"]
    assert out["results"][0]["details"]["agent_trust_level"] == "medium"


def test_a2a_with_a_dpop_verified_token_passes(cert_agent):
    st = SimpleNamespace(agent_key="billing-bot", trust_level=None, identity_method=None,
                         identity=_token(pop=True))
    out = _a2a(cert_agent, state=st)
    assert not out["blocked"], out


def test_a2a_escape_hatch_restores_the_registry_fallback(cert_agent, monkeypatch):
    hatch(monkeypatch)
    assert not _a2a(cert_agent)["blocked"]


# ── 6. proxy secret rotation ───────────────────────────────────────


def test_the_proxy_secret_can_be_rotated(monkeypatch):
    from core.proxy_trust import peer_is_trusted
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", "old-secret, new-secret")
    req = lambda tok: SimpleNamespace(headers={"X-Shield-Proxy-Token": tok}, client=None)  # noqa: E731
    assert peer_is_trusted(req("old-secret")) and peer_is_trusted(req("new-secret"))
    assert not peer_is_trusted(req("other")) and not peer_is_trusted(req(""))
    assert not peer_is_trusted(req("old-secret, new-secret"))
