"""The agent identity client helper (packages/shield-py/shield_agent.py).
Spec: docs/specs/agent-identity-poc.md.

Its proofs and thumbprints are checked with the server's own verifier
(core/dpop.py), so the two cannot drift apart unnoticed."""

import json
import os
import sys
import time

import httpx
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages", "shield-py"))

import shield_agent as sa  # noqa: E402
from core import dpop  # noqa: E402

URL = "https://shield.example.com/v1/shield/cap/mint"


def test_the_thumbprint_is_what_the_server_computes():
    key = sa.AgentKey.generate()
    assert key.thumbprint == dpop.jwk_thumbprint(key.jwk)
    assert set(key.jwk) == {"kty", "crv", "x"}                      # never the private part


def test_a_proof_verifies_with_the_servers_verifier():
    key = sa.AgentKey.generate()
    proof = sa.dpop_proof(key, "post", URL + "?ignored=1")
    p = dpop.verify_proof(proof, expected_jkt=key.thumbprint, http_method="POST", http_uri=URL)
    assert p.htm == "POST" and p.jti


@pytest.mark.parametrize("change,why", [
    (dict(method="GET"), "htm"), (dict(url="https://shield.example.com/v1/other"), "htu"),
    (dict(now=int(time.time()) - 3600), "expired"),
])
def test_a_proof_for_another_request_or_time_fails(change, why):
    key = sa.AgentKey.generate()
    proof = sa.dpop_proof(key, change.get("method", "POST"), change.get("url", URL), now=change.get("now"))
    with pytest.raises(dpop.DPoPError, match=why):
        dpop.verify_proof(proof, expected_jkt=key.thumbprint, http_method="POST", http_uri=URL)


def test_a_proof_from_another_key_fails():
    a, b = sa.AgentKey.generate(), sa.AgentKey.generate()
    with pytest.raises(dpop.DPoPError, match="does not match"):
        dpop.verify_proof(sa.dpop_proof(b, "POST", URL), expected_jkt=a.thumbprint,
                          http_method="POST", http_uri=URL)


def test_a_key_survives_a_pem_round_trip():
    key = sa.AgentKey.generate()
    assert sa.AgentKey.from_pem(key.to_pem()).thumbprint == key.thumbprint


# ── the agent against a scripted Shield ──────────────────────────────


class FakeShield:
    def __init__(self, mint_status=200, mint_detail=None, verify=None, ttl=900):
        self.calls, self.tokens = [], 0
        self.mint_status, self.mint_detail, self.verify, self.ttl = mint_status, mint_detail, verify, ttl

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        self.calls.append((request.method, request.url.path, dict(request.headers), body))
        if request.url.path == sa.TOKEN_PATH:
            self.tokens += 1
            return httpx.Response(200, json={"agent_token": f"tok{self.tokens}", "expires_in": self.ttl})
        if request.url.path == sa.MINT_PATH:
            if self.mint_status != 200:
                return httpx.Response(self.mint_status, json={"detail": self.mint_detail})
            return httpx.Response(200, json={"cap_token": "cap1", "expires_in": 60, "decision": {"ok": 1}})
        if request.url.path == sa.VERIFY_PATH:
            return httpx.Response(200, json=self.verify or {"valid": True, "claims": {"agent_id": "a"}})
        if request.url.path == sa.REVOKE_PATH:
            return httpx.Response(200, json={"revoked": True})
        return httpx.Response(404)


def _agent(shield, **kw):
    client = httpx.Client(transport=httpx.MockTransport(shield.handler))
    return sa.ShieldAgent("support-bot", "user-1", "s1", shield_url="https://shield.example.com",
                          api_key="sk-x", user_role="support", client=client, **kw)


def test_mint_sends_token_proof_key_and_role_and_binds_the_token():
    shield = FakeShield()
    agent = _agent(shield)
    cap = agent.mint("lookup", "ticket/1", tool_params={"id": 1})
    assert cap.token == "cap1" and cap.tool == "lookup"
    _, _, token_headers, token_body = shield.calls[0]
    assert token_headers["x-api-key"] == "sk-x" and token_body["agent_jwk"] == agent.key.jwk
    _, path, h, body = shield.calls[1]
    assert path == sa.MINT_PATH and h["x-agent-token"] == "tok1" and h["x-user-role"] == "support"
    dpop.verify_proof(h["x-agent-dpop"], expected_jkt=agent.key.thumbprint, http_method="POST",
                      http_uri="https://shield.example.com" + sa.MINT_PATH)
    assert body["tool_params"] == {"id": 1} and body["session_id"] == "s1"


def test_the_token_is_reused_then_refreshed_before_it_expires():
    shield = FakeShield(ttl=120)
    agent = _agent(shield, refresh_margin_s=60)
    agent.token(), agent.token()
    assert shield.tokens == 1
    agent._token_exp = time.time() + 30                         # inside the refresh margin
    agent.token()
    assert shield.tokens == 2


def test_an_approval_hold_is_its_own_exception():
    shield = FakeShield(403, {"reason": "approval_required", "request_id": "apr_1",
                              "required_approvals": 2, "expires_at": 9})
    with pytest.raises(sa.ApprovalRequired) as e:
        _agent(shield).mint("refund", "order/1")
    assert e.value.request_id == "apr_1" and e.value.required_approvals == 2


def test_a_denial_carries_its_reasons():
    shield = FakeShield(403, {"reasons": ["role 'support' may not use refund"]})
    with pytest.raises(sa.CapabilityDenied) as e:
        _agent(shield).mint("refund", "order/1")
    assert e.value.reasons == ["role 'support' may not use refund"] and e.value.status == 403


def test_other_failures_are_agent_identity_errors():
    shield = FakeShield(429, "rate limit exceeded")
    with pytest.raises(sa.AgentIdentityError, match="rate limit") as e:
        _agent(shield).mint("x", "y")
    assert not isinstance(e.value, sa.CapabilityDenied)


def test_an_unreachable_shield_is_an_error_not_a_grant():
    def boom(request):
        raise httpx.ConnectError("down")
    agent = sa.ShieldAgent("a", "u", "s", shield_url="https://s", api_key="k",
                           client=httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(sa.AgentIdentityError, match="unreachable"):
        agent.mint("x", "y")


def test_delegation_chains_the_token_and_uses_a_new_key():
    shield = FakeShield()
    parent = _agent(shield)
    child = parent.delegate("billing-sub")
    child.token()
    body = shield.calls[-1][3]
    assert body["parent_agent_token"] == "tok1" and body["agent_id"] == "billing-sub"
    assert child.key.thumbprint != parent.key.thumbprint and child.user_sub == "user-1"


def test_revoke_forgets_the_token():
    shield = FakeShield()
    agent = _agent(shield)
    agent.token()
    agent.revoke("compromised")
    assert shield.calls[-1][3]["agent_instance_id"] == agent.instance_id
    agent.token()
    assert shield.tokens == 2


def test_the_verifier_fails_closed():
    ok = sa.CapabilityVerifier("https://s", client=httpx.Client(
        transport=httpx.MockTransport(FakeShield().handler)))
    assert ok.verify("cap1", "lookup") == {"agent_id": "a"}
    bad = sa.CapabilityVerifier("https://s", client=httpx.Client(transport=httpx.MockTransport(
        FakeShield(verify={"valid": False, "error": "cap replay detected"}).handler)))
    with pytest.raises(sa.CapabilityInvalid) as e:
        bad.verify("cap1", "lookup")
    assert e.value.replayed


def test_bind_key_false_sends_a_bearer_token():
    shield = FakeShield()
    agent = _agent(shield, bind_key=False)
    agent.mint("lookup", "t")
    assert "agent_jwk" not in shield.calls[0][3] and "x-agent-dpop" not in shield.calls[1][2]
