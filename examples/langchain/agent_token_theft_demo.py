#!/usr/bin/env python3
"""Steal an agent token and watch it fail.

Runs the real path in-process: Shield mints a bound token, the agent proves
possession, and then a second "process" that has the complete token string —
but not the private key — tries the same call.

    python examples/langchain/agent_token_theft_demo.py

The attacker here holds everything that actually leaks: the full token, from a
log file, a crash dump, an error report, or a proxy access log. What they do
not have is the private key, which never left the agent process and was never
sent to Shield.

See docs/agent-governance.md and docs/spec-agent-token-pop.md.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from core import dpop  # noqa: E402
from core.agent_tokens import (POP_VERIFIED, decode_claims_unverified,  # noqa: E402
                               mint_agent_token, verify_agent_pop,
                               verify_agent_token)

G, R, Y, B, DIM, Z = ("\033[32m", "\033[31m", "\033[33m", "\033[1m",
                      "\033[2m", "\033[0m")

URL = "https://api.guardrails.votal.ai/v1/shield/cap/mint"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Agent:
    """Holds a keypair. Only the public half is ever sent to Shield."""

    def __init__(self):
        self._sk = ed25519.Ed25519PrivateKey.generate()
        self.public_jwk = {"kty": "OKP", "crv": "Ed25519",
                           "x": _b64(self._sk.public_key().public_bytes_raw())}

    def proof(self, method="POST", url=URL):
        header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": self.public_jwk}
        payload = {"htm": method, "htu": url,
                   "jti": _b64(str(time.time_ns()).encode()),
                   "iat": int(time.time())}
        si = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
        return f"{si}.{_b64(self._sk.sign(si.encode()))}"


class Request:
    """Just enough of a request for the possession check."""

    def __init__(self, proof=None, method="POST", url=URL):
        self.headers = {"X-Agent-DPoP": proof} if proof else {}
        self.method = method
        self.url = url
        self.client = None


def attempt(label, identity, request, *, expect_ok):
    status, err = verify_agent_pop(request, identity)
    ok = status == POP_VERIFIED
    mark = f"{G}allowed{Z}" if ok else f"{R}refused{Z}"
    print(f"   {label:<38} {mark}  {DIM}{err or status}{Z}")
    if ok is not expect_ok:
        print(f"   {R}!! unexpected outcome — the control is not working{Z}")


def main():
    os.environ["SHIELD_AGENT_TOKEN_POP"] = "required"
    os.environ.pop("SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND", None)
    os.environ.pop("SHIELD_TRUSTED_PROXY_ONLY", None)

    print(f"{B}Agent token theft — with and without proof-of-possession{Z}")

    # ── 1. The old shape ────────────────────────────────────────────────
    print(f"\n{B}1. An unbound token is a bearer token{Z}")
    unbound = mint_agent_token(
        user_sub="alice", agent_id="billing-bot", agent_instance_id="inst-1",
        tenant_id="acme", build_hash="b1", model_version="m1",
        session_id="s1", ttl_seconds=300)
    claims = decode_claims_unverified(unbound)
    print(f"   cnf claim: {R}{claims.get('cnf', 'absent')}{Z}")
    print(f"   {DIM}Whoever holds this string can use it until it expires.{Z}")

    # ── 2. Bind it ──────────────────────────────────────────────────────
    print(f"\n{B}2. Bind the token to a keypair{Z}")
    agent = Agent()
    bound = mint_agent_token(
        user_sub="alice", agent_id="billing-bot", agent_instance_id="inst-1",
        tenant_id="acme", build_hash="b1", model_version="m1",
        session_id="s1", ttl_seconds=300, agent_jwk=agent.public_jwk)
    identity = verify_agent_token(bound)
    print(f"   cnf.jkt:  {G}{identity.cnf_jkt}{Z}")
    print(f"   {DIM}Shield stores no keys. Only this thumbprint, inside the "
          f"signed token.{Z}")

    # ── 3. The agent, then the thief ────────────────────────────────────
    print(f"\n{B}3. The legitimate agent vs. someone holding the same token{Z}")
    attempt("agent, with its private key", identity,
            Request(agent.proof()), expect_ok=True)
    attempt("thief, token only", identity,
            Request(), expect_ok=False)
    attempt("thief, with their own keypair", identity,
            Request(Agent().proof()), expect_ok=False)

    # ── 4. Replay and redirection ───────────────────────────────────────
    print(f"\n{B}4. A proof captured in flight{Z}")
    captured = agent.proof()
    attempt("first use (the real agent)", identity,
            Request(captured), expect_ok=True)
    attempt("replayed by an eavesdropper", identity,
            Request(captured), expect_ok=False)
    attempt("proof aimed at a different URL", identity,
            Request(agent.proof(url="https://evil.example/cap/mint")),
            expect_ok=False)
    attempt("proof aimed at a different method", identity,
            Request(agent.proof(method="DELETE")), expect_ok=False)

    print(f"\n{DIM}The attacker had the complete token every time. That is what "
          f"leaks.{Z}")
    print(f"{DIM}Docs: docs/agent-governance.md — section 5{Z}\n")


if __name__ == "__main__":
    main()
