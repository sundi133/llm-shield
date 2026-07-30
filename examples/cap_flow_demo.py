#!/usr/bin/env python3
"""Walk the capability-token flow end to end, and prove the properties.

    agent -> POST /auth/agent-token   AuthN: who is calling (identity tuple)
    agent -> POST /cap/mint           AuthZ: may it? -> cap bound to ONE action
    tool  -> POST /cap/verify         verify + BURN the nonce
    tool  -> executes

Running it is only half the point. Anyone can watch a happy path succeed; what
tells you the control works is what it REFUSES. So after the happy path this
replays the cap, presents it for a different tool, and waits out the TTL. A
run where those three succeed is a broken deployment, not a passing test.

Takes the same environment as examples/langchain/interactive_demo.py, so one
export block drives both:

    export LLM_SHIELD_URL=https://api.guardrails.votal.ai \
           KEYCLOAK_URL=http://localhost:8180 KEYCLOAK_REALM=shield \
           KEYCLOAK_CLIENT=demo-cli KC_USER=dr.smith KC_PASSWORD=password \
           AGENT_ID=test-oidc-agent TENANT_API_KEY=bank-co-key
    python examples/cap_flow_demo.py

Any of three credentials can authorize issuance, and the script sends whatever
it has:

  TENANT_API_KEY    the tenant's own key — needs `tenant_key` in
                    SHIELD_WORKLOAD_IDENTITY_PROVIDERS on the data plane. Issues
                    for that tenant and no other.
  KC_USER/PASSWORD  a signed OIDC token (oidc_sa). Also makes `user_sub` the
                    subject Keycloak signed rather than one this script made up,
                    so the audit trail names a real person.
  SHIELD_ADMIN_KEY  the operator's platform-wide key. Not tenant-scoped, which
                    is exactly why a tenant should not be holding it.

Needs SHIELD_AGENT_TOKEN_PRIVATE_KEY and SHIELD_CAP_TOKEN_PRIVATE_KEY set on
the server. Without them it mints with an ephemeral key that dies with the
worker, and verification fails for reasons that have nothing to do with policy.
"""

import base64
import json
import os
import sys
import time
import uuid

import requests

SHIELD = (os.getenv("SHIELD_URL") or os.getenv("LLM_SHIELD_URL")
          or "http://localhost:8000").rstrip("/")
API_KEY = os.getenv("TENANT_API_KEY", "")
ADMIN_KEY = os.getenv("SHIELD_ADMIN_KEY", "")
AGENT = os.getenv("AGENT_ID", "billing-bot")
TENANT = os.getenv("TENANT_ID", "t1")
TOOL = os.getenv("TOOL", "send_email")
RESOURCE = os.getenv("RESOURCE", "user/42/inbox")
TIMEOUT = float(os.getenv("SHIELD_TIMEOUT", "30"))

KC_URL = (os.getenv("KEYCLOAK_URL") or "").rstrip("/")
KC_REALM = os.getenv("KEYCLOAK_REALM", "shield")
KC_CLIENT = os.getenv("KEYCLOAK_CLIENT", "demo-cli")
KC_USER = os.getenv("KC_USER", "")
KC_PASSWORD = os.getenv("KC_PASSWORD", "")

G, R, Y, DIM, B, Z = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
INSTANCE = "inst-" + uuid.uuid4().hex[:8]
SESSION = "sess-" + uuid.uuid4().hex[:8]

_passed, _failed = [], []


def check(name: str, ok: bool, detail: str = "", because: str = "") -> bool:
    """Assert the refusal AND its reason.

    Checking only that something was refused is how a broken deployment reads
    as a passing run: an unverifiable signature refuses everything, so every
    negative test goes green while nothing works. `because` pins WHY.
    """
    if ok and because and because.lower() not in (detail or "").lower():
        (_failed).append(f"{name} [refused, but for the wrong reason]")
        print(f"   {R}FAIL{Z} {name}")
        print(f"        {DIM}refused — but expected {because!r}, got: {detail}{Z}")
        return False
    (_passed if ok else _failed).append(name)
    print(f"   {G}PASS{Z} {name}" if ok else f"   {R}FAIL{Z} {name}")
    if detail:
        print(f"        {DIM}{detail}{Z}")
    return ok


def preflight_signing_key(auth: dict) -> bool:
    """Mint several caps and verify each immediately. All must verify.

    A cap is signed at mint and checked at verify, by whichever worker each
    request lands on. If SHIELD_CAP_TOKEN_PRIVATE_KEY is unset, every worker
    generates its own ephemeral key at boot, so a cap only verifies on the
    worker that minted it and the rest fail as forgeries. Nothing downstream
    means anything until this holds.
    """
    bad = 0
    n = 8
    for _ in range(n):
        r = post("/v1/shield/cap/mint", {"tool": TOOL, "resource": RESOURCE,
                                         "ttl_seconds": 30, "session_id": SESSION}, auth)
        if r.status_code != 200:
            return True  # a mint failure is reported by the caller, not here
        d = post("/v1/shield/cap/verify",
                 {"cap_token": r.json()["cap_token"], "expected_tool": TOOL}).json()
        if "signature" in (d.get("error") or ""):
            bad += 1
    if not bad:
        print(f"   {G}PASS{Z} every worker can verify what another minted ({n}/{n})")
        _passed.append("signing key is shared across workers")
        return True
    print(f"   {R}FAIL{Z} {bad}/{n} freshly-minted caps failed as 'invalid signature'")
    print(f"        {DIM}SHIELD_CAP_TOKEN_PRIVATE_KEY is not set on the data plane, so{Z}")
    print(f"        {DIM}each worker signs with its own ephemeral key and a cap only{Z}")
    print(f"        {DIM}verifies on the worker that minted it. Set it (32 hex bytes),{Z}")
    print(f"        {DIM}identical across every replica, and restart.{Z}")
    _failed.append("signing key is shared across workers")
    return False


def claims_of(token: str) -> dict:
    """Read a JWT's claims WITHOUT verifying — for display only.

    Shield does the verifying. Decoding here is how the script reports which
    identity it is actually carrying, so a run that silently fell back to the
    admin key is visible rather than inferred.
    """
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def keycloak_login() -> str:
    """Password grant against the realm. Empty string if not configured."""
    if not (KC_URL and KC_USER and KC_PASSWORD):
        return ""
    try:
        r = requests.post(
            f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": KC_CLIENT,
                  "username": KC_USER, "password": KC_PASSWORD},
            timeout=TIMEOUT)
    except Exception as e:
        print(f"   {Y}Keycloak unreachable ({e}){Z}")
        return ""
    if r.status_code != 200:
        print(f"   {Y}Keycloak login failed — {r.status_code}: {r.text[:160]}{Z}")
        return ""
    return r.json().get("access_token", "")


def post(path: str, body: dict, headers: dict = None) -> requests.Response:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["X-API-Key"] = API_KEY
    h.update(headers or {})
    return requests.post(f"{SHIELD}{path}", json=body, headers=h, timeout=TIMEOUT)


def main() -> int:
    print(f"\n{B}Shield capability flow{Z}  {DIM}{SHIELD}{Z}")
    print(f"{DIM}agent={AGENT} instance={INSTANCE} tool={TOOL} resource={RESOURCE}{Z}")

    # ── 0. who the human is ─────────────────────────────────────────────
    # A cap carries user_sub. If this script invents one, the audit trail says
    # a capability was minted for a person who does not exist — so prefer the
    # subject Keycloak signed.
    kc_token = keycloak_login()
    user_sub = "user-1"
    if kc_token:
        c = claims_of(kc_token)
        user_sub = c.get("sub") or user_sub
        roles = (c.get("realm_access") or {}).get("roles", [])
        print(f"{DIM}user  {KC_USER} -> sub={user_sub[:18]}... roles={roles}{Z}")
    elif KC_URL:
        print(f"{Y}no Keycloak token — falling back to a made-up user_sub{Z}")

    # ── 1. AuthN ────────────────────────────────────────────────────────
    print(f"\n{B}1. POST /v1/shield/auth/agent-token{Z}  {DIM}who is calling{Z}")
    # Gated by the workload-identity providers: a signed OIDC token (oidc_sa),
    # an admin key, or SPIFFE/mTLS where those exist. Minting identity is
    # exactly the operation you would not leave open to the agent itself, so
    # send whichever credential this environment has.
    # X-API-Key is already sent by post(); with the tenant_key provider enabled
    # it authorizes issuance for that tenant, so a tenant never needs the
    # operator's SHIELD_ADMIN_KEY.
    issue_headers = {}
    if kc_token:
        issue_headers["Authorization"] = "Bearer " + kc_token
    if ADMIN_KEY:
        issue_headers["X-Admin-Key"] = ADMIN_KEY
    offered = sorted(issue_headers) + (["X-API-Key"] if API_KEY else [])
    if not offered:
        print(f"   {Y}No credential to authorize issuance.{Z}")
        print(f"   {DIM}Set TENANT_API_KEY, or KC_USER/KC_PASSWORD with "
              f"KEYCLOAK_URL, or SHIELD_ADMIN_KEY.{Z}")
        return 1
    print(f"   {DIM}authorizing with: {', '.join(offered)}{Z}")

    r = post("/v1/shield/auth/agent-token", {
        "user_sub": user_sub, "agent_id": AGENT, "agent_instance_id": INSTANCE,
        "tenant_id": TENANT, "build_hash": "b1", "model_version": "m1",
        "session_id": SESSION, "ttl_seconds": 300,
    }, issue_headers)
    if r.status_code != 200:
        print(f"   {R}HTTP {r.status_code}{Z} {r.text[:300]}")
        print(f"\n   {Y}Cannot continue without an agent token.{Z}")
        # The server says which providers it tried. Read it, rather than
        # guessing "the provider is off" at every 403 — that sends someone back
        # to an env var they already set while the real cause is elsewhere.
        detail = ""
        try:
            detail = str(r.json().get("detail", ""))
        except Exception:
            detail = r.text[:200]

        if "admin key required" in detail:
            print(f"   {Y}That error string was removed from Shield.{Z}")
            print(f"   {DIM}The data plane is running a build from before the{Z}")
            print(f"   {DIM}tenant_key provider existed, so it drops that name from{Z}")
            print(f"   {DIM}SHIELD_WORKLOAD_IDENTITY_PROVIDERS as unknown, however{Z}")
            print(f"   {DIM}the variable is set. Deploy current main.{Z}")
        elif "tenant key authorizes tenant" in detail:
            print(f"   {DIM}The key worked; TENANT_ID is the problem. Set it to the{Z}")
            print(f"   {DIM}tenant named above — TENANT_ID={TENANT} was sent.{Z}")
        elif "tried:" in detail and "tenant_key" not in detail:
            print(f"   {DIM}tenant_key is not in the chain the server tried. Add it to{Z}")
            print(f"   {DIM}SHIELD_WORKLOAD_IDENTITY_PROVIDERS on the DATA plane and{Z}")
            print(f"   {DIM}restart it — it is off by default.{Z}")
        elif "tried:" in detail and API_KEY:
            print(f"   {DIM}tenant_key was tried and did not accept this key: it may not{Z}")
            print(f"   {DIM}resolve to a tenant on this deployment. Check TENANT_API_KEY.{Z}")
        return 1
    agent_token = r.json()["agent_token"]
    print(f"   {G}issued{Z} {DIM}{agent_token[:40]}... ({len(agent_token)} chars){Z}")
    # Carry the OIDC token onward too: cap/mint runs AuthZ, and with role
    # binding on it resolves the role from this signed claim rather than from
    # anything the caller asserts.
    auth = {"X-Agent-Token": agent_token}
    if kc_token:
        auth["Authorization"] = "Bearer " + kc_token

    # ── 2. AuthZ ────────────────────────────────────────────────────────
    print(f"\n{B}2. POST /v1/shield/cap/mint{Z}  {DIM}may it? -> cap for ONE action{Z}")
    r = post("/v1/shield/cap/mint", {
        "tool": TOOL, "resource": RESOURCE, "ttl_seconds": 30,
        "session_id": SESSION,
    }, auth)
    if r.status_code != 200:
        print(f"   {R}HTTP {r.status_code}{Z} {r.text[:300]}")
        print(f"\n   {Y}Policy denied the mint, or the endpoint is gated.{Z}")
        print(f"   {DIM}A denial here is a working control, not a broken demo —{Z}")
        print(f"   {DIM}check that {AGENT} is allowed {TOOL} on {RESOURCE};{Z}")
        print(f"   {DIM}override with TOOL=... RESOURCE=...{Z}")
        if API_KEY and "tenant" in r.text.lower():
            # cap/mint cross-checks the agent token's tenant against the tenant
            # the API key resolves to, so a default TENANT_ID that does not
            # match the key fails here rather than at issuance.
            print(f"   {DIM}TENANT_ID={TENANT} must match the tenant "
                  f"TENANT_API_KEY resolves to.{Z}")
        return 1
    body = r.json()
    cap = body["cap_token"]
    print(f"   {G}minted{Z} expires_in={body.get('expires_in')}s")
    print(f"   {DIM}decision: {json.dumps(body.get('decision', {}))[:120]}{Z}")

    # ── 3. the tool server verifies ─────────────────────────────────────
    print(f"\n{B}3. POST /v1/shield/cap/verify{Z}  {DIM}the tool server, before executing{Z}")
    preflight_signing_key(auth)
    r = post("/v1/shield/cap/verify", {"cap_token": cap, "expected_tool": TOOL})
    d = r.json()
    check("a fresh cap verifies", d.get("valid") is True, d.get("error", ""))
    if d.get("claims"):
        c = d["claims"]
        print(f"        {DIM}bound to: tool={c.get('tool')} resource={c.get('resource')} "
              f"instance={c.get('agent_instance_id')}{Z}")

    # ── 4. what it must REFUSE ──────────────────────────────────────────
    print(f"\n{B}4. The refusals — this is the actual test{Z}")

    r = post("/v1/shield/cap/verify", {"cap_token": cap, "expected_tool": TOOL})
    d = r.json()
    check("the same cap a second time is rejected (nonce burned)",
          d.get("valid") is False,
          d.get("error") or "it verified twice — single-use is NOT holding",
          because="replay")

    r = post("/v1/shield/cap/mint", {"tool": TOOL, "resource": RESOURCE,
                                     "ttl_seconds": 30, "session_id": SESSION}, auth)
    cap2 = r.json().get("cap_token", "") if r.status_code == 200 else ""
    if cap2:
        r = post("/v1/shield/cap/verify",
                 {"cap_token": cap2, "expected_tool": "delete_everything"})
        d = r.json()
        check("a cap for one tool does not authorize another",
              d.get("valid") is False,
              d.get("error") or "IT AUTHORIZED THE WRONG TOOL",
              because="tool mismatch")

    r = post("/v1/shield/cap/verify", {"cap_token": "not.a.token",
                                       "expected_tool": TOOL})
    check("a garbage token is rejected", r.json().get("valid") is False)

    # TTL. Minted at 1s so the wait is short; the point is that expiry is
    # enforced at verify, not merely advertised in expires_in.
    r = post("/v1/shield/cap/mint", {"tool": TOOL, "resource": RESOURCE,
                                     "ttl_seconds": 1, "session_id": SESSION}, auth)
    if r.status_code == 200:
        short = r.json()["cap_token"]
        # ttl + the 2s clock-skew allowance, then margin. Waiting exactly
        # ttl+skew lands on `exp < now - skew` being false, and reads as
        # "expiry is broken" when it is working precisely as written.
        print(f"   {DIM}waiting 5s for a 1s cap to expire (1s ttl + 2s skew)...{Z}")
        time.sleep(5)
        d = post("/v1/shield/cap/verify",
                 {"cap_token": short, "expected_tool": TOOL}).json()
        check("an expired cap is rejected", d.get("valid") is False,
              d.get("error") or "EXPIRY IS NOT ENFORCED", because="expired")

    # Single-use must not be waivable by the party it constrains.
    r = post("/v1/shield/cap/mint", {"tool": TOOL, "resource": RESOURCE,
                                     "ttl_seconds": 30, "session_id": SESSION}, auth)
    if r.status_code == 200:
        cap3 = r.json()["cap_token"]
        post("/v1/shield/cap/verify", {"cap_token": cap3, "expected_tool": TOOL,
                                       "burn_nonce": False})
        d = post("/v1/shield/cap/verify", {"cap_token": cap3, "expected_tool": TOOL,
                                           "burn_nonce": False}).json()
        check("a caller cannot waive single-use with burn_nonce=false",
              d.get("valid") is False,
              d.get("error") or "the caller opted out of replay protection "
              "(expected if SHIELD_CAP_ALLOW_DRYRUN_VERIFY is set)",
              because="replay")

    print(f"\n{B}Result{Z}  {G}{len(_passed)} passed{Z}"
          + (f"  {R}{len(_failed)} FAILED{Z}" if _failed else ""))
    for name in _failed:
        print(f"   {R}x{Z} {name}")
    print(f"\n{DIM}Note: none of this makes execution exactly-once. The nonce burns"
          f"\nBEFORE the tool runs, so a crash in between loses the action, and an"
          f"\nagent retrying after a timeout can execute twice with a fresh cap."
          f"\nSingle-use bounds one TOKEN, not one INTENT.{Z}\n")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
