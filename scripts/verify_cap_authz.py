#!/usr/bin/env python3
"""Verify the Agent IdP / capability control-plane fixes against a live Shield.

Asserts the post-fix Pass Criteria from the bug-reproduction report, using two
*registered* agents in the target tenant that own disjoint tools:

  Control  /v1/agents/authorize for a rogue agent              -> allowed=false
  Bug 1    token mint for the rogue (unregistered) agent       -> 401/403/404, no token
  Bug 1    cap mint with a rogue token                         -> impossible (no token)
  Bug 2    cap mint CROSS_TOOL with AGENT's token              -> 403, no cap
  OK       cap mint OWNED_TOOL with AGENT's token              -> 200, cap returned
  OK       cap mint CROSS_TOOL with OWNER_AGENT's token        -> 200, cap returned

Exit 0 if every check passes, else 1. Read-only except the (expected-to-fail)
mint attempts; no secrets are printed.

Usage:
    pip install requests
    export SHIELD_URL="https://kebrpqdbp1log1.api.runpod.ai"
    export RUNPOD_TOKEN="..."          # proxy bearer
    export TENANT_API_KEY="..."        # tenant key

Defaults match this tenant's registry (customer-service-agent / test-oidc-agent).
Override for a different tenant:
    AGENT=customer-service-agent          # registered; does NOT own CROSS_TOOL
    OWNER_AGENT=test-oidc-agent           # registered; owns CROSS_TOOL
    OWNED_TOOL=customer_profile_get       # AGENT owns this
    CROSS_TOOL=prescribe_medication       # OWNER_AGENT owns; AGENT does not
    ROGUE_AGENT=rogue-agent  USER_SUB=verify-user
"""

import os
import sys

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

SHIELD = os.environ.get("SHIELD_URL", "").rstrip("/")
TOKEN = os.environ.get("RUNPOD_TOKEN", "")
KEY = os.environ.get("TENANT_API_KEY", "")
AGENT = os.environ.get("AGENT", "customer-service-agent")
OWNER_AGENT = os.environ.get("OWNER_AGENT", "test-oidc-agent")
OWNED_TOOL = os.environ.get("OWNED_TOOL", "customer_profile_get")
CROSS_TOOL = os.environ.get("CROSS_TOOL", "prescribe_medication")
ROGUE = os.environ.get("ROGUE_AGENT", "rogue-agent")
USER_SUB = os.environ.get("USER_SUB", "verify-user")

AUTH = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
TENANT = {**AUTH, "X-API-Key": KEY}

_results = []


def check(ok, name, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    _results.append(bool(ok))
    return ok


def post(path, headers, body, extra=None):
    h = dict(headers)
    if extra:
        h.update(extra)
    try:
        r = requests.post(f"{SHIELD}{path}", headers=h, json=body, timeout=20)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {}
    except Exception as e:
        return None, {"_error": str(e)}


def mint_token(agent_id, inst):
    return post("/v1/tenant/me/agent-auth/agent-token", TENANT,
                {"user_sub": USER_SUB, "agent_id": agent_id, "agent_instance_id": inst,
                 "build_hash": "verify-proof", "model_version": "gpt-4o-mini",
                 "session_id": "verify-session", "ttl_seconds": 600})


def mint_cap(agent_token, tool, resource):
    return post("/v1/shield/cap/mint", AUTH,
                {"tool": tool, "resource": resource, "clearance_max": "public", "ttl_seconds": 30},
                extra={"X-Agent-Token": agent_token})


def authorize(agent_id, tool, role):
    return post("/v1/agents/authorize", TENANT,
                {"agent_id": agent_id, "tool_name": tool, "user_role": role},
                extra={"X-Agent-Key": agent_id, "X-User-Role": role})


def main():
    missing = [n for n, v in [("SHIELD_URL", SHIELD), ("RUNPOD_TOKEN", TOKEN),
                              ("TENANT_API_KEY", KEY)] if not v]
    if missing:
        sys.exit("Set: " + ", ".join(missing))
    print(f"Verifying capability authorization fixes\n  {SHIELD}")
    print(f"  agent={AGENT}  owner_agent={OWNER_AGENT}  owned={OWNED_TOOL}  cross={CROSS_TOOL}\n")

    # ── Control ───────────────────────────────────────────────────────
    print("Control checks")
    try:
        r = requests.get(f"{SHIELD}/health", headers=AUTH, timeout=15)
        check(r.status_code == 200, "health is up", f"HTTP {r.status_code}")
    except Exception as e:
        check(False, "health is up", str(e))
    _, body = authorize(ROGUE, OWNED_TOOL, "employee")
    check(isinstance(body, dict) and body.get("allowed") is False,
          "RBAC /authorize denies rogue agent", f"allowed={body.get('allowed')}")

    # ── Bug 1: rogue token + cap ──────────────────────────────────────
    print("\nBug 1 — rogue (unregistered) agent")
    sc, body = mint_token(ROGUE, "rogue-inst-proof")
    rogue_token = body.get("agent_token") if isinstance(body, dict) else None
    check(sc in (401, 403, 404) and not rogue_token,
          "token mint for rogue agent rejected", f"HTTP {sc}, token={'yes' if rogue_token else 'none'}")
    if rogue_token:
        sc, body = mint_cap(rogue_token, OWNED_TOOL, "resource/x")
        check(sc in (401, 403) and not body.get("cap_token"),
              "cap mint with rogue token rejected", f"HTTP {sc}")
    else:
        check(True, "cap mint with rogue token impossible", "no rogue token issued (expected)")

    # ── Bug 2: cross-agent tool ───────────────────────────────────────
    print("\nBug 2 — cross-agent tool ownership")
    sc, body = mint_token(AGENT, "agent-cross-tool-proof")
    agent_token = body.get("agent_token") if isinstance(body, dict) else None
    if not check(bool(agent_token), f"token mint for {AGENT}", f"HTTP {sc}"):
        print(f"    (precondition: {AGENT} must be registered+active for this tenant)")
    else:
        _, body = authorize(AGENT, CROSS_TOOL, "admin")
        check(body.get("allowed") is False, f"RBAC denies {AGENT} -> {CROSS_TOOL}",
              f"allowed={body.get('allowed')}")
        sc, body = mint_cap(agent_token, CROSS_TOOL, "resource/cross")
        check(sc == 403 and not body.get("cap_token"),
              f"cap mint {CROSS_TOOL} with {AGENT} token rejected", f"HTTP {sc}")
        sc, body = mint_cap(agent_token, OWNED_TOOL, "resource/owned")
        check(sc == 200 and bool(body.get("cap_token")),
              f"cap mint {OWNED_TOOL} with {AGENT} token allowed", f"HTTP {sc}")

    # ── Positive: owner can mint its own tool ─────────────────────────
    print("\nPositive — owner can mint")
    sc, body = mint_token(OWNER_AGENT, "owner-proof")
    owner_token = body.get("agent_token") if isinstance(body, dict) else None
    if not check(bool(owner_token), f"token mint for {OWNER_AGENT}", f"HTTP {sc}"):
        print(f"    (precondition: {OWNER_AGENT} must be registered+active for this tenant)")
    else:
        sc, body = mint_cap(owner_token, CROSS_TOOL, "resource/cross")
        check(sc == 200 and bool(body.get("cap_token")),
              f"cap mint {CROSS_TOOL} with {OWNER_AGENT} token allowed", f"HTTP {sc}")

    passed, total = sum(_results), len(_results)
    print(f"\n{'='*52}\nRESULT: {passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
