#!/usr/bin/env python3
"""Verify the Agent IdP / capability control-plane fixes against a live Shield.

Runs the exact sequence from the CTO bug-reproduction report and asserts the
post-fix Pass Criteria:

  Control  /v1/agents/authorize for rogue-agent            -> allowed=false
  Bug 1    token mint for rogue-agent                       -> 401/403/404, no token
  Bug 1    cap mint with rogue token                        -> impossible (no token)
  Bug 2    cap mint update_salary (directory-agent token)   -> 403, no cap
  OK       cap mint lookup_employee (directory-agent token) -> 200, cap returned
  OK       cap mint update_salary (people-ops-agent token)  -> 200, cap returned

Exit 0 if every check passes, else 1. Read-only except for the (expected-to-fail)
mint attempts; no secrets are printed.

Usage:
    pip install requests
    export SHIELD_URL="https://kebrpqdbp1log1.api.runpod.ai"
    export RUNPOD_TOKEN="..."          # proxy bearer
    export TENANT_API_KEY="..."        # hr tenant key
    python scripts/verify_cap_authz.py

Optional overrides (defaults match the report's HR app):
    DIRECTORY_AGENT=people-directory-agent  OPS_AGENT=people-ops-agent
    ROGUE_AGENT=rogue-agent  USER_SUB=local-hr-user
    OWNED_TOOL=lookup_employee  CROSS_TOOL=update_salary
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
DIRECTORY = os.environ.get("DIRECTORY_AGENT", "people-directory-agent")
OPS = os.environ.get("OPS_AGENT", "people-ops-agent")
ROGUE = os.environ.get("ROGUE_AGENT", "rogue-agent")
USER_SUB = os.environ.get("USER_SUB", "local-hr-user")
OWNED_TOOL = os.environ.get("OWNED_TOOL", "lookup_employee")
CROSS_TOOL = os.environ.get("CROSS_TOOL", "update_salary")

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


def _token_body(agent_id, inst):
    return {"user_sub": USER_SUB, "agent_id": agent_id, "agent_instance_id": inst,
            "build_hash": "verify-proof", "model_version": "gpt-4o-mini",
            "session_id": "verify-session", "ttl_seconds": 600}


def mint_token(agent_id, inst):
    return post("/v1/tenant/me/agent-auth/agent-token", TENANT, _token_body(agent_id, inst))


def mint_cap(agent_token, tool, resource):
    return post("/v1/shield/cap/mint", AUTH,
                {"tool": tool, "resource": resource, "clearance_max": "public", "ttl_seconds": 30},
                extra={"X-Agent-Token": agent_token})


def main():
    missing = [n for n, v in [("SHIELD_URL", SHIELD), ("RUNPOD_TOKEN", TOKEN),
                              ("TENANT_API_KEY", KEY)] if not v]
    if missing:
        sys.exit("Set: " + ", ".join(missing))
    print(f"Verifying capability authorization fixes\n  {SHIELD}\n")

    # ── Control: health ───────────────────────────────────────────────
    print("Control checks")
    try:
        r = requests.get(f"{SHIELD}/health", headers=AUTH, timeout=15)
        check(r.status_code == 200, "health is up", f"HTTP {r.status_code}")
    except Exception as e:
        check(False, "health is up", str(e))

    # ── Control: RBAC blocks rogue (should already pass) ──────────────
    sc, body = post("/v1/agents/authorize", TENANT,
                    {"agent_id": ROGUE, "tool_name": OWNED_TOOL, "user_role": "employee"},
                    extra={"X-Agent-Key": ROGUE, "X-User-Role": "employee"})
    check(isinstance(body, dict) and body.get("allowed") is False,
          "RBAC /authorize denies rogue-agent", f"allowed={body.get('allowed')}")

    # ── Bug 1: rogue token issuance must be rejected ──────────────────
    print("\nBug 1 — rogue agent")
    sc, body = mint_token(ROGUE, "rogue-inst-proof")
    rogue_token = body.get("agent_token") if isinstance(body, dict) else None
    check(sc in (401, 403, 404) and not rogue_token,
          "token mint for rogue-agent rejected", f"HTTP {sc}, token={'yes' if rogue_token else 'none'}")

    # ── Bug 1: cap mint with rogue token (only reachable on regression) ─
    if rogue_token:
        sc, body = mint_cap(rogue_token, OWNED_TOOL, f"employee/EMP-1001/{OWNED_TOOL}")
        check(sc in (401, 403) and not body.get("cap_token"),
              "cap mint with rogue token rejected", f"HTTP {sc}")
    else:
        check(True, "cap mint with rogue token impossible", "no rogue token issued (expected)")

    # ── Bug 2: registered directory-agent cannot mint another's tool ──
    print("\nBug 2 — cross-agent tool")
    sc, body = mint_token(DIRECTORY, "directory-cross-tool-proof")
    dir_token = body.get("agent_token") if isinstance(body, dict) else None
    if not check(bool(dir_token), f"token mint for {DIRECTORY}", f"HTTP {sc}"):
        print(f"    (precondition: {DIRECTORY} must be registered+active for this tenant)")
    else:
        # control: /authorize already knows directory can't update_salary
        sc, body = post("/v1/agents/authorize", TENANT,
                        {"agent_id": DIRECTORY, "tool_name": CROSS_TOOL, "user_role": "hr_admin"},
                        extra={"X-Agent-Key": DIRECTORY, "X-User-Role": "hr_admin"})
        check(body.get("allowed") is False, f"RBAC denies {DIRECTORY} -> {CROSS_TOOL}",
              f"allowed={body.get('allowed')}")
        # the fix: cap mint for the cross-owned tool must be denied
        sc, body = mint_cap(dir_token, CROSS_TOOL, "employee/EMP-1002/salary")
        check(sc == 403 and not body.get("cap_token"),
              f"cap mint {CROSS_TOOL} with {DIRECTORY} token rejected", f"HTTP {sc}")
        # sanity: its own tool still works
        sc, body = mint_cap(dir_token, OWNED_TOOL, f"employee/EMP-1001/{OWNED_TOOL}")
        check(sc == 200 and bool(body.get("cap_token")),
              f"cap mint {OWNED_TOOL} with {DIRECTORY} token allowed", f"HTTP {sc}")

    # ── Positive: people-ops-agent CAN mint update_salary ─────────────
    print("\nPositive — owner can mint")
    sc, body = mint_token(OPS, "ops-proof")
    ops_token = body.get("agent_token") if isinstance(body, dict) else None
    if not check(bool(ops_token), f"token mint for {OPS}", f"HTTP {sc}"):
        print(f"    (precondition: {OPS} must be registered+active for this tenant)")
    else:
        sc, body = mint_cap(ops_token, CROSS_TOOL, "employee/EMP-1002/salary")
        check(sc == 200 and bool(body.get("cap_token")),
              f"cap mint {CROSS_TOOL} with {OPS} token allowed", f"HTTP {sc}")

    passed = sum(_results)
    total = len(_results)
    print(f"\n{'='*52}\nRESULT: {passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
