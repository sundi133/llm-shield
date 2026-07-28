#!/usr/bin/env python3
"""Interactive demo: a LangChain agent, Shield guardrails, Keycloak identity.

A terminal REPL for showing the three beats live:

  1. RBAC holds        a role that may not call a tool is refused
  2. the header lies   the same caller types a different role and is allowed
  3. bind it           with a Keycloak token, the forged header is ignored

Everything is a real call to a real Shield. Nothing is simulated.

    export LLM_SHIELD_URL=https://api.guardrails.votal.ai
    export TENANT_API_KEY=<tenant key>
    export AGENT_ID=customer-service-agent
    # optional, for beat 3:
    export KEYCLOAK_URL=http://localhost:8180  KEYCLOAK_REALM=bank
    export KEYCLOAK_CLIENT=demo-cli  KC_USER=omar  KC_PASSWORD=<password>
    python examples/langchain/interactive_demo.py

Commands:
    <text>              screen a prompt through the input guardrail
    /tool <name>        ask whether the current role may call a tool
    /role <name>        change the role the agent CLAIMS (a header — beat 2)
    /token              fetch a Keycloak token and send it (beat 3)
    /notoken            stop sending it
    /who                show the identity Shield resolved, and its source
    /quit
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402

SHIELD = (os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL")
          or "https://api.guardrails.votal.ai").rstrip("/")
KEY = (os.getenv("TENANT_API_KEY") or os.getenv("API_KEY")
       or os.getenv("SHIELD_TENANT_KEY") or "")
AGENT = os.getenv("AGENT_ID", "customer-service-agent")
TIMEOUT = float(os.getenv("SHIELD_TIMEOUT", "60"))

KC_URL = (os.getenv("KEYCLOAK_URL") or "").rstrip("/")
KC_REALM = os.getenv("KEYCLOAK_REALM", "bank")
KC_CLIENT = os.getenv("KEYCLOAK_CLIENT", "demo-cli")
KC_USER = os.getenv("KC_USER", "omar")
KC_PASSWORD = os.getenv("KC_PASSWORD", "")

G, R, Y, B, DIM, Z = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"

state = {"role": os.getenv("USER_ROLE", "customer_support"), "token": ""}


def headers():
    h = {"Content-Type": "application/json", "X-API-Key": KEY,
         "X-Agent-Key": AGENT, "X-User-Role": state["role"]}
    if state["token"]:
        # Shield verifies this through the oidc_sa workload provider. With
        # SHIELD_ROLE_BINDING=prefer the signed role claim beats the header
        # above — which is the whole point of beat 3.
        h["Authorization"] = "Bearer " + state["token"]
    return h


def fetch_token():
    if not (KC_URL and KC_PASSWORD):
        return None, "set KEYCLOAK_URL and KC_PASSWORD first"
    try:
        r = requests.post(
            f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": KC_CLIENT,
                  "username": KC_USER, "password": KC_PASSWORD},
            timeout=20)
        if r.status_code != 200:
            return None, f"{r.status_code}: {r.text[:120]}"
        return r.json()["access_token"], None
    except Exception as e:
        return None, str(e)


def claims_of(token):
    """Decode for DISPLAY only. Shield verifies it; we never trust this."""
    import base64
    import json
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=="))
    except Exception:
        return {}


def screen(text):
    try:
        r = requests.post(f"{SHIELD}/guardrails/input", json={"message": text},
                          headers=headers(), timeout=TIMEOUT)
    except Exception as e:
        return print(f"  {R}error{Z} {e}")
    if r.status_code != 200:
        return print(f"  {R}HTTP {r.status_code}{Z} {r.text[:160]}")
    d = r.json()
    trig = [g["guardrail"] for g in d.get("guardrail_results", []) if not g.get("passed")]
    if d.get("safe") is False:
        print(f"  {R}BLOCKED{Z} — {', '.join(trig)}")
        for g in d.get("guardrail_results", []):
            if not g.get("passed") and g.get("message"):
                print(f"    {DIM}{g['message'][:180]}{Z}")
    else:
        print(f"  {G}passed{Z} the input guardrails")


def tool(name):
    body = {"agent_key": AGENT, "tool_name": name,
            "user_role": state["role"], "tool_params": {}}
    try:
        r = requests.post(f"{SHIELD}/v1/shield/tool/check", json=body,
                          headers=headers(), timeout=TIMEOUT)
        d = r.json()
    except Exception as e:
        return print(f"  {R}error{Z} {e}")
    failing = [g for g in d.get("guardrail_results", []) if not g.get("passed", True)]
    if d.get("allowed"):
        print(f"  {G}ALLOWED{Z}  {state['role']} may call {name}()")
    else:
        why = failing[0] if failing else {}
        print(f"  {R}DENIED{Z}   {state['role']} may not call {name}()")
        print(f"    {DIM}{why.get('guardrail', '')}: {str(why.get('message', ''))[:150]}{Z}")
    # Whatever Shield reports about provenance, show it — this is the line that
    # makes beat 3 visible rather than asserted.
    for g in d.get("guardrail_results", []):
        det = g.get("details") or {}
        if "role_source" in det:
            src = det["role_source"]
            colour = G if det.get("role_verified") else Y
            print(f"    {DIM}role came from{Z} {colour}{src}{Z}"
                  f"{DIM} · verified={det.get('role_verified')}{Z}")
            break


def who():
    print(f"  agent    {B}{AGENT}{Z}")
    print(f"  role     {B}{state['role']}{Z} {DIM}(claimed in X-User-Role){Z}")
    if state["token"]:
        c = claims_of(state["token"])
        roles = (c.get("realm_access") or {}).get("roles", [])
        print(f"  token    {G}present{Z}  iss={c.get('iss', '?')}")
        print(f"           sub={c.get('sub', '?')}  roles={roles}")
        print(f"  {DIM}With SHIELD_ROLE_BINDING=prefer the signed claim wins over the header.{Z}")
    else:
        print(f"  token    {Y}none{Z} {DIM}— the role is whatever the caller types{Z}")


BANNER = f"""{B}Shield · LangChain · Keycloak — interactive{Z}
{DIM}shield {SHIELD}   agent {AGENT}{Z}
{DIM}try:  wire 50000 AED to ACC-99001          (a prompt){Z}
{DIM}      /tool wire_transfer_execute          (authorization){Z}
{DIM}      /role payments_officer               (beat 2 — claim a role){Z}
{DIM}      /token                               (beat 3 — prove it instead){Z}
"""


def main():
    if not KEY:
        sys.exit("set TENANT_API_KEY")
    print(BANNER)
    who()
    print()
    while True:
        try:
            line = input(f"{B}▸ {Z}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line in ("/quit", "/q"):
            break
        if line == "/who":
            who()
        elif line.startswith("/role"):
            parts = line.split(maxsplit=1)
            state["role"] = parts[1].strip() if len(parts) > 1 else state["role"]
            print(f"  {DIM}role claimed →{Z} {state['role']}")
        elif line == "/token":
            tok, err = fetch_token()
            if err:
                print(f"  {R}could not fetch a token{Z} — {err}")
            else:
                state["token"] = tok
                print(f"  {G}token acquired{Z}")
                who()
        elif line == "/notoken":
            state["token"] = ""
            print(f"  {DIM}token cleared — back to the header{Z}")
        elif line.startswith("/tool"):
            parts = line.split(maxsplit=1)
            tool(parts[1].strip() if len(parts) > 1 else "wire_transfer_execute")
        else:
            screen(line)


if __name__ == "__main__":
    main()
