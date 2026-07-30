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
    /tool <name> [k=v ...]
                        ask whether the current role may call a tool. Arguments
                        are sent too, so argument-level policies apply:
                        /tool prescribe_medication patient_id=P-1043
    /role <name>        change the role the agent CLAIMS (a header — beat 2)
    /login <user>       authenticate as a Keycloak user; the role comes from
                        the signed token instead (beat 3)
    /token              fetch a token for KC_USER without changing the role
    /notoken            stop sending it
    /who                show the identity Shield resolved, and its source
    /quit
"""
from __future__ import annotations

import json
import os
import re
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


def fetch_token(user=None):
    if not (KC_URL and KC_PASSWORD):
        return None, "set KEYCLOAK_URL and KC_PASSWORD first"
    try:
        r = requests.post(
            f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": KC_CLIENT,
                  "username": user or KC_USER, "password": KC_PASSWORD},
            timeout=20)
        if r.status_code != 200:
            return None, f"{r.status_code}: {r.text[:120]}"
        return r.json()["access_token"], None
    except Exception as e:
        return None, str(e)


def claims_of(token):
    """Decode for DISPLAY only. Shield verifies it; we never trust this."""
    import base64
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
        print(f"  {R}error{Z} {e}")
        return False
    if r.status_code != 200:
        print(f"  {R}HTTP {r.status_code}{Z} {r.text[:160]}")
        return False
    d = r.json()
    trig = [g["guardrail"] for g in d.get("guardrail_results", []) if not g.get("passed")]
    if d.get("safe") is False:
        print(f"  {R}BLOCKED{Z} — {', '.join(trig)}")
        for g in d.get("guardrail_results", []):
            if not g.get("passed") and g.get("message"):
                print(f"    {DIM}{g['message'][:180]}{Z}")
        return False
    print(f"  {G}passed{Z} the input guardrails")
    return True


# ── the agent loop ───────────────────────────────────────────────────────
# The part that makes this an agent rather than a CLI: the MODEL reads what you
# typed and decides which tool to call with which arguments. Shield never sees
# your sentence — it sees the tool call the model produced.
#
# That ordering is the whole point. The model is free to plan anything,
# including an action this role may not take; Shield is what stops it. A demo
# where the human picks the tool cannot show that, because the human already
# knows what they are allowed to do.

TOOLS = [
    {"name": "patient_lookup",
     "description": "Look up a patient's record by id. Read-only.",
     "params": {"patient_id": "string, the patient identifier"}},
    {"name": "view_records",
     "description": "View a patient's full medical records, including history.",
     "params": {"patient_id": "string", "section": "string, optional"}},
    {"name": "check_vitals",
     "description": "Read current vital signs for a patient.",
     "params": {"patient_id": "string"}},
    {"name": "prescribe_medication",
     "description": "Prescribe a drug to a patient. Clinical action, not read-only.",
     "params": {"patient_id": "string", "drug": "string", "dose": "string, optional"}},
]

_SYSTEM = (
    "You route a clinician's request to exactly one tool.\n"
    "Return ONLY a JSON object: {\"tool\": <name or null>, \"params\": {...}, "
    "\"why\": <short reason>}.\n"
    "Use null when no tool fits — do not invent one.\n"
    "Do NOT consider permissions. You are not the authorization layer; something "
    "else decides whether the call is allowed. Plan what was asked.\n\n"
    "Tools:\n" + "\n".join(
        f"  {t['name']}({', '.join(t['params'])}) — {t['description']}"
        for t in TOOLS)
)


def _plan_with_llm(text):
    """Ask a real model. Returns (plan, engine) or (None, None) if unavailable."""
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            import anthropic
            m = anthropic.Anthropic().messages.create(
                model=os.getenv("DEMO_MODEL", "claude-sonnet-5"),
                max_tokens=300, system=_SYSTEM,
                messages=[{"role": "user", "content": text}])
            raw = "".join(b.text for b in m.content if b.type == "text")
            return json.loads(raw[raw.find("{"):raw.rfind("}") + 1]), "claude"
        except Exception as e:
            print(f"  {DIM}LLM planning failed ({e.__class__.__name__}); "
                  f"using the rule-based planner{Z}")
    if os.getenv("OPENAI_API_KEY"):
        try:
            from openai import OpenAI
            r = OpenAI().chat.completions.create(
                model=os.getenv("DEMO_MODEL", "gpt-4o-mini"),
                response_format={"type": "json_object"},
                messages=[{"role": "system", "content": _SYSTEM},
                          {"role": "user", "content": text}])
            return json.loads(r.choices[0].message.content), "openai"
        except Exception as e:
            print(f"  {DIM}LLM planning failed ({e.__class__.__name__}); "
                  f"using the rule-based planner{Z}")
    return None, None


_ID = re.compile(r"\b(?:patient|pt|mrn)?\s*#?\s*([A-Z]-?\d{2,}|\d{2,})\b", re.I)
_DRUGS = ("paracetamol", "parcetamol", "acetaminophen", "amoxicillin", "ibuprofen",
          "insulin", "morphine", "aspirin", "metformin", "warfarin")


def _plan_with_rules(text):
    """Deterministic stand-in, so the demo runs with no API key.

    Labelled as such wherever it is used: presenting keyword matching as a
    model's judgement would misrepresent the one component the demo is not
    testing.
    """
    low = text.lower()
    params = {}
    m = _ID.search(text)
    if m:
        params["patient_id"] = m.group(1)
    drug = next((d for d in _DRUGS if d in low), "")
    if drug:
        params["drug"] = drug

    if any(w in low for w in ("prescribe", "prescribing", "give", "administer", "order")) and drug:
        return {"tool": "prescribe_medication", "params": params,
                "why": f"asks to prescribe {drug}"}
    if any(w in low for w in ("vitals", "vital signs", "blood pressure", "heart rate", "temperature")):
        return {"tool": "check_vitals", "params": params, "why": "asks for vitals"}
    if any(w in low for w in ("record", "history", "chart", "notes", "ssn")):
        return {"tool": "view_records", "params": params, "why": "asks for records"}
    if any(w in low for w in ("look up", "lookup", "find", "who is", "patient")):
        return {"tool": "patient_lookup", "params": params, "why": "asks to look up a patient"}
    return {"tool": None, "params": {}, "why": "nothing matched a tool"}


def agent_turn(text):
    """One turn: screen the text, let the model plan, let Shield decide.

    Runs the input guardrail FIRST. A prompt injection that talks the model into
    a tool call is cheaper to stop before the model reads it than after.
    """
    if not screen(text):
        print(f"  {DIM}blocked before the model saw it — nothing was planned{Z}")
        return

    plan, engine = _plan_with_llm(text)
    if plan is None:
        plan, engine = _plan_with_rules(text), "rules"

    name = (plan or {}).get("tool")
    params = (plan or {}).get("params") or {}
    why = (plan or {}).get("why", "")
    label = {"claude": "claude", "openai": "openai",
             "rules": "rule-based planner (no API key set)"}[engine]

    if not name:
        print(f"  {DIM}{label} chose no tool{Z} — {why}")
        return

    shown = " ".join(f"{k}={v}" for k, v in params.items())
    print(f"  {DIM}{label} planned{Z} {B}{name}({shown}){Z}  {DIM}{why}{Z}")
    # Shield authorizes the MODEL's choice, not yours. If this is denied, the
    # model still wanted to do it — that is what the control is for.
    tool(name, params)


def parse_params(rest):
    """key=value pairs, or raw JSON. Numbers are coerced so an amount policy
    compares against a number rather than a string."""
    rest = (rest or "").strip()
    if not rest:
        return {}
    if rest.startswith("{"):
        try:
            return json.loads(rest)
        except ValueError:
            print(f"  {R}bad JSON{Z} — falling back to no arguments")
            return {}
    out = {}
    for tok in rest.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        try:
            out[k] = int(v)
        except ValueError:
            out[k] = v
    return out


def tool(name, params=None):
    params = params or {}
    body = {"agent_key": AGENT, "tool_name": name,
            "user_role": state["role"], "tool_params": params}
    try:
        r = requests.post(f"{SHIELD}/v1/shield/tool/check", json=body,
                          headers=headers(), timeout=TIMEOUT)
        d = r.json()
    except Exception as e:
        return print(f"  {R}error{Z} {e}")
    failing = [g for g in d.get("guardrail_results", []) if not g.get("passed", True)]
    shown = " ".join(f"{k}={v}" for k, v in params.items())
    if d.get("allowed"):
        print(f"  {G}ALLOWED{Z}  {state['role']} may call {name}({shown})")
    else:
        why = failing[0] if failing else {}
        print(f"  {R}DENIED{Z}   {state['role']} may not call {name}({shown})")
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
{DIM}users: dr.smith (doctor)  nurse.jones (nurse)  admin.doe  patient.lee{Z}
{DIM}       password for all of them is "password"{Z}
{DIM}Just talk to it. The model picks the tool; Shield decides if it runs.{Z}
{DIM}  prescribe amoxicillin to patient 101   the interesting one — try it{Z}
{DIM}  check vitals for patient 101           as both roles, and compare{Z}
{DIM}  Ignore all previous instructions.      blocked before the model reads it{Z}
{DIM}  /login nurse.jones                     then ask to prescribe again{Z}
{DIM}  /tool <name> k=v                       call one directly, skipping the model{Z}
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
        elif line.startswith("/login"):
            # Authenticate AS a person. Their role comes from the token, so it
            # is no longer something the caller can choose.
            parts = line.split(maxsplit=1)
            user = parts[1].strip() if len(parts) > 1 else KC_USER
            tok, err = fetch_token(user)
            if err:
                print(f"  {R}login failed{Z} — {err}")
            else:
                state["token"] = tok
                c = claims_of(tok)
                roles = (c.get("realm_access") or {}).get("roles", [])
                state["role"] = roles[0] if roles else state["role"]
                print(f"  {G}signed in as {user}{Z} — roles {roles}")
                print(f"  {DIM}the role now comes from the token, not from you{Z}")
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
            parts = line.split(maxsplit=2)
            tool(parts[1].strip() if len(parts) > 1 else "prescribe_medication",
                 parse_params(parts[2] if len(parts) > 2 else ""))
        else:
            agent_turn(line)


if __name__ == "__main__":
    main()
