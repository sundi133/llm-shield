#!/usr/bin/env python3
"""A real LangChain agent, with Shield authorizing every tool call.

The difference from interactive_demo.py: this runs an actual agent loop. The
model calls a tool, sees the result, and keeps going until it has an answer for
you — including when the result is a refusal. Ask a nurse to prescribe and the
agent does not stop at a red line; it tells you it could not, in words, because
Shield's denial came back to it as the tool's output.

Shield sits INSIDE each tool, before the work happens:

    model decides  ->  tool called  ->  Shield authorizes  ->  work, or a denial
                                                              returned to the model

That placement is the point. Authorization is not a wrapper the agent can route
around, and a denial is data the agent has to reason about rather than an
exception that ends the run.

Usage — same environment as interactive_demo.py:

    export OPENAI_API_KEY=sk-...
    export LLM_SHIELD_URL=https://api.guardrails.votal.ai \
           KEYCLOAK_URL=http://localhost:8180 KEYCLOAK_REALM=shield \
           KEYCLOAK_CLIENT=demo-cli KC_USER=dr.smith KC_PASSWORD=password \
           AGENT_ID=test-oidc-agent TENANT_API_KEY=bank-co-key
    python examples/langchain/interactive_demo_langchain.py
"""

import json
import os
import sys
import time

import requests

SHIELD = (os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL")
          or "http://localhost:8000").rstrip("/")
KEY = os.getenv("TENANT_API_KEY", "")
AGENT = os.getenv("AGENT_ID", "test-oidc-agent")
TIMEOUT = float(os.getenv("SHIELD_TIMEOUT", "120"))
MODEL = os.getenv("DEMO_MODEL", "gpt-4o-mini")

KC_URL = (os.getenv("KEYCLOAK_URL") or "").rstrip("/")
KC_REALM = os.getenv("KEYCLOAK_REALM", "shield")
KC_CLIENT = os.getenv("KEYCLOAK_CLIENT", "demo-cli")
KC_USER = os.getenv("KC_USER", "dr.smith")
KC_PASSWORD = os.getenv("KC_PASSWORD", "")

G, R, Y, DIM, B, Z = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"

state = {"role": os.getenv("USER_ROLE", "customer_support"), "token": "",
         "trace": os.getenv("DEMO_TRACE", "1") not in ("0", "false", "no")}

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_data.json")
try:
    with open(_DATA) as f:
        PATIENTS = json.load(f)["patients"]
except Exception as e:                                    # pragma: no cover
    print(f"could not load demo_data.json ({e})")
    PATIENTS = {}


def headers():
    h = {"Content-Type": "application/json", "X-API-Key": KEY,
         "X-Agent-Key": AGENT, "X-User-Role": state["role"]}
    if state["token"]:
        h["Authorization"] = "Bearer " + state["token"]
    return h


def claims_of(token):
    try:
        p = token.split(".")[1]
        import base64
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def _pt(patient_id):
    return PATIENTS.get(str(patient_id).strip())


# ── Shield, inside the tool ──────────────────────────────────────────────

def shielded(tool_name, params, run):
    """Authorize, then run. The denial is RETURNED, not raised.

    An exception would end the agent's turn and it would report a crash. The
    agent should learn that it may not do this and say so, which means the
    refusal has to arrive the way any other tool result does.
    """
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
                          headers=headers(),
                          json={"agent_key": AGENT, "tool_name": tool_name,
                                "user_role": state["role"], "tool_params": params})
        d = r.json()
    except Exception as e:
        # Fail closed. A tool that runs because the authorizer was unreachable
        # is worse than a turn that fails.
        return f"DENIED — could not reach Shield to authorize this ({e.__class__.__name__})"
    ms = (time.perf_counter() - t0) * 1000

    allowed = bool(d.get("allowed"))
    if state["trace"]:
        ran = d.get("guardrail_results", []) or []
        verdict = f"{G}ALLOW{Z}" if allowed else f"{R}DENY{Z}"
        shown = " ".join(f"{k}={v}" for k, v in params.items())
        print(f"  {DIM}shield{Z} {verdict} {B}{tool_name}({shown}){Z} "
              f"{DIM}role={state['role']} {ms:.0f}ms{Z}")
        for g in ran:
            if not g.get("passed", True):
                print(f"       {DIM}DENY {g.get('guardrail')} — "
                      f"{str(g.get('message', ''))[:120]}{Z}")

    if not allowed:
        why = next((g.get("message") for g in d.get("guardrail_results", [])
                    if not g.get("passed", True)), "not permitted")
        return f"DENIED by policy: {why}"
    return run()


try:
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
except ImportError as e:                                   # pragma: no cover
    sys.exit(f"needs langchain + langchain-openai: {e}")


@tool
def patient_lookup(patient_id: str) -> str:
    """Look up a patient's demographic record by id. Read-only."""
    def run():
        p = _pt(patient_id)
        if not p:
            return f"no patient with id {patient_id}"
        return (f"{p['name']} · {p['sex']} · DOB {p['dob']} · {p['mrn']} · "
                f"conditions: {', '.join(p['conditions']) or 'none recorded'}")
    return shielded("patient_lookup", {"patient_id": patient_id}, run)


@tool
def view_records(patient_id: str, section: str = "") -> str:
    """View a patient's full medical records, including history and identifiers."""
    def run():
        p = _pt(patient_id)
        if not p:
            return f"no patient with id {patient_id}"
        meds = "; ".join(f"{m['drug']} {m['dose']} {m['frequency']}"
                         for m in p["medications"]) or "none"
        return (f"{p['name']} ({p['mrn']}) DOB {p['dob']} SSN {p['ssn']} "
                f"phone {p['phone']}; conditions: {', '.join(p['conditions']) or 'none'}; "
                f"allergies: {', '.join(p['allergies']) or 'none known'}; "
                f"medications: {meds}; notes: {' | '.join(p['notes'])}")
    return shielded("view_records", {"patient_id": patient_id, "section": section}, run)


@tool
def check_vitals(patient_id: str) -> str:
    """Read current vital signs (BP, heart rate, temperature, SpO2)."""
    def run():
        p = _pt(patient_id)
        if not p:
            return f"no patient with id {patient_id}"
        v = p["vitals"]
        flag = " [FEVER]" if v["temp_c"] >= 38.0 else ""
        return (f"{p['name']}: BP {v['bp']} · HR {v['hr']} · temp {v['temp_c']}C{flag}"
                f" · SpO2 {v['spo2']}% (taken {v['taken_at']})")
    return shielded("check_vitals", {"patient_id": patient_id}, run)


@tool
def prescribe_medication(patient_id: str, drug: str, dose: str = "") -> str:
    """Prescribe a medication to a patient. A clinical action, not read-only."""
    def run():
        p = _pt(patient_id)
        if not p:
            return f"no patient with id {patient_id}"
        # Shield decides who may prescribe. It does not know medicine, so an
        # authorized call can still be the wrong call.
        if drug.lower().strip() in [a.lower() for a in p["allergies"]]:
            return (f"NOT PRESCRIBED — {p['name']} is allergic to {drug}. "
                    f"Recorded allergies: {', '.join(p['allergies'])}")
        return f"prescribed {drug} {dose} to {p['name']} ({p['mrn']})".replace("  ", " ")
    return shielded("prescribe_medication",
                    {"patient_id": patient_id, "drug": drug, "dose": dose}, run)


@tool
def send_email(to: str, subject: str, body: str = "") -> str:
    """Send an email to an external address. Leaves the organisation."""
    def run():
        return f"email sent to {to} — subject: {subject} ({len(body)} chars)"
    # to/subject/body all go to Shield: this is the one tool whose PARAMETERS
    # matter as much as the caller's role. Who may email is a role question;
    # whether a patient's chart may go to a personal address is a payload one.
    return shielded("send_email", {"to": to, "subject": subject, "body": body}, run)


TOOLS = [patient_lookup, view_records, check_vitals, prescribe_medication,
         send_email]

# Deliberately silent about permissions. A model that self-censors hides the
# control behind its own caution; what this shows is what happens when the model
# is willing and the authorizer is not.
SYSTEM = (
    "You are a clinical assistant. Use the tools to answer. If a tool returns "
    "DENIED, tell the user plainly that they are not permitted to do it and "
    "say which action was refused — do not retry it and do not work around it. "
    "Do not consider permissions when choosing a tool; a separate layer decides."
)

_agent = None


def get_agent():
    global _agent
    if _agent is None:
        if not os.getenv("OPENAI_API_KEY"):
            return None
        _agent = create_agent(
            ChatOpenAI(model=MODEL, temperature=0), TOOLS, system_prompt=SYSTEM)
    return _agent


def stream_turn(agent, history):
    """Run one turn, printing tokens as they arrive.

    stream_mode="messages" yields (chunk, metadata) per LLM token, so the answer
    appears as it is generated rather than after the whole turn. Tool calls and
    Shield's verdicts interleave in the order they actually happen — which is
    the honest picture of an agent loop, and not what a spinner followed by a
    finished paragraph suggests.

    On reasoning: gpt-4o-mini produces none. Reasoning tokens are an o-series /
    GPT-5 feature, and OpenAI returns a COUNT plus optional summaries, never the
    raw chain — so there is nothing to stream for most models. Where a chunk
    does carry reasoning content it is printed, dimmed, rather than pretended
    into existence.
    """
    answered = False
    final_state = None
    # Ask for BOTH streams in one run: token chunks to print, and the
    # accumulated state to keep. Re-invoking afterwards to get the state would
    # replay the entire turn — every tool a second time.
    for mode, payload in agent.stream({"messages": history},
                                      stream_mode=["messages", "values"]):
        if mode == "values":
            final_state = payload
            continue
        chunk, meta = payload
        # Some providers attach reasoning summaries here. Most attach nothing.
        extra = getattr(chunk, "additional_kwargs", {}) or {}
        thought = extra.get("reasoning_content") or extra.get("reasoning")
        if thought and state["trace"]:
            print(f"{DIM}{thought}{Z}", end="", flush=True)

        if isinstance(chunk, ToolMessage):
            if state["trace"]:
                print(f"\n  {DIM}tool result → {str(chunk.content)[:150]}{Z}")
            continue
        text = chunk.content if isinstance(chunk.content, str) else ""
        if text:
            if not answered:
                print(f"\n{G}", end="")
                answered = True
            print(text, end="", flush=True)
    if answered:
        print(Z)
    else:
        print(f"\n{DIM}(no text answer){Z}")
    # The last "values" payload IS the final state. Calling invoke() here to
    # fetch it re-ran the whole turn: every tool executed twice, which for a
    # read is wasted latency and for prescribe_medication or send_email is a
    # duplicate side effect.
    return final_state["messages"] if final_state else history


def screen(text):
    """Input guardrails, before the agent sees anything."""
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{SHIELD}/guardrails/input", json={"message": text},
                          headers=headers(), timeout=TIMEOUT)
        d = r.json()
    except Exception as e:
        print(f"  {R}error{Z} {e}")
        return False
    if state["trace"]:
        ran = d.get("guardrail_results", []) or []
        bad = [g["guardrail"] for g in ran if not g.get("passed")]
        print(f"  {DIM}input{Z} {(R + 'BLOCK' + Z) if bad else (G + 'pass' + Z)} "
              f"{DIM}{len(ran)} guardrails, {(time.perf_counter() - t0) * 1000:.0f}ms{Z}")
    if d.get("safe") is False:
        for g in d.get("guardrail_results", []):
            if not g.get("passed") and g.get("message"):
                print(f"  {R}BLOCKED{Z} {DIM}{g['message'][:160]}{Z}")
        return False
    return True


def who():
    print(f"  agent  {B}{AGENT}{Z}   role {B}{state['role']}{Z}", end="")
    if state["token"]:
        c = claims_of(state["token"])
        print(f"  {DIM}from token sub={str(c.get('sub'))[:12]}...{Z}")
    else:
        print(f"  {DIM}(claimed in a header — not proven){Z}")


def login(user):
    if not (KC_URL and KC_PASSWORD):
        return None, "KEYCLOAK_URL / KC_PASSWORD not set"
    r = requests.post(f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token",
                      data={"grant_type": "password", "client_id": KC_CLIENT,
                            "username": user, "password": KC_PASSWORD}, timeout=30)
    if r.status_code != 200:
        return None, f"{r.status_code}: {r.text[:120]}"
    return r.json()["access_token"], None


BANNER = f"""{B}Shield · LangChain agent — interactive{Z}
{DIM}shield {SHIELD}   agent {AGENT}   model {MODEL}{Z}

{B}A real agent loop.{Z}{DIM} The model calls tools, reads the results, and keeps going
until it can answer you — including when Shield refuses. A denial comes back as
the tool's output, so the agent has to tell you about it in words.{Z}

{B}Try{Z}
{DIM}  what are the vitals for patient 103, and should I be worried?{Z}
{DIM}  look up patient 101 and tell me if amoxicillin is safe for her{Z}
{DIM}  prescribe amoxicillin to patient 101{Z}
{DIM}  email patient 101's chart to sun@gmail.com{Z}
{DIM}  /login nurse.jones     then ask it to prescribe again{Z}

{B}Commands{Z}{DIM}  /login <user>  /role <name>  /who  /trace  /quit{Z}
{DIM}Answers stream as they are generated. gpt-4o-mini emits no reasoning tokens —
those are an o-series/GPT-5 feature and the provider returns summaries, not the
raw chain. Set DEMO_MODEL to a reasoning model and any summary shown will
appear dimmed above the answer.{Z}
"""


def main():
    if not KEY:
        sys.exit("set TENANT_API_KEY")
    print(BANNER)
    who()
    history = []
    while True:
        try:
            line = input(f"\n{B}▸ {Z}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line in ("/quit", "/q"):
            break
        if line == "/who":
            who()
            continue
        if line == "/trace":
            state["trace"] = not state["trace"]
            print(f"  {DIM}trace {'on' if state['trace'] else 'off'}{Z}")
            continue
        if line.startswith("/role"):
            parts = line.split(maxsplit=1)
            state["role"] = parts[1].strip() if len(parts) > 1 else state["role"]
            print(f"  {DIM}role claimed →{Z} {state['role']}")
            continue
        if line.startswith("/login"):
            parts = line.split(maxsplit=1)
            user = parts[1].strip() if len(parts) > 1 else KC_USER
            tok, err = login(user)
            if err:
                print(f"  {R}login failed{Z} — {err}")
            else:
                state["token"] = tok
                roles = (claims_of(tok).get("realm_access") or {}).get("roles", [])
                state["role"] = roles[0] if roles else state["role"]
                # A new person means a new conversation. Carrying history across
                # a role change would let the previous role's tool results stay
                # in context and be summarised to someone not entitled to them.
                history = []
                print(f"  {G}signed in as {user}{Z} — roles {roles} "
                      f"{DIM}(history cleared){Z}")
            continue

        if not screen(line):
            continue
        agent = get_agent()
        if agent is None:
            print(f"  {Y}set OPENAI_API_KEY{Z} — this demo needs a model")
            continue

        history.append(HumanMessage(content=line))
        try:
            history = stream_turn(agent, history)
        except Exception as e:
            print(f"  {R}agent error{Z} {e.__class__.__name__}: {str(e)[:200]}")
            history.pop()


if __name__ == "__main__":
    main()
