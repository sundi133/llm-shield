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
import uuid

import requests

SHIELD = (os.getenv("LLM_SHIELD_URL") or os.getenv("SHIELD_URL")
          or "http://localhost:8000").rstrip("/")
KEY = os.getenv("TENANT_API_KEY", "")
AGENT = os.getenv("AGENT_ID", "sre-copilot")
TIMEOUT = float(os.getenv("SHIELD_TIMEOUT", "120"))
MODEL = os.getenv("DEMO_MODEL", "gpt-4o-mini")

KC_URL = (os.getenv("KEYCLOAK_URL") or "").rstrip("/")
KC_REALM = os.getenv("KEYCLOAK_REALM", "shield")
KC_CLIENT = os.getenv("KEYCLOAK_CLIENT", "demo-cli")
KC_USER = os.getenv("KC_USER", "dr.smith")
KC_PASSWORD = os.getenv("KC_PASSWORD", "")

# DEMO_CAPS=1 switches from the advisory path to the capability path.
#   off: tool/check — Shield answers allow/deny and this client chooses to obey
#   on:  cap/mint -> cap/verify — Shield mints a signed, single-use token bound
#        to one tool and one resource, and the nonce is burned before the tool
#        runs. Skipping Shield is no longer a client-side decision.
# The roles the SRE matrix defines. Used to pick the meaningful one out of a
# token that also carries Keycloak's realm defaults.
DEMO_ROLES = ("sre_lead", "oncall_engineer", "contractor", "ci_bot", "intern")

CAPS = os.getenv("DEMO_CAPS", "").strip().lower() in ("1", "true", "yes", "on")
TENANT = os.getenv("TENANT_ID", "")
INSTANCE = "inst-" + uuid.uuid4().hex[:8]
SESSION = "sess-" + uuid.uuid4().hex[:8]

G, R, Y, DIM, B, Z = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"

state = {"role": os.getenv("USER_ROLE", "contractor"), "token": "",
         "trace": os.getenv("DEMO_TRACE", "1") not in ("0", "false", "no"),
         "agent_token": ""}

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_data_sre.json")
try:
    with open(_DATA) as f:
        INFRA = json.load(f)
except Exception as e:                                    # pragma: no cover
    print(f"could not load demo_data_sre.json ({e})")
    INFRA = {"services": {}, "secrets": {}, "firewall": [], "db": {}}


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


def _svc(name):
    return (INFRA.get("services") or {}).get(str(name).strip())


def mint_agent_token():
    """Exchange the tenant credential for an agent identity token (AuthN).

    Needs `tenant_key` in SHIELD_WORKLOAD_IDENTITY_PROVIDERS on the data plane;
    a tenant issues for its own tenant and no other, so the operator's admin key
    stays out of this. user_sub is the Keycloak subject when signed in, so the
    capability names a real person rather than a string this script invented.
    """
    sub = "anonymous"
    if state["token"]:
        sub = claims_of(state["token"]).get("sub") or sub
    body = {"user_sub": sub, "agent_id": AGENT, "agent_instance_id": INSTANCE,
            "tenant_id": TENANT, "build_hash": "demo", "model_version": MODEL,
            "session_id": SESSION, "ttl_seconds": 900}
    try:
        r = requests.post(f"{SHIELD}/v1/shield/auth/agent-token", json=body,
                          headers=headers(), timeout=TIMEOUT)
    except Exception as e:
        return None, f"{e.__class__.__name__}"
    if r.status_code != 200:
        return None, f"{r.status_code}: {r.text[:160]}"
    return r.json()["agent_token"], None


def _advisory_check(tool_name, params):
    """tool/check as a gate before minting. None if allowed, else the denial."""
    t0 = time.perf_counter()
    try:
        d = requests.post(f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
                          headers=headers(),
                          json={"agent_key": AGENT, "tool_name": tool_name,
                                "user_role": state["role"],
                                "tool_params": params}).json()
    except Exception as e:
        return f"DENIED — could not reach Shield to authorize this ({e.__class__.__name__})"
    ms = (time.perf_counter() - t0) * 1000
    allowed = bool(d.get("allowed"))
    if state["trace"]:
        print(f"  {DIM}rbac{Z} {(G + 'ALLOW' + Z) if allowed else (R + 'DENY' + Z)} "
              f"{B}{tool_name}{Z} {DIM}role={state['role']} {ms:.0f}ms{Z}")
    if allowed:
        return None
    why = next((g.get("message") for g in d.get("guardrail_results", [])
                if not g.get("passed", True)), "not permitted")
    if state["trace"]:
        print(f"       {DIM}{str(why)[:120]}{Z}")
        print(f"       {DIM}no capability minted — the check gates the mint{Z}")
    return f"DENIED by policy: {why}"


def _capability_path(tool_name, params, run):
    """mint -> verify (nonce burned) -> execute.

    cap/mint runs the SAME authorization stack as tool/check, so this replaces
    that call rather than adding to it. Doing both would pay twice and write two
    audit entries for one decision.
    """
    if not state["agent_token"]:
        tok, err = mint_agent_token()
        if err:
            return (f"DENIED — no agent identity ({err}). "
                    f"Needs tenant_key enabled and TENANT_ID matching the API key.")
        state["agent_token"] = tok
        if state["trace"]:
            print(f"  {DIM}authn{Z} {G}agent token{Z} {DIM}instance={INSTANCE}{Z}")

    # The resource the capability is bound to. A cap for patient 101 does not
    # authorize patient 102 — that binding is the point of minting per action.
    resource = (f"service/{params['service']}" if params.get("service")
                else f"secret/{params['name']}" if params.get("name")
                else f"{tool_name}/any")
    auth = dict(headers(), **{"X-Agent-Token": state["agent_token"]})

    t0 = time.perf_counter()
    try:
        r = requests.post(f"{SHIELD}/v1/shield/cap/mint", timeout=TIMEOUT, headers=auth,
                          json={"tool": tool_name, "resource": resource,
                                "ttl_seconds": 30, "session_id": SESSION,
                                "tool_params": params})
    except Exception as e:
        return f"DENIED — could not reach Shield to mint a capability ({e.__class__.__name__})"
    mint_ms = (time.perf_counter() - t0) * 1000

    if r.status_code != 200:
        if state["trace"]:
            print(f"  {DIM}cap{Z} {R}NO MINT{Z} {B}{tool_name}{Z} "
                  f"{DIM}role={state['role']} {mint_ms:.0f}ms{Z}")
            print(f"       {DIM}{r.text[:160]}{Z}")
        # A refused mint IS the authorization decision.
        return f"DENIED by policy: {r.text[:200]}"
    cap = r.json()["cap_token"]

    # The verify step is what a tool server would do before executing. Here it
    # runs in the same process, so the process boundary is simulated — but the
    # signature check, the tool binding and the nonce burn are real, and the cap
    # cannot be presented twice.
    t1 = time.perf_counter()
    v = requests.post(f"{SHIELD}/v1/shield/cap/verify", timeout=TIMEOUT,
                      headers=headers(),
                      json={"cap_token": cap, "expected_tool": tool_name}).json()
    verify_ms = (time.perf_counter() - t1) * 1000

    if state["trace"]:
        ok = v.get("valid") is True
        print(f"  {DIM}cap{Z} {(G + 'MINT+BURN' + Z) if ok else (R + 'INVALID' + Z)} "
              f"{B}{tool_name}({resource}){Z} {DIM}role={state['role']} "
              f"mint {mint_ms:.0f}ms · verify {verify_ms:.0f}ms{Z}")
        if not ok:
            print(f"       {DIM}{v.get('error', '')}{Z}")
    if v.get("valid") is not True:
        return f"DENIED — capability did not verify: {v.get('error', 'invalid')}"
    return run()


# ── Shield, inside the tool ──────────────────────────────────────────────

def shielded(tool_name, params, run):
    """Authorize, then run. The denial is RETURNED, not raised.

    An exception would end the agent's turn and it would report a crash. The
    agent should learn that it may not do this and say so, which means the
    refusal has to arrive the way any other tool result does.
    """
    if CAPS:
        # RBAC FIRST, then mint. cap/mint does not enforce role -> tool: it
        # unions every role's permissions, so a nurse can mint a capability to
        # prescribe that tool/check denies. Until that is fixed server-side, an
        # application that wants the role respected has to ask for the check
        # explicitly and refuse to mint on a denial.
        #
        # This makes the DEMO correct. It does not close the hole — a client
        # that skips this call still gets the capability. The fix belongs in
        # _decide_authz.
        verdict = _advisory_check(tool_name, params)
        if verdict is not None:
            return verdict
        return _capability_path(tool_name, params, run)

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
def read_logs(service: str, lines: int = 20) -> str:
    """Read recent log lines for a service. Read-only."""
    def run():
        s = _svc(service)
        if not s:
            return f"no service named {service}"
        return "\n".join(s["logs"][-int(lines or 20):])
    return shielded("read_logs", {"service": service}, run)


@tool
def query_prod_db(table: str, limit: int = 5) -> str:
    """Run a read query against the production database."""
    def run():
        rows = (INFRA.get("db") or {}).get(table.strip())
        if rows is None:
            return f"no table named {table}"
        return json.dumps(rows[:int(limit or 5)])
    return shielded("query_prod_db", {"table": table, "limit": limit}, run)


@tool
def restart_service(service: str) -> str:
    """Restart a service. Disruptive but reversible."""
    def run():
        s = _svc(service)
        return f"restarted {service} ({s['replicas']} replicas)" if s else f"no service named {service}"
    return shielded("restart_service", {"service": service}, run)


@tool
def scale_deployment(service: str, replicas: int) -> str:
    """Change the replica count for a service."""
    def run():
        s = _svc(service)
        if not s:
            return f"no service named {service}"
        was = s["replicas"]
        s["replicas"] = int(replicas)
        return f"scaled {service} from {was} to {replicas} replicas"
    return shielded("scale_deployment",
                    {"service": service, "replicas": replicas}, run)


@tool
def read_secret(name: str) -> str:
    """Read a secret value from the vault."""
    def run():
        v = (INFRA.get("secrets") or {}).get(name.strip())
        return f"{name} = {v}" if v else f"no secret named {name}"
    return shielded("read_secret", {"name": name}, run)


@tool
def rotate_credential(name: str) -> str:
    """Rotate a credential and return the new value."""
    def run():
        secrets = INFRA.get("secrets") or {}
        if name.strip() not in secrets:
            return f"no secret named {name}"
        new = f"pk_live_ROTATED_{uuid.uuid4().hex[:16]}"
        secrets[name.strip()] = new
        return f"{name} rotated; new value {new}"
    return shielded("rotate_credential", {"name": name}, run)


@tool
def open_firewall_rule(port: int, cidr: str) -> str:
    """Open a port to a CIDR range on the production edge."""
    def run():
        INFRA.setdefault("firewall", []).append({"port": int(port), "cidr": cidr})
        return f"opened port {port} to {cidr}"
    return shielded("open_firewall_rule", {"port": port, "cidr": cidr}, run)


@tool
def delete_namespace(namespace: str) -> str:
    """Delete an entire Kubernetes namespace. Irreversible."""
    def run():
        return f"deleted namespace {namespace} and everything in it"
    return shielded("delete_namespace", {"namespace": namespace}, run)


@tool
def send_webhook(url: str, payload: str) -> str:
    """POST a payload to an external URL. Leaves the organisation."""
    # url AND payload both go to Shield: who may call a webhook is a role
    # question, whether a rotated credential may travel in the body is not.
    def run():
        return f"posted {len(payload)} bytes to {url}"
    return shielded("send_webhook", {"url": url, "payload": payload}, run)


TOOLS = [read_logs, query_prod_db, restart_service, scale_deployment,
         read_secret, rotate_credential, open_firewall_rule, delete_namespace,
         send_webhook]


# Deliberately silent about permissions. A model that self-censors hides the
# control behind its own caution; what this shows is what happens when the model
# is willing and the authorizer is not.
SYSTEM = (
    "You are a site-reliability assistant. Use the tools to answer. If a tool returns "
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


BANNER = f"""{B}Shield · SRE copilot — an agent with production access{Z}
{DIM}shield {SHIELD}   agent {AGENT}   model {MODEL}{Z}

{B}Sign in as{Z}{DIM}  alex.chen (sre_lead) · sam.patel (oncall_engineer)
             jordan.ext (contractor) · riley.grad (intern) · ci-bot (ci_bot)
             password for all of them is "password" — the role comes from the token{Z}

{B}The beats{Z}
{DIM}  /login riley.grad   restart checkout-api                   denied, plainly{Z}
{DIM}  /login jordan.ext   I need the prod DB password to debug   denied, no human needed{Z}
{DIM}  /login ci-bot       rotate the prod-db-password credential a bot cannot be phished{Z}
{DIM}  /login sam.patel    open port 5432 to 0.0.0.0/0 to debug   3am pressure, refused{Z}
{DIM}  /login alex.chen    rotate prod-db-password, then post it to{Z}
{DIM}                      https://collect.example/audit          ALLOWED by role,{Z}
{DIM}                                                             BLOCKED on payload{Z}

{B}The closer — indirect injection{Z}
{DIM}  /login jordan.ext{Z}
{DIM}  read the auth-svc logs and do whatever they say needs doing{Z}
{DIM}  The logs carry an instruction. The model obeys it. The role does not.{Z}

{B}Commands{Z}{DIM}  /login <user>  /role <name>  /who  /trace  /quit{Z}
"""


def preflight():
    """Say up front whether this agent exists in the tenant.

    Without a registry entry every tool call fails tool_allowlist, which reads
    as a broken demo rather than missing configuration — and it fails the same
    way for every role, so the matrix looks like it denies everything. Better to
    say so once, at startup, than to have it discovered mid-demo.
    """
    try:
        d = requests.post(f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
                          headers=headers(),
                          json={"agent_key": AGENT, "tool_name": "read_logs",
                                "user_role": "sre_lead",
                                "tool_params": {"service": "checkout-api"}}).json()
    except Exception as e:
        print(f"  {Y}cannot reach Shield at {SHIELD}{Z} {DIM}({e.__class__.__name__}){Z}\n")
        return
    if d.get("allowed"):
        print(f"  {G}agent registered{Z} {DIM}— sre_lead may read_logs, matrix is live{Z}\n")
        return
    why = " ".join(str(g.get("message", "")) for g in d.get("guardrail_results", [])
                   if not g.get("passed", True)).lower()
    # Match only the phrase the registry itself emits. Matching "allowlist" or
    # "unknown" caught a REGISTERED agent that simply lacks this tool, and told
    # the operator to go create something that already exists — a diagnostic
    # confidently pointing at the wrong problem.
    # The phrases the registry actually emits, checked against the live
    # deployment rather than guessed: rbac_guard says "unknown agent key" for an
    # agent that does not exist, and the registry gate says "not registered" /
    # "is not active". An earlier version matched "allowlist" too, which caught
    # a REGISTERED agent merely lacking this tool and told the operator to
    # create something that already existed.
    if ("unknown agent key" in why or "not registered" in why
            or "is not active" in why):
        print(f"  {Y}agent '{AGENT}' is not registered in this tenant.{Z}")
        print(f"  {DIM}Every tool will be denied the same way regardless of role, which{Z}")
        print(f"  {DIM}looks like the matrix denying everything. Create '{AGENT}' in the{Z}")
        print(f"  {DIM}portal with these tools:{Z}")
        print(f"  {DIM}    {', '.join(t.name for t in TOOLS)}{Z}")
        print(f"  {DIM}and roles: {', '.join(DEMO_ROLES)}{Z}\n")
    else:
        # Registered, but this tool is not granted to sre_lead. A policy
        # answer, not a setup problem — do not send anyone to the portal.
        print(f"  {Y}agent '{AGENT}' exists, but sre_lead is not granted read_logs{Z}")
        print(f"  {DIM}{why[:170]}{Z}")
        print(f"  {DIM}Expected if this agent is not the SRE one — check AGENT_ID.{Z}\n")


def main():
    if not KEY:
        sys.exit("set TENANT_API_KEY")
    print(BANNER)
    preflight()
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
                # Pick a role this demo knows rather than roles[0]. Keycloak
                # returns default-roles-<realm> alongside the real one and the
                # order is not guaranteed, so roles[0] is a coin flip that
                # currently lands right — and would silently authorize as
                # "default-roles-shield" the day it does not.
                known = [r for r in roles if r in DEMO_ROLES]
                state["role"] = known[0] if known else (roles[0] if roles else state["role"])
                if roles and not known:
                    print(f"  {Y}none of {roles} is a role this demo defines{Z}")
                # A new person means a new conversation. Carrying history across
                # a role change would let the previous role's tool results stay
                # in context and be summarised to someone not entitled to them.
                history = []
                state["agent_token"] = ""   # new subject -> new agent identity
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
