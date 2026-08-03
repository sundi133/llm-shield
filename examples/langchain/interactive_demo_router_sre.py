#!/usr/bin/env python3
"""The SRE agent from interactive_demo_sre.py, routed through LiteLLM.

Same agent, same tools, same Shield authorization inside every tool. The one
thing that changes is where the model call goes:

    interactive_demo_sre.py     agent ->            OpenAI
    this file                   agent -> LiteLLM -> whichever model the router picks

LiteLLM is an OpenAI-compatible proxy, so LangChain still talks to it with
ChatOpenAI — only base_url and the key change. That buys two things worth
demoing:

  * one model name, many providers. DEMO_MODEL=moonshotai/kimi-k2.5 or
    gpt-4.1-mini or claude-sonnet-4-5 with nothing else touched.
  * guardrails enforced at the ROUTER, not by this client. The `guardrails`
    field names the guards LiteLLM's votal_guardrail plugin runs against Shield,
    pre-call and post-call. A blocked prompt never reaches the model — and the
    block is not this script politely deciding not to send.

    Watch out for the shape of that block: the proxy answers 200 with the
    refusal as the assistant's message (finish_reason=content_filter), so it
    reaches LangChain looking exactly like a real answer. guard_block() below is
    what keeps the demo from printing "your request was blocked" in the same
    green as a genuine reply.

That second point is the difference that matters. In interactive_demo_sre.py the
input screen is a call THIS process chooses to make; an agent that skipped it
would still reach the model. Here the guard sits in the path.

Identity, and it is easy to get wrong: LiteLLM claims the `x-api-key` header for
its own virtual keys, so the Shield tenant key travels in the body as
`metadata.tenant_api_key`. The tool-call path (tool/check, cap/mint) still goes
straight to Shield with X-API-Key as before — that is a different hop.

Usage:

    export LITELLM_URL=https://litellm-guardrails-votal-ai-production.up.railway.app
    export LITELLM_KEY=sk-...                  # LiteLLM virtual/master key
    export LLM_SHIELD_URL=https://api.guardrails.votal.ai \
           KEYCLOAK_URL=http://localhost:8180 KEYCLOAK_REALM=shield \
           KEYCLOAK_CLIENT=demo-cli KC_USER=dr.smith KC_PASSWORD=password \
           AGENT_ID=sre-agent TENANT_API_KEY=bank-co-key \
           DEMO_MODEL=moonshotai/kimi-k2.5 DEMO_CAPS=1
    python examples/langchain/interactive_demo_router_sre.py

No OPENAI_API_KEY. The router holds the provider credentials.
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

# ── the router ───────────────────────────────────────────────────────────
LITELLM_URL = os.getenv(
    "LITELLM_URL",
    "https://litellm-guardrails-votal-ai-production.up.railway.app").rstrip("/")
LITELLM_KEY = os.getenv("LITELLM_KEY", "")
MODEL = os.getenv("DEMO_MODEL", "moonshotai/kimi-k2.5")
# The proxy configures these default_on:false, so every request names the guards
# it wants. Empty (LITELLM_GUARDRAILS="") sends none — useful for showing the
# same agent with the router's guards switched off.
#
# These names are the ones the live proxy actually serves. The shorter
# `votal-input-guard` / `votal-output-guard` are also accepted, but on the
# current deployment every prompt through them comes back "Guardrail check
# failed" — including "say hello in 3 words" — and in streaming the turn dies
# with "Streaming response failed final Votal check. Triggered: unknown". That
# is a broken guard failing closed, not a demo worth showing.
GUARDS = [g.strip() for g in os.getenv(
    "LITELLM_GUARDRAILS",
    "votal-cloud-input-guardrails,votal-cloud-output-guardrails").split(",")
    if g.strip()]
# The client-side /guardrails/input call the direct-OpenAI demo makes. Off by
# default here: the router already screens, and running both would screen the
# same text twice and hide which layer actually caught it.
LOCAL_SCREEN = os.getenv("DEMO_LOCAL_SCREEN", "").strip().lower() in (
    "1", "true", "yes", "on")

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
RUN = "run-" + uuid.uuid4().hex[:8]

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

    Unchanged by the router: LiteLLM sits between the agent and the model, not
    between the agent and its tools. Tool authorization stays a direct hop to
    Shield.
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


# ── the model, via the router ────────────────────────────────────────────

def _chat_model():
    """ChatOpenAI pointed at LiteLLM. Same class, different address.

    Everything the guardrail plugin needs travels with the request:

      guardrails                which guards to run (default_on:false on the proxy)
      metadata.tenant_api_key   whose policies apply. In the BODY, because
                                LiteLLM eats the x-api-key header as its own
                                virtual key — a header here silently authorizes
                                as the wrong thing.
      metadata.user_role        the role, so the proxy's post-call tool RBAC
                                sees the same role the tools do.
    """
    return ChatOpenAI(
        model=MODEL,
        temperature=0,
        base_url=f"{LITELLM_URL}/v1",
        api_key=LITELLM_KEY,
        extra_body={
            "guardrails": GUARDS,
            "metadata": {"tenant_api_key": KEY, "agent_key": AGENT,
                         "user_role": state["role"], "session_id": SESSION},
        },
        default_headers={"x-agent-key": AGENT, "x-user-role": state["role"],
                         "x-session-id": SESSION, "x-shield-run-id": RUN},
    )


_agent = {"role": None, "obj": None}


def get_agent():
    # Keyed on role, not cached once. The role rides along in the request
    # metadata, so a cached agent built as "contractor" would keep telling the
    # proxy "contractor" after /login makes you an sre_lead — the tools would
    # enforce the new role and the router would enforce the old one.
    if _agent["obj"] is None or _agent["role"] != state["role"]:
        if not LITELLM_KEY:
            return None
        _agent["obj"] = create_agent(_chat_model(), TOOLS, system_prompt=SYSTEM)
        _agent["role"] = state["role"]
    return _agent["obj"]


def guard_block(x):
    """Did the router refuse this, or is this a real answer?

    Worth knowing how the block actually arrives, because it is not what you
    would guess: the proxy answers 200 and puts the refusal in the assistant
    message with finish_reason=content_filter — streaming included, as one
    chunk. So a block looks exactly like the model replying, and a client that
    does not check prints "Your request was blocked..." in the same green as a
    real answer.

    Takes text or an exception. Some failures (a guard that errors mid-stream)
    do surface as exceptions, and those go through here too.
    """
    low = str(x).lower()
    # "by votal guardrails" and not "blocked by votal guardrails": the output
    # guard firing part-way through a stream says "blocked MID-STREAM by Votal
    # guardrails", which the narrower phrase missed — and a working control then
    # printed as "agent error", which is the one way it must never read.
    return ("by votal guardrails" in low
            or "triggered guardrails:" in low
            or "guardrail check failed" in low
            or "votal check" in low)


# ── the loop ─────────────────────────────────────────────────────────────

def stream_turn(agent, history):
    """Run one turn, printing tokens as they arrive.

    stream_mode="messages" yields (chunk, metadata) per LLM token, so the answer
    appears as it is generated rather than after the whole turn. Tool calls and
    Shield's verdicts interleave in the order they actually happen — which is
    the honest picture of an agent loop, and not what a spinner followed by a
    finished paragraph suggests.

    On reasoning: whether anything streams here is the router's business now.
    Models that emit reasoning content (kimi, the o-series via LiteLLM) surface
    it in additional_kwargs; most emit nothing, and nothing is printed rather
    than a chain of thought invented for the demo.
    """
    answered = False
    blocked = False
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
            # The colour is decided on the FIRST text chunk, and the refusal
            # arrives whole in that chunk — so this is enough to tell a block
            # from an answer before a single character is printed green.
            if not answered:
                blocked = guard_block(text)
                if blocked:
                    print(f"\n  {R}BLOCKED at the router{Z} "
                          f"{DIM}— this never reached {MODEL}{Z}\n  {R}", end="")
                else:
                    print(f"\n{G}", end="")
                answered = True
            print(text, end="", flush=True)
    if answered:
        print(Z)
    else:
        print(f"\n{DIM}(no text answer){Z}")
    # The last "values" payload IS the final state. Calling invoke() here to
    # fetch it re-ran the whole turn: every tool executed twice, which for a
    # read is wasted latency and for rotate_credential or send_webhook is a
    # duplicate side effect.
    return (final_state["messages"] if final_state else history), blocked


def screen(text):
    """Input guardrails called directly, the way the non-router demo does it.

    Off unless DEMO_LOCAL_SCREEN=1. The router runs the same guards in the
    request path; this is here so the two placements can be compared side by
    side, not because the demo needs both.
    """
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


BANNER = f"""{B}Shield · SRE copilot — an agent with production access, routed through LiteLLM{Z}
{DIM}router {LITELLM_URL}   model {MODEL}
shield {SHIELD}   agent {AGENT}
router guards {', '.join(GUARDS) or '(none — LITELLM_GUARDRAILS is empty)'}{Z}

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

{B}What the router adds{Z}{DIM}  /model <name> swaps providers mid-demo, and a prompt the
             guards refuse never reaches the model — the block comes back from
             LiteLLM, not from this script deciding not to send.{Z}

{B}Commands{Z}{DIM}  /login <user>  /role <name>  /model <name>  /models  /who  /trace  /quit{Z}
"""


def router_preflight():
    """Ask the proxy what it serves, before the first turn spends a minute.

    A wrong DEMO_MODEL is otherwise a 400 in the middle of the first answer,
    which reads as the agent being broken rather than as a name the router does
    not have.
    """
    try:
        r = requests.get(f"{LITELLM_URL}/v1/models", timeout=30,
                         headers={"Authorization": f"Bearer {LITELLM_KEY}"})
    except Exception as e:
        print(f"  {Y}cannot reach the router at {LITELLM_URL}{Z} {DIM}({e.__class__.__name__}){Z}\n")
        return []
    if r.status_code != 200:
        print(f"  {Y}router rejected the key{Z} {DIM}{r.status_code}: {r.text[:120]}{Z}\n")
        return []
    names = [m.get("id") for m in (r.json().get("data") or []) if m.get("id")]
    if MODEL in names:
        print(f"  {G}router ready{Z} {DIM}— {MODEL}, {len(names)} models available{Z}")
    else:
        print(f"  {Y}router does not serve '{MODEL}'{Z}")
        print(f"  {DIM}try one of: {', '.join(names[:12])}{Z}")
    return names


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
    global MODEL
    if not KEY:
        sys.exit("set TENANT_API_KEY")
    if not LITELLM_KEY:
        sys.exit("set LITELLM_KEY — the LiteLLM virtual/master key. "
                 "This demo has no OPENAI_API_KEY path; the router holds the "
                 "provider credentials.")
    print(BANNER)
    served = router_preflight()
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
        if line == "/models":
            served = served or router_preflight()
            print(f"  {DIM}{', '.join(served) or 'none'}{Z}")
            continue
        if line.startswith("/model"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                MODEL = parts[1].strip()
                _agent["obj"] = None          # rebuild against the new model
                # History carries over on purpose: the same conversation
                # continuing on a different provider is the thing worth seeing.
                print(f"  {DIM}model →{Z} {MODEL}")
                if served and MODEL not in served:
                    print(f"  {Y}the router does not list this model{Z}")
            else:
                print(f"  {DIM}model{Z} {MODEL}")
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

        if LOCAL_SCREEN and not screen(line):
            continue
        agent = get_agent()
        if agent is None:
            print(f"  {Y}set LITELLM_KEY{Z} — this demo reaches the model through the router")
            continue

        if state["trace"]:
            print(f"  {DIM}router{Z} {B}{MODEL}{Z} {DIM}via litellm · "
                  f"guards {', '.join(GUARDS) or 'none'}{Z}")

        before = list(history)
        history.append(HumanMessage(content=line))
        try:
            history, blocked = stream_turn(agent, history)
            if blocked:
                # Roll the turn back. The refusal is a message the assistant
                # never wrote; leaving it in context teaches the model that it
                # answers that way, and the blocked prompt would be re-sent with
                # every following turn and blocked again.
                history = before
        except Exception as e:
            if guard_block(e):
                # The output guard fires on text already on its way out, so
                # some of the answer is above this line. Say so — a truncated
                # sentence followed by a red line otherwise looks like a crash.
                print(f"\n  {R}CUT OFF at the router{Z} "
                      f"{DIM}— the output guard stopped the answer mid-stream; "
                      f"what printed above is partial{Z}")
                print(f"  {DIM}{str(e)[:300]}{Z}")
            else:
                print(f"  {R}agent error{Z} {e.__class__.__name__}: {str(e)[:200]}")
            history = before


if __name__ == "__main__":
    main()
