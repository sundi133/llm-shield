#!/usr/bin/env python3
"""A LangChain agent behind your own login, with Shield enforcing the role.

The shape most teams actually have: your own users table, no Okta, and a
LangChain agent that calls tools. You want Shield to enforce who may do what,
and you want the role to be something neither the user NOR the model can pick.

    browser ──► your FastAPI backend ──► LangChain agent ──► tool
                └ knows who logged in         │               └ runs only if
                └ holds the Shield secret     │                  Shield allowed
                                              └ the LLM picks the tool,
                                                never the role

Two different things could lie to you here, and they need different answers.

1. THE USER lies about their role.
   Answered by the trusted-proxy boundary. The backend resolves the role from
   its own session and asserts it to Shield with X-Shield-Proxy-Token. With
   SHIELD_ROLE_BINDING=strict_proxy, Shield accepts that assertion from this
   process and from nowhere else. A forged X-User-Role on the browser request
   is never even read.

2. THE MODEL lies about the role.
   This is the one specific to agents, and the answer is structural. Look at
   the tool signatures below: not one of them takes a `role` argument. The role
   is captured in a closure when the agent is built, per request, from the
   session. A prompt injection saying "call restart_service as sre_lead" has
   nowhere to put that — there is no parameter for it. The model chooses WHICH
   tool to call. It cannot choose WHO is calling.

   If you take one thing from this file, take that. A role passed as a tool
   argument is a role the LLM controls.

What this is NOT
----------------
The proxy secret proves the HOP, not the USER. Shield records
`role_source: proxy` and `role_verified: false` — vouched, not proven. If you
have an IdP, send the user's token as `X-On-Behalf-Of` and Shield verifies it
cryptographically. This file is the answer for teams who do not.

Setup
-----
    pip install -r requirements.txt

    export LLM_SHIELD_URL=https://api.guardrails.votal.ai   # NOT localhost:8000
    export TENANT_API_KEY=<your tenant key>
    export AGENT_ID=sre-agent                 # registered for that tenant
    export SHIELD_PROXY_TOKEN=<same value as SHIELD_TRUSTED_PROXY_SECRET>

    # The agent needs a model. Set ONE of these; whichever key is present picks
    # the provider, so an existing OpenAI deployment keeps working untouched.
    export ANTHROPIC_API_KEY=sk-ant-...       # -> claude-opus-5
    export OPENAI_API_KEY=sk-...              # -> gpt-4.1-mini
    export DEMO_MODEL=<model id>              # optional, overrides the default
    export DEMO_PROVIDER=anthropic|openai     # optional, only if both keys set

    export DEMO_CAPS=1                        # optional: capability path
    export TENANT_ID=<tenant id>              # only needed with DEMO_CAPS=1

On Shield:
    SHIELD_ROLE_BINDING=strict_proxy
    SHIELD_TRUSTED_PROXY_ONLY=true
    SHIELD_TRUSTED_PROXY_SECRET=<same value>

No Keycloak. That is the point — your login replaces it.

Run
---
    python langchain_trusted_proxy_agent.py            # serve on :8500
    python langchain_trusted_proxy_agent.py --attack   # forgeries, no LLM needed
"""
# NOTE: no `from __future__ import annotations`. It turns the Pydantic model
# annotations into strings that FastAPI cannot resolve unless the module is
# registered under its own name in sys.modules — which bites `uvicorn app:app`.
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import uuid
from typing import Optional

import requests
from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

# shield_client.py sits beside this file. Put that directory on the path
# explicitly rather than relying on cwd: `python examples/langchain/app.py`
# happens to work, `uvicorn app:app` from the repo root does not.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shield_client import ShieldClient  # noqa: E402

from langchain.agents import create_agent
from langchain_core.messages import AIMessageChunk
from langchain_core.tools import tool

# The @tool objects are built per REQUEST by session.tools(), closed over the
# role, rather than once at module level. That is the security design, not an
# accident: a shared tool would have to receive the role as an ARGUMENT, and
# every argument is chosen by the model. See shield_client.py.

SHIELD = os.getenv("LLM_SHIELD_URL", "http://localhost:8000").rstrip("/")

# NOT 8000. That is Shield's own default port and the default LLM_SHIELD_URL
# above, so binding there means this app either collides with a local Shield or
# calls itself. Both fail in confusing ways: you get Shield's auth error in the
# browser and assume this app is broken.
# PORT is what Railway, Render, Fly and Heroku inject. Honour it first, or the
# platform health-checks a port nothing is listening on and kills the deploy.
APP_PORT = int(os.getenv("PORT") or os.getenv("APP_PORT") or "8500")

# Loopback locally, all interfaces when a platform assigns the port — a
# container bound to 127.0.0.1 is unreachable from outside itself.
APP_HOST = os.getenv("APP_HOST") or ("0.0.0.0" if os.getenv("PORT") else "127.0.0.1")
TENANT_KEY = os.getenv("TENANT_API_KEY", "")
AGENT_KEY = os.getenv("SHIELD_AGENT_KEY") or os.getenv("AGENT_ID") or "sre-agent"
TENANT_ID = os.getenv("TENANT_ID", "")

# Which model provider. Nothing in Shield cares — the guardrail and capability
# calls are separate HTTP requests to Shield, and the LLM call goes straight to
# the vendor. The provider is an implementation detail of the agent, which is
# exactly why it is worth showing that swapping it changes no security code.
#
# Precedence, most specific signal first: an explicit DEMO_PROVIDER, then the
# model name, then which key is present. The model name has to outrank the key
# because DEMO_MODEL is the setting most likely to be stale in a shell that has
# run this demo before — inferring the provider from the key while taking the
# model from an old export asks Anthropic for gpt-4.1-mini, which is a 404 with
# no obvious cause. Falling back to the key last is what lets an existing
# OPENAI_API_KEY deployment keep working with no config change.
DEFAULT_MODEL = {"anthropic": "claude-opus-5", "openai": "gpt-4.1-mini"}
API_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

# Claude models that reject output_config.effort. Named individually rather
# than matched by prefix because this is a property of these two releases, not
# of their tiers — a later haiku is expected to support it, and would silently
# lose the setting under a "haiku" prefix rule. These are also the two someone
# reaches for to make a demo cheap, so getting it wrong is not a rare path.
NO_EFFORT = {"claude-haiku-4-5", "claude-sonnet-4-5"}


def _provider_of(model: str) -> str:
    """Which vendor serves this model id, or "" if the name does not say."""
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return "openai"
    return ""


MODEL = os.getenv("DEMO_MODEL", "")
PROVIDER = (os.getenv("DEMO_PROVIDER") or _provider_of(MODEL) or
            ("anthropic" if os.getenv("ANTHROPIC_API_KEY") else "openai")).lower()
MODEL = MODEL or DEFAULT_MODEL[PROVIDER]


def check_model_config() -> str:
    """Return a human-readable problem with the model settings, or "".

    Called at startup so a misconfiguration is a line in the terminal before
    the first request, not a 404 the browser reports as a failed answer.
    """
    if PROVIDER not in DEFAULT_MODEL:
        return (f"DEMO_PROVIDER={PROVIDER!r} is not one of "
                f"{', '.join(sorted(DEFAULT_MODEL))}.")
    named = _provider_of(MODEL)
    if named and named != PROVIDER:
        return (f"DEMO_MODEL={MODEL!r} is a {named} model but the provider "
                f"resolved to {PROVIDER!r}. Unset one of them.")
    if not os.getenv(API_KEY_ENV[PROVIDER]):
        return (f"provider {PROVIDER!r} (model {MODEL!r}) needs "
                f"{API_KEY_ENV[PROVIDER]}, which is not set. If you meant the "
                f"other vendor, unset DEMO_MODEL so it picks its own default.")
    return ""


def build_llm(streaming: bool = False):
    """The one place the provider is named. Both call paths go through here.

    Claude notes, because two of these are 400s rather than style choices:

      * No temperature. Claude Opus 5 removed the sampling parameters and
        rejects `temperature` outright, including the temperature=0 that reads
        as an obviously-safe default elsewhere.
      * max_tokens bounds thinking AND the reply together, and thinking is ON
        by default on Opus 5. Sized for the whole budget, not the answer.
      * effort low, not thinking disabled. Disabling thinking is permitted at
        this effort, but on Opus 5 it can make the model write a tool call as
        plain text — the call silently never runs, the turn still succeeds, and
        a demo whose entire point is watching tools get refused would quietly
        stop calling them. Low effort buys most of the latency back safely.
    """
    if PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        kwargs = {}
        if MODEL not in NO_EFFORT:
            kwargs["output_config"] = {"effort": "low"}
        return ChatAnthropic(model=MODEL, max_tokens=8192,
                             streaming=streaming, **kwargs)
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(model=MODEL, temperature=0, streaming=streaming)


# DEMO_CAPS=1 switches the tool path from advisory (tool/check only) to the
# capability path: mint a single-use token bound to this exact action, then
# verify and burn it. Read by ShieldClient.from_env(); same switch name as
# interactive_demo_sre.py.

# The shared secret. Lives ONLY on the server. Never in a template, never in an
# API response. If it reaches the browser, the browser becomes the trusted
# proxy and the control is gone.
PROXY_TOKEN = os.getenv("SHIELD_PROXY_TOKEN", "")

# Signs the session cookie. Separate from the Shield secret on purpose: reusing
# one for the other means leaking the cookie key hands over Shield's trust too.
SESSION_KEY = os.getenv("APP_SESSION_KEY", secrets.token_urlsafe(32))

TIMEOUT = 30
G, R, Y, B, DIM, Z = ("\033[32m", "\033[31m", "\033[33m", "\033[1m",
                      "\033[2m", "\033[0m")

# Stands in for whatever you already have: a users table, LDAP, your SaaS auth.
# What matters is that the ROLE is decided HERE, on the server.
# These role names must match the `role_permissions` on the sre-agent registry
# entry EXACTLY. A role the registry has never heard of gets no grants, which
# looks identical to "this role is correctly restricted" — so a typo here reads
# as working security. Check them against the Agent Registry page in the portal.
USERS = {
    "alex":   {"password": "demo", "role": "sre_lead"},
    "sam":    {"password": "demo", "role": "oncall"},
    "jordan": {"password": "demo", "role": "contractor"},
    "riley":  {"password": "demo", "role": "intern"},
    "ci":     {"password": "demo", "role": "ci_bot"},
}

# The same fixture interactive_demo_sre.py uses — services, secrets, db tables,
# firewall. Shared rather than copied so the two demos cannot drift.
_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_data_sre.json")
try:
    with open(_DATA) as _f:
        INFRA = json.load(_f)
except Exception as _e:                                    # pragma: no cover
    print(f"could not load demo_data_sre.json ({_e})")
    INFRA = {"services": {}, "secrets": {}, "db": {}}


def _svc(name):
    return (INFRA.get("services") or {}).get(str(name).strip())


# ── Sessions ─────────────────────────────────────────────────────────────

def _sign(payload: str) -> str:
    mac = hmac.new(SESSION_KEY.encode(), payload.encode(), hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")


def make_session(username: str) -> str:
    """Signed cookie carrying the USERNAME, not the role.

    A role baked into the cookie means a permission change does not take effect
    until the user logs out. Look it up per request; it is a dict read.
    """
    body = base64.urlsafe_b64encode(
        json.dumps({"u": username}).encode()).decode().rstrip("=")
    return f"{body}.{_sign(body)}"


def read_session(cookie: Optional[str]) -> Optional[str]:
    if not cookie or "." not in cookie:
        return None
    body, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(body)):
        return None
    try:
        pad = "=" * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(body + pad))["u"]
    except Exception:
        return None


def role_for(username: Optional[str]) -> str:
    """The one place a role is decided. Note what is not an input: the request."""
    return USERS.get(username or "", {}).get("role", "")


# ── Shield ───────────────────────────────────────────────────────────────
#
# One client for the process. Everything it needs comes from the environment;
# see shield_client.py for the constructor if you would rather be explicit.

shield = ShieldClient.from_env()


# ── The tools ────────────────────────────────────────────────────────────
#
# Ordinary functions. `@shield.tool` is a drop-in for LangChain's `@tool`, and
# adds the authorization check (and the capability mint, when enabled) around
# the body. Note what no signature has: a `role` argument. The role is bound
# per request in session.tools(), so the model cannot choose it.

@shield.tool
def read_logs(service: str, lines: int = 20) -> str:
    """Read recent log lines for a service. Read-only."""
    sv = _svc(service)
    if not sv:
        return f"no service named {service}"
    return "\n".join(sv["logs"][-int(lines or 20):])


@shield.tool
def query_prod_db(table: str, limit: int = 5) -> str:
    """Run a read query against the production database."""
    rows = (INFRA.get("db") or {}).get(table.strip())
    if rows is None:
        return f"no table named {table}"
    return json.dumps(rows[:int(limit or 5)])


@shield.tool
def restart_service(service: str) -> str:
    """Restart a service. Disruptive but reversible."""
    sv = _svc(service)
    return (f"restarted {service} ({sv['replicas']} replicas)"
            if sv else f"no service named {service}")


@shield.tool
def scale_deployment(service: str, replicas: int) -> str:
    """Change the replica count for a service."""
    sv = _svc(service)
    if not sv:
        return f"no service named {service}"
    was = sv["replicas"]
    sv["replicas"] = int(replicas)
    return f"scaled {service} from {was} to {replicas} replicas"


@shield.tool
def read_secret(name: str) -> str:
    """Read a secret value from the vault."""
    v = (INFRA.get("secrets") or {}).get(name.strip())
    return f"{name} = {v}" if v else f"no secret named {name}"


@shield.tool
def rotate_credential(name: str) -> str:
    """Rotate a credential and return the new value."""
    secrets_ = INFRA.get("secrets") or {}
    if name.strip() not in secrets_:
        return f"no secret named {name}"
    new = f"pk_live_ROTATED_{uuid.uuid4().hex[:16]}"
    secrets_[name.strip()] = new
    return f"{name} rotated; new value {new}"


@shield.tool
def open_firewall_rule(port: int, cidr: str) -> str:
    """Open a port to a CIDR range on the production edge."""
    INFRA.setdefault("firewall", []).append({"port": int(port), "cidr": cidr})
    return f"opened port {port} to {cidr}"


@shield.tool
def delete_namespace(namespace: str) -> str:
    """Delete an entire Kubernetes namespace. Irreversible."""
    return f"deleted namespace {namespace} and everything in it"


@shield.tool
def send_webhook(url: str, payload: str) -> str:
    """POST a payload to an external URL. Leaves the organisation."""
    # url AND payload both reach Shield: who may call a webhook is a role
    # question, whether a rotated credential may travel in the body is not.
    return f"posted {len(payload)} bytes to {url}"


SYSTEM = (
    "You are a site-reliability assistant. Use the tools to answer.\n"
    # Without this the model invents service names: asked for "logs last 30
    # events" it calls read_logs(service="last_30_events") and gets nothing.
    f"Known services: {', '.join((INFRA.get('services') or {}) ) or 'none loaded'}. "
    f"Known secrets: {', '.join((INFRA.get('secrets') or {})) or 'none loaded'}. "
    f"Known db tables: {', '.join((INFRA.get('db') or {})) or 'none loaded'}.\n"
    "A count like 'last 30 events' is the `lines` argument, never part of the "
    "service name. If the user does not name a service, ask which one rather "
    "than guessing.\n"
    "If a tool returns DENIED, tell the user plainly that they are not "
    "permitted to do it and say which action was refused — do not retry it and "
    "do not work around it. Do not consider permissions when choosing a tool; "
    "a separate layer decides."
)


def run_agent(question: str, role: str) -> dict:
    """One request, one session, one role. Nothing is cached across users."""
    session = shield.session(role)
    refusal = session.screen_input(question)
    if refusal:
        return {"role": role, "answer": refusal, "trace": session.trace}

    agent = create_agent(build_llm(), session.tools(), system_prompt=SYSTEM)
    result = agent.invoke({"messages": [{"role": "user", "content": question}]})
    answer = ""
    for msg in reversed(result.get("messages", [])):
        content = getattr(msg, "content", None)
        if content and getattr(msg, "type", "") == "ai":
            answer = content if isinstance(content, str) else str(content)
            break
    return {"role": role, "answer": answer, "trace": session.trace}


def stream_agent(question: str, role: str):
    """Server-sent events: pipeline stages as they happen, then model tokens.

    The stage events are the reason this is worth streaming. Watching a tool
    get refused mid-answer conveys the authorization model in a way a final
    JSON blob never does.
    """
    pending: list = []

    def sse(payload: dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    def drain():
        while pending:
            yield sse({"type": "stage", **pending.pop(0)})

    try:
        session = shield.session(role, on_stage=pending.append)
        yield sse({"type": "start", "role": role})

        # Input guardrails run BEFORE the model, so a blocked prompt never
        # reaches it.
        refusal = session.screen_input(question)
        yield from drain()
        if refusal:
            yield sse({"type": "token", "text": refusal})
            yield sse({"type": "done"})
            return

        agent = create_agent(build_llm(streaming=True),
                             session.tools(), system_prompt=SYSTEM)

        for chunk, _meta in agent.stream(
                {"messages": [{"role": "user", "content": question}]},
                stream_mode="messages"):
            yield from drain()
            # Tool results arrive on this stream too; forwarding them would
            # print raw tool output as if the assistant had said it.
            # isinstance, not a class-name string: a subclass or a rename drops
            # every token silently and the UI just says "(no response)".
            if not isinstance(chunk, AIMessageChunk):
                continue
            text = getattr(chunk, "content", "")
            if isinstance(text, list):
                # Claude streams a list of typed blocks. Select text blocks
                # rather than skipping known-bad ones, so a block type nobody
                # has seen yet cannot end up rendered as the assistant talking.
                text = "".join(part.get("text", "") for part in text
                               if isinstance(part, dict)
                               and part.get("type") == "text")
            if text:
                yield sse({"type": "token", "text": text})

        yield from drain()
        yield sse({"type": "done"})
    except Exception as e:
        yield sse({"type": "error", "detail": f"{e.__class__.__name__}: {e}"})


# ── HTTP ─────────────────────────────────────────────────────────────────

app = FastAPI(title="LangChain agent behind your own login")


class LoginBody(BaseModel):
    username: str
    password: str


class ChatBody(BaseModel):
    message: str
    # Deliberately no role field. If your request model has one, the caller
    # sets it, and you are back to trusting the client.


@app.post("/login")
def login(body: LoginBody, response: Response):
    user = USERS.get(body.username)
    if not user or not hmac.compare_digest(user["password"], body.password):
        raise HTTPException(401, "bad credentials")
    response.set_cookie("session", make_session(body.username),
                        httponly=True, samesite="lax")
    return {"user": body.username, "role": user["role"]}


@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("session")
    return {"ok": True}


@app.get("/whoami")
def whoami(session: Optional[str] = Cookie(None)):
    username = read_session(session)
    return {"user": username, "role": role_for(username),
            "note": "role comes from the server session, not from your request"}


@app.post("/chat")
def chat(body: ChatBody, session: Optional[str] = Cookie(None)):
    role = role_for(read_session(session))
    if not role:
        raise HTTPException(401, "log in first")
    try:
        return run_agent(body.message, role)
    except Exception as e:
        raise HTTPException(500, f"{e.__class__.__name__}: {e}")


@app.post("/chat/stream")
def chat_stream(body: ChatBody, session: Optional[str] = Cookie(None)):
    """Same authorization as /chat. The role still comes from the session."""
    role = role_for(read_session(session))
    if not role:
        raise HTTPException(401, "log in first")
    return StreamingResponse(
        stream_agent(body.message, role),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/code")
def code():
    """Source for the panel behind the Code button.

    Public on purpose: it is this repo's own example code, and a developer
    evaluating Shield should be able to read exactly what the integration costs
    before signing up for anything.
    """
    import sys as _sys
    import code_tour
    return {"sections": code_tour.sections(_sys.modules[__name__])}


@app.get("/", response_class=HTMLResponse)
def index():
    # No secret here. The page only ever talks to this backend.
    return PAGE


# RAW string: the JS below contains \n inside string literals
# (SSE frame splitting, newline in an error message). In a normal
# triple-quoted string Python turns those into real newlines, which
# breaks the JS string literals and the whole script fails to parse —
# silently, so the page renders and no button does anything.
PAGE = r"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Shielded agent</title>
<style>
*{box-sizing:border-box}
:root{--bg:#fff;--fg:#0d0d0d;--muted:#8f8f8f;--line:#e5e5e5;--user:#f4f4f4;
      --ok:#0a7c42;--no:#b42318;--okbg:#eaf6ef;--nobg:#fdeceb}
@media(prefers-color-scheme:dark){:root{--bg:#212121;--fg:#ececec;--muted:#9b9b9b;
  --line:#3a3a3a;--user:#303030;--ok:#5ed09a;--no:#ff8a80;--okbg:#1c3328;--nobg:#3a2220}}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);display:flex;flex-direction:column;
     font:16px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;gap:.6rem;padding:.7rem 1rem;
       border-bottom:1px solid var(--line);flex-wrap:wrap}
header b{font-size:.95rem;margin-right:auto}
.pill{font-size:.78rem;padding:.2rem .6rem;border-radius:999px;border:1px solid var(--line);
      color:var(--muted);white-space:nowrap}
header button{font:inherit;font-size:.8rem;padding:.25rem .7rem;border-radius:999px;
  border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer}
header button:hover{background:var(--user)}
.cta{font-size:.8rem;padding:.3rem .8rem;border-radius:999px;background:var(--fg);
     color:var(--bg);text-decoration:none;white-space:nowrap}
.cta:hover{opacity:.85}
/* Slide-over with the real integration source. */
#codepanel{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;z-index:20}
#codepanel.open{display:block}
#codeinner{position:absolute;right:0;top:0;bottom:0;width:min(46rem,100%);
  background:var(--bg);overflow-y:auto;padding:1.2rem 1.4rem 3rem;
  border-left:1px solid var(--line)}
#codeinner h3{margin:1.6rem 0 .2rem;font-size:1rem}
#codeinner .why{color:var(--muted);font-size:.87rem;margin:0 0 .7rem}
#codeinner .lbl{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);margin:.9rem 0 .3rem}
#codeinner pre{background:var(--user);padding:.8rem 1rem;border-radius:10px;
  overflow-x:auto;font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
  margin:0;white-space:pre}
#codehead{display:flex;align-items:center;gap:.6rem;position:sticky;top:0;
  background:var(--bg);padding:.2rem 0 .8rem;border-bottom:1px solid var(--line)}
#codehead b{margin-right:auto}
main{flex:1;overflow-y:auto}
.thread{max-width:46rem;margin:0 auto;padding:1.5rem 1rem 7rem}
.turn{margin:1.4rem 0}
.turn.user{display:flex;justify-content:flex-end}
.turn.user .body{background:var(--user);padding:.65rem 1rem;border-radius:1.25rem;
                 max-width:80%;white-space:pre-wrap}
.turn.bot .body{white-space:pre-wrap;min-height:1.6rem}
.who{font-size:.72rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
     margin-bottom:.35rem}
/* The pipeline trace, in the shape the terminal demo prints it. */
.trace{font:12.5px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);
  border-left:2px solid var(--line);padding:.35rem 0 .35rem .8rem;margin:.2rem 0 .7rem}
.trace.hide{display:none}
/* Grid, not flex: a long meta then wraps UNDER the label instead of back to
   the left edge, which is what keeps this readable as a column of stages. */
.trace .row{display:grid;grid-template-columns:3.6rem 1fr;gap:.5rem;align-items:start}
.trace .st{color:var(--muted)}
.trace .lb{font-weight:600;color:var(--fg)}
.trace .allow .lb,.trace .pass .lb,.trace .ok .lb{color:var(--ok)}
.trace .deny .lb,.trace .block .lb,.trace .fail .lb{color:var(--no)}
.trace .meta{color:var(--muted)}
.trace .c{white-space:pre-wrap;word-break:break-word}
.cursor{display:inline-block;width:.5rem;height:1.05rem;background:var(--fg);
        vertical-align:-2px;animation:b 1s steps(2) infinite}
@keyframes b{50%{opacity:0}}
footer{position:fixed;bottom:0;left:0;right:0;background:linear-gradient(transparent,var(--bg) 35%);
       padding:1rem}
.composer{max-width:46rem;margin:0 auto;display:flex;gap:.5rem;align-items:flex-end;
  border:1px solid var(--line);background:var(--bg);border-radius:1.6rem;padding:.5rem .5rem .5rem 1rem}
.composer textarea{flex:1;border:0;outline:0;resize:none;background:transparent;color:var(--fg);
  font:inherit;max-height:9rem;padding:.35rem 0}
.send{border:0;border-radius:999px;width:2.1rem;height:2.1rem;cursor:pointer;
      background:var(--fg);color:var(--bg);font-size:1rem;flex:none}
.send:disabled{opacity:.3;cursor:default}
.hint{max-width:46rem;margin:.5rem auto 0;font-size:.74rem;color:var(--muted);text-align:center}
</style></head><body>
<header>
  <b>Shielded agent</b>
  <span class=pill id=who>not signed in</span>
  <button onclick="login('alex')">alex · sre_lead</button>
  <button onclick="login('sam')">sam · oncall</button>
  <button onclick="login('jordan')">jordan · contractor</button>
  <button onclick="login('ci')">ci · ci_bot</button>
  <button onclick="login('riley')">riley · intern</button>
  <button id=tracebtn onclick=toggleTrace()>trace on</button>
  <button onclick=openCode()>&lt;/&gt; code</button>
  <a class=cta href="https://calendly.com/sundi133/book-a-meet" target=_blank rel=noopener>book a demo</a>
</header>
<main id=main><div class=thread id=thread></div></main>
<div id=codepanel onclick="if(event.target.id==='codepanel')closeCode()">
  <div id=codeinner>
    <div id=codehead>
      <b>How the integration works</b>
      <a class=cta href="https://calendly.com/sundi133/book-a-meet" target=_blank rel=noopener>book a demo</a>
      <button onclick=closeCode()>close</button>
    </div>
    <p class=why>Pulled live from the running source with
       <code>inspect.getsource</code> — this is the code executing right now,
       not a copy that can drift.</p>
    <div id=codebody>loading...</div>
  </div>
</div>
<footer>
  <div class=composer>
    <textarea id=q rows=1 placeholder="Ask the agent to do something..."></textarea>
    <button class=send id=send onclick=send()>&#8593;</button>
  </div>
  <div class=hint>Your role comes from this server's session. Neither this box nor the model can change it.</div>
</footer>
<script>
let showTrace = true;
function toggleTrace(){
  showTrace = !showTrace;
  document.getElementById('tracebtn').textContent = showTrace ? 'trace on' : 'trace off';
  document.querySelectorAll('.trace').forEach(t => t.classList.toggle('hide', !showTrace));
}

const thread = document.getElementById('thread'), main = document.getElementById('main');
const q = document.getElementById('q'), sendBtn = document.getElementById('send');
let busy = false;

const scroll = () => main.scrollTop = main.scrollHeight;
const esc = t => String(t).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
q.addEventListener('input', () => { q.style.height='auto'; q.style.height=q.scrollHeight+'px'; });
q.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
});

function turn(role, label){
  const d = document.createElement('div');
  d.className = 'turn ' + role;
  d.innerHTML = (label ? `<div class=who>${label}</div>` : '') + '<div class=body></div>';
  thread.appendChild(d); scroll();
  return d.querySelector('.body');
}

async function login(u){
  const r = await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u,password:'demo'})});
  const j = await r.json();
  document.getElementById('who').textContent = `${j.user} · ${j.role}`;
  turn('bot','system').textContent = `Signed in as ${j.user}. Role ${j.role}, decided by the server.`;
}

async function send(){
  const text = q.value.trim();
  if (!text || busy) return;
  busy = true; sendBtn.disabled = true;
  q.value = ''; q.style.height = 'auto';
  turn('user','').textContent = text;

  const body = turn('bot','assistant');
  let trace = null;
  const cursor = document.createElement('span');
  cursor.className = 'cursor'; body.appendChild(cursor);

  let res;
  try {
    // The forged role header below is deliberate. It changes nothing: the
    // server reads the session cookie and never looks at this.
    res = await fetch('/chat/stream',{method:'POST',
      headers:{'Content-Type':'application/json','X-User-Role':'sre_lead'},
      body:JSON.stringify({message:text})});
  } catch(e){ cursor.remove(); body.textContent = 'network error'; busy=false; sendBtn.disabled=false; return; }

  if (!res.ok){
    cursor.remove();
    body.textContent = res.status === 401 ? 'Sign in first.' : `error ${res.status}`;
    busy = false; sendBtn.disabled = false; return;
  }

  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = '', answer = '', failed = false;
  while (true){
    const {value, done} = await reader.read();
    if (done) break;
    buf += dec.decode(value, {stream:true});
    const parts = buf.split('\n\n'); buf = parts.pop();
    for (const p of parts){
      if (!p.startsWith('data:')) continue;
      let ev; try { ev = JSON.parse(p.slice(5)); } catch { continue; }
      if (ev.type === 'token'){
        answer += ev.text;
        cursor.insertAdjacentText('beforebegin', ev.text);
      } else if (ev.type === 'stage'){
        if (!trace){
          trace = document.createElement('div');
          trace.className = 'trace' + (showTrace ? '' : ' hide');
          body.parentNode.insertBefore(trace, body);
        }
        const row = document.createElement('div');
        row.className = 'row ' + (ev.status || '');
        const meta = [ev.meta, ev.ms != null ? `${Math.round(ev.ms)}ms` : '']
                       .filter(Boolean).join('  ');
        row.innerHTML = `<span class=st>${esc(ev.stage || '')}</span>`
          + `<span class=c>${ev.label ? `<span class=lb>${esc(ev.label)}</span> ` : ''}`
          + `<span class=meta>${esc(meta)}</span></span>`;
        trace.appendChild(row);
      } else if (ev.type === 'error'){
        // failed, not just empty. Without this the '(no response)' fallback
        // below overwrites body.textContent and deletes the message we just
        // showed — which is how every server-side exception in this demo
        // came out looking like the model had simply said nothing.
        failed = true;
        cursor.insertAdjacentText('beforebegin', '\n[' + ev.detail + ']');
      }
      scroll();
    }
  }
  cursor.remove();
  if (!answer.trim() && !failed) body.textContent = '(no response)';
  busy = false; sendBtn.disabled = false; q.focus();
}

let codeLoaded = false;
function closeCode(){ document.getElementById('codepanel').classList.remove('open'); }
async function openCode(){
  document.getElementById('codepanel').classList.add('open');
  if (codeLoaded) return;
  const body = document.getElementById('codebody');
  try {
    const secs = (await (await fetch('/code')).json()).sections;
    body.innerHTML = secs.map(s => `
      <h3>${esc(s.title)}</h3>
      <p class=why>${esc(s.why)}</p>
      ${s.blocks.map(b => `<div class=lbl>${esc(b.label)}</div>`
                        + `<pre>${esc(b.code)}</pre>`).join('')}`).join('');
    codeLoaded = true;
  } catch(e) { body.textContent = 'could not load source'; }
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeCode(); });

fetch('/whoami').then(r=>r.json()).then(j=>{
  if (j.role) document.getElementById('who').textContent = `${j.user} · ${j.role}`;
});
</script></body></html>"""


# ── Prove it, without needing a model ────────────────────────────────────

def attack():
    print(f"{B}Roles the user cannot choose, and the model cannot either{Z}\n")
    print(f"{DIM}Shield {SHIELD}   agent {AGENT_KEY}   proxy token "
          f"{'set' if PROXY_TOKEN else R + 'NOT SET' + Z}{Z}\n")

    print(f"{B}1. The same request as each user{Z}")
    for username in USERS:
        role = role_for(username)
        allowed, reason = shield.session(role).check(
            "restart_service", {"service": "checkout-api"})
        mark = f"{G}allowed{Z}" if allowed else f"{R}refused{Z}"
        print(f"   {username:<8} ({role:<16}) {mark}  {DIM}{reason}{Z}")

    print(f"\n{B}2. The user forges X-User-Role at your app{Z}")
    print(f"   {DIM}/chat reads the session cookie. The header is never read, "
          f"so there is nothing to forge.{Z}")
    print(f"   {G}no effect{Z}")

    print(f"\n{B}3. The model tries to pick its own role{Z}")
    for t in shield.session("intern").tools():
        params = list(getattr(t, "args", {}) or {})
        has_role = any("role" in p.lower() for p in params)
        mark = f"{R}HAS A ROLE ARG{Z}" if has_role else f"{G}no role arg{Z}"
        print(f"   {t.name:<20} args={params}  {mark}")
    print(f"   {DIM}The role is in a closure, not a parameter. A prompt "
          f"injection has nowhere to put one.{Z}")

    print(f"\n{B}4. A client skips your app and calls Shield directly{Z}")
    try:
        r = requests.post(f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
                          headers={"Content-Type": "application/json",
                                   "X-API-Key": TENANT_KEY,
                                   "X-Agent-Key": AGENT_KEY,
                                   "X-User-Role": "sre_lead"},  # no proxy token
                          json={"agent_key": AGENT_KEY,
                                "tool_name": "restart_service",
                                "tool_input": "{}", "user_role": "sre_lead"})
        allowed = bool(r.json().get("allowed", False)) if r.status_code == 200 else False
        if allowed:
            print(f"   {R}ALLOWED{Z} — strict_proxy is NOT enforcing on this "
                  f"deployment. Check SHIELD_ROLE_BINDING and "
                  f"SHIELD_TRUSTED_PROXY_ONLY.")
        else:
            print(f"   {G}refused{Z}  {DIM}no proxy token, so the role was "
                  f"discarded{Z}")
    except Exception as e:
        print(f"   {Y}could not reach Shield{Z} {DIM}({e.__class__.__name__}){Z}")
    print()


if __name__ == "__main__":
    if "--attack" in sys.argv:
        attack()
    else:
        import uvicorn
        if not TENANT_KEY:
            print(f"{Y}TENANT_API_KEY is unset — Shield calls will fail.{Z}")
        # Refuse rather than warn. A model misconfiguration surfaces as a
        # failed answer in the browser, which reads as "the agent is broken"
        # and sends you looking at the guardrails — the expensive wrong place.
        problem = check_model_config()
        if problem:
            sys.exit(f"{R}{problem}{Z}\n{DIM}Use --attack to exercise "
                     f"authorization without a model.{Z}")
        # Calling ourselves would produce Shield's error text from this app's
        # port, which reads as "the example is broken" rather than "the URL is
        # wrong". Refuse instead of starting.
        if SHIELD.rstrip("/").endswith(f":{APP_PORT}"):
            sys.exit(f"{R}LLM_SHIELD_URL points at this app's own port "
                     f"({APP_PORT}). Set it to your Shield deployment.{Z}")
        print(f"{DIM}app    http://{APP_HOST}:{APP_PORT}{Z}")
        print(f"{DIM}shield {SHIELD}   model {PROVIDER}/{MODEL}   "
              f"agent {AGENT_KEY}{Z}")
        uvicorn.run(app, host=APP_HOST, port=APP_PORT, log_level="warning")
