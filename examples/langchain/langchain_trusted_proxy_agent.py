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
    export OPENAI_API_KEY=sk-...              # the agent needs a model
    export DEMO_MODEL=gpt-4.1-mini            # optional

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
from typing import Optional

import requests
from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

SHIELD = os.getenv("LLM_SHIELD_URL", "http://localhost:8000").rstrip("/")

# NOT 8000. That is Shield's own default port and the default LLM_SHIELD_URL
# above, so binding there means this app either collides with a local Shield or
# calls itself. Both fail in confusing ways: you get Shield's auth error in the
# browser and assume this app is broken.
APP_PORT = int(os.getenv("APP_PORT", "8500"))
TENANT_KEY = os.getenv("TENANT_API_KEY", "")
AGENT_KEY = os.getenv("SHIELD_AGENT_KEY") or os.getenv("AGENT_ID") or "sre-agent"
MODEL = os.getenv("DEMO_MODEL", "gpt-4.1-mini")

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
USERS = {
    "alex":   {"password": "demo", "role": "sre_lead"},
    "sam":    {"password": "demo", "role": "oncall_engineer"},
    "jordan": {"password": "demo", "role": "contractor"},
    "riley":  {"password": "demo", "role": "intern"},
}

# Pretend infrastructure the tools act on.
SERVICES = {
    "checkout-api": {"replicas": 3, "logs": ["200 GET /健", "500 POST /pay"]},
    "auth-api": {"replicas": 2, "logs": ["200 GET /token"]},
}


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

def shield_headers(role: str) -> dict:
    """X-User-Role says what we assert; X-Shield-Proxy-Token says why Shield
    should believe us. Without the second, strict_proxy discards the first."""
    headers = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY,
               "X-Agent-Key": AGENT_KEY}
    if role:
        headers["X-User-Role"] = role
    if PROXY_TOKEN:
        headers["X-Shield-Proxy-Token"] = PROXY_TOKEN
    return headers


def shield_allows(tool_name: str, role: str, params: dict) -> tuple:
    """(allowed, reason). Fail closed — a check you could not perform is not a
    check that passed."""
    try:
        r = requests.post(f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
                          headers=shield_headers(role),
                          json={"agent_key": AGENT_KEY, "tool_name": tool_name,
                                "tool_input": json.dumps(params),
                                "user_role": role})
    except Exception as e:
        return False, f"Shield unreachable ({e.__class__.__name__})"
    if r.status_code != 200:
        return False, f"Shield returned {r.status_code}"
    body = r.json()
    allowed = bool(body.get("allowed", False))
    return allowed, (body.get("reason") or body.get("message")
                     or ("allowed" if allowed else "denied by policy"))


# ── The LangChain tools ──────────────────────────────────────────────────
#
# Built per request, closed over the role. This is the structural part: the
# model can pick a tool, and it has no way to express a different role.

def build_tools(role: str, trace: list):
    from langchain_core.tools import tool

    def guarded(tool_name: str, params: dict, run):
        allowed, reason = shield_allows(tool_name, role, params)
        trace.append({"tool": tool_name, "role": role,
                      "allowed": allowed, "reason": reason})
        if not allowed:
            # Return the refusal to the MODEL rather than raising. The agent
            # then explains it to the user instead of the request 500ing, and
            # a refusal it can read is a refusal it can relay accurately.
            return f"DENIED by Shield: {reason}"
        return run()

    @tool
    def read_logs(service: str) -> str:
        """Read recent log lines for a service. Read-only."""
        def run():
            s = SERVICES.get(service)
            return "\n".join(s["logs"]) if s else f"no service named {service}"
        return guarded("read_logs", {"service": service}, run)

    @tool
    def restart_service(service: str) -> str:
        """Restart a service. Disruptive but reversible."""
        def run():
            s = SERVICES.get(service)
            return (f"restarted {service} ({s['replicas']} replicas)"
                    if s else f"no service named {service}")
        return guarded("restart_service", {"service": service}, run)

    @tool
    def rotate_secret(name: str) -> str:
        """Rotate a production secret. Destructive."""
        def run():
            return f"rotated secret {name}"
        return guarded("rotate_secret", {"name": name}, run)

    # Every signature above takes only what the WORK needs. None takes a role.
    return [read_logs, restart_service, rotate_secret]


SYSTEM = (
    "You are an SRE assistant. Use the tools to answer. "
    "If a tool returns a line starting with 'DENIED by Shield', tell the user "
    "plainly that they are not authorized for that action and do not retry it."
)


def run_agent(question: str, role: str) -> dict:
    """One request, one agent, one role. Nothing is cached across users."""
    from langchain.agents import create_agent
    from langchain_openai import ChatOpenAI

    trace: list = []
    agent = create_agent(
        ChatOpenAI(model=MODEL, temperature=0),
        build_tools(role, trace),
        system_prompt=SYSTEM,
    )
    result = agent.invoke({"messages": [{"role": "user", "content": question}]})
    messages = result.get("messages", [])
    answer = ""
    for msg in reversed(messages):
        content = getattr(msg, "content", None)
        if content and getattr(msg, "type", "") == "ai":
            answer = content if isinstance(content, str) else str(content)
            break
    return {"role": role, "answer": answer, "shield_decisions": trace}


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


@app.get("/", response_class=HTMLResponse)
def index():
    # No secret here. The page only ever talks to this backend.
    return """<!doctype html><meta charset=utf-8><title>Shielded LangChain agent</title>
<style>body{font-family:system-ui;max-width:48rem;margin:3rem auto;padding:0 1rem}
button{padding:.4rem .8rem;margin:.2rem}input{width:60%;padding:.4rem}
pre{background:#f4f4f5;padding:1rem;border-radius:8px;white-space:pre-wrap}</style>
<h2>LangChain agent, role enforced by Shield</h2>
<p>Log in, then ask. The role comes from this server's session — the box below
cannot change it, and neither can the model.</p>
<div>
  <button onclick="login('alex')">alex (sre_lead)</button>
  <button onclick="login('riley')">riley (intern)</button>
  <button onclick="fetch('/whoami').then(r=>r.json()).then(show)">whoami</button>
</div>
<p><input id=q value="restart checkout-api"> <button onclick="ask()">ask</button></p>
<pre id=out>...</pre>
<script>
const out = document.getElementById('out');
const show = o => out.textContent = JSON.stringify(o, null, 2);
async function login(u){
  show(await (await fetch('/login',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u,password:'demo'})})).json());
}
async function ask(){
  out.textContent = 'thinking...';
  // The forged header below changes nothing — the server never reads it.
  show(await (await fetch('/chat',{method:'POST',
    headers:{'Content-Type':'application/json','X-User-Role':'sre_lead'},
    body:JSON.stringify({message:document.getElementById('q').value})})).json());
}
</script>"""


# ── Prove it, without needing a model ────────────────────────────────────

def attack():
    print(f"{B}Roles the user cannot choose, and the model cannot either{Z}\n")
    print(f"{DIM}Shield {SHIELD}   agent {AGENT_KEY}   proxy token "
          f"{'set' if PROXY_TOKEN else R + 'NOT SET' + Z}{Z}\n")

    print(f"{B}1. The same request as two different users{Z}")
    for username in ("riley", "alex"):
        role = role_for(username)
        allowed, reason = shield_allows("restart_service", role,
                                        {"service": "checkout-api"})
        mark = f"{G}allowed{Z}" if allowed else f"{R}refused{Z}"
        print(f"   {username:<8} ({role:<16}) {mark}  {DIM}{reason}{Z}")

    print(f"\n{B}2. The user forges X-User-Role at your app{Z}")
    print(f"   {DIM}/chat reads the session cookie. The header is never read, "
          f"so there is nothing to forge.{Z}")
    print(f"   {G}no effect{Z}")

    print(f"\n{B}3. The model tries to pick its own role{Z}")
    from inspect import signature
    tools = build_tools("intern", [])
    for t in tools:
        params = list(getattr(t, "args", {}) or {})
        has_role = any("role" in p.lower() for p in params)
        mark = f"{R}HAS A ROLE ARG{Z}" if has_role else f"{G}no role arg{Z}"
        print(f"   {t.name:<18} args={params}  {mark}")
    print(f"   {DIM}The role is in a closure, not a parameter. A prompt "
          f"injection has nowhere to put one.{Z}")

    print(f"\n{B}4. A client skips your app and calls Shield directly{Z}")
    try:
        r = requests.post(f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
                          headers={"Content-Type": "application/json",
                                   "X-API-Key": TENANT_KEY,
                                   "X-Agent-Key": AGENT_KEY,
                                   "X-User-Role": "sre_lead"},
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
        if not os.getenv("OPENAI_API_KEY"):
            print(f"{Y}OPENAI_API_KEY is unset — /chat will 500. "
                  f"Use --attack to exercise authorization without a model.{Z}")
        # Calling ourselves would produce Shield's error text from this app's
        # port, which reads as "the example is broken" rather than "the URL is
        # wrong". Refuse instead of starting.
        if SHIELD.rstrip("/").endswith(f":{APP_PORT}"):
            sys.exit(f"{R}LLM_SHIELD_URL points at this app's own port "
                     f"({APP_PORT}). Set it to your Shield deployment.{Z}")
        print(f"{DIM}app    http://localhost:{APP_PORT}{Z}")
        print(f"{DIM}shield {SHIELD}   model {MODEL}   agent {AGENT_KEY}{Z}")
        uvicorn.run(app, host="127.0.0.1", port=APP_PORT, log_level="warning")
