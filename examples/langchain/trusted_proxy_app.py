#!/usr/bin/env python3
"""Your app as the trusted proxy — roles without an IdP.

The shape most teams actually have: your own login, your own user table, no
Okta, and an agent that calls tools. You want Shield to enforce roles, and you
want the role to be something a user cannot pick for themselves.

    browser ──► YOUR BACKEND (this file) ──► Shield
                └ knows who is logged in     └ trusts this hop, not the browser
                └ holds the shared secret

The browser never talks to Shield and never sees the secret. Your backend
resolves the role from its own session and asserts it to Shield along with
`X-Shield-Proxy-Token`. Shield runs in `strict_proxy`, so that assertion counts
from your backend and from nowhere else.

Why this is not the same as trusting a header
---------------------------------------------
`X-User-Role` on its own is whatever the caller typed. The difference here is
*who* the caller is: a hop that proved itself with a secret the browser does
not have. A user hitting Shield directly, or hitting this backend with a forged
role header, gets nothing. Run `--attack` to watch both fail.

What this is NOT
----------------
The proxy secret proves the HOP, not the USER. Shield records
`role_source: proxy` and `role_verified: false` — vouched, not proven. If you
have an IdP, send the user's token as `X-On-Behalf-Of` instead and Shield
verifies it cryptographically. This file is the answer for teams who do not.

Setup
-----
    pip install -r requirements.txt

    export LLM_SHIELD_URL=https://api.guardrails.votal.ai
    export TENANT_API_KEY=<your tenant key>
    export SHIELD_PROXY_TOKEN=<same value as SHIELD_TRUSTED_PROXY_SECRET>
    export OPENAI_API_KEY=sk-...        # optional; without it, tools run directly

On Shield:
    SHIELD_ROLE_BINDING=strict_proxy
    SHIELD_TRUSTED_PROXY_ONLY=true
    SHIELD_TRUSTED_PROXY_SECRET=<same value>

Run
---
    python trusted_proxy_app.py              # serve on :8000, open the page
    python trusted_proxy_app.py --attack     # prove the forgeries fail
"""
# NOTE: no `from __future__ import annotations` here. It turns the Pydantic
# model annotations into strings, which FastAPI then cannot resolve unless
# the module happens to be registered under its own name in sys.modules.
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
TENANT_KEY = os.getenv("TENANT_API_KEY", "")
AGENT_KEY = os.getenv("SHIELD_AGENT_KEY", "sre-agent")

# The shared secret. Lives ONLY on the server. It is never sent to the browser,
# never in a template, never in an API response. If it reaches the client, the
# client becomes the trusted proxy and the whole control is gone.
PROXY_TOKEN = os.getenv("SHIELD_PROXY_TOKEN", "")

# Signs the session cookie. Unrelated to the Shield secret — do not reuse one
# for the other, or leaking the cookie key hands over Shield's trust too.
SESSION_KEY = os.getenv("APP_SESSION_KEY", secrets.token_urlsafe(32))

TIMEOUT = 30

G, R, Y, B, DIM, Z = ("\033[32m", "\033[31m", "\033[33m", "\033[1m",
                      "\033[2m", "\033[0m")

# ── Your user store ──────────────────────────────────────────────────────
# Stands in for whatever you already have: a users table, LDAP, a SaaS auth
# provider. The only thing that matters is that the ROLE is decided here, on
# the server, from something the user proved — not read off their request.
USERS = {
    "alex":   {"password": "demo", "role": "sre_lead"},
    "sam":    {"password": "demo", "role": "oncall_engineer"},
    "jordan": {"password": "demo", "role": "contractor"},
    "riley":  {"password": "demo", "role": "intern"},
}


# ── Sessions ─────────────────────────────────────────────────────────────

def _sign(payload: str) -> str:
    mac = hmac.new(SESSION_KEY.encode(), payload.encode(), hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")


def make_session(username: str) -> str:
    """A signed cookie. The ROLE is not in it — only the username.

    Putting the role in the cookie would mean re-issuing every session when a
    permission changes, and a stale cookie would carry stale authority. Look
    the role up per request instead; it is a dict read.
    """
    body = base64.urlsafe_b64encode(
        json.dumps({"u": username}).encode()).decode().rstrip("=")
    return f"{body}.{_sign(body)}"


def read_session(cookie: Optional[str]) -> Optional[str]:
    if not cookie or "." not in cookie:
        return None
    body, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(body)):
        return None                       # forged or tampered cookie
    try:
        pad = "=" * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(body + pad))["u"]
    except Exception:
        return None


def role_for(username: Optional[str]) -> str:
    """The single place a role is decided. Note what is NOT an input here:
    anything from the incoming request."""
    return USERS.get(username or "", {}).get("role", "")


# ── The one function that talks to Shield ────────────────────────────────

def shield_headers(role: str) -> dict:
    """Every Shield call goes out with these, and only from this process.

    Two headers do the work:
      X-User-Role            what we assert about the user
      X-Shield-Proxy-Token   why Shield should believe us

    Without the second, Shield in strict_proxy mode discards the first. That is
    the point: the header is only as good as the hop it arrived on.
    """
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": TENANT_KEY,
        "X-Agent-Key": AGENT_KEY,
    }
    if role:
        headers["X-User-Role"] = role
    if PROXY_TOKEN:
        headers["X-Shield-Proxy-Token"] = PROXY_TOKEN
    return headers


def shield_tool_check(tool_name: str, role: str, params: dict) -> tuple:
    """(allowed, reason). Ask Shield before running anything that matters."""
    try:
        r = requests.post(
            f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
            headers=shield_headers(role),
            json={"agent_key": AGENT_KEY, "tool_name": tool_name,
                  "tool_input": json.dumps(params), "user_role": role},
        )
    except Exception as e:
        # Fail closed. An authorization check you could not perform is not an
        # authorization check that passed.
        return False, f"Shield unreachable ({e.__class__.__name__})"

    if r.status_code != 200:
        return False, f"Shield returned {r.status_code}"

    body = r.json()
    allowed = bool(body.get("allowed", False))
    reason = body.get("reason") or body.get("message") or (
        "allowed" if allowed else "denied by policy")
    return allowed, reason


# ── The tools your agent can call ────────────────────────────────────────

def _restart_service(service: str) -> str:
    return f"restarted {service}"


def _read_logs(service: str) -> str:
    return f"last 30 log lines for {service}"


def _rotate_secret(name: str) -> str:
    return f"rotated secret {name}"


TOOLS = {
    "restart_service": _restart_service,
    "read_logs": _read_logs,
    "rotate_secret": _rotate_secret,
}


def run_tool(tool_name: str, role: str, **params) -> dict:
    """Check, then run. Never the other way round."""
    if tool_name not in TOOLS:
        return {"ok": False, "detail": f"no such tool: {tool_name}"}

    allowed, reason = shield_tool_check(tool_name, role, params)
    if not allowed:
        return {"ok": False, "tool": tool_name, "role": role,
                "detail": f"DENIED — {reason}"}

    return {"ok": True, "tool": tool_name, "role": role,
            "detail": TOOLS[tool_name](**params)}


# ── HTTP surface ─────────────────────────────────────────────────────────

app = FastAPI(title="Trusted-proxy example app")


class LoginBody(BaseModel):
    username: str
    password: str


class ToolBody(BaseModel):
    tool: str
    service: Optional[str] = None
    name: Optional[str] = None
    # Deliberately absent: any field naming a role. If your request model has
    # one, a caller can set it, and you are back to trusting the client.


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


@app.post("/tool")
def tool(body: ToolBody, session: Optional[str] = Cookie(None)):
    """Run a tool as whoever is logged in.

    The role is looked up from the session. Nothing the caller sends can
    influence it — not a header, not a body field, not a query param.
    """
    username = read_session(session)
    role = role_for(username)
    if not role:
        raise HTTPException(401, "log in first")

    params = {k: v for k, v in
              {"service": body.service, "name": body.name}.items() if v}
    return run_tool(body.tool, role, **params)


@app.get("/", response_class=HTMLResponse)
def index():
    # No secret here, obviously. The page only ever talks to this backend.
    return """<!doctype html><meta charset=utf-8><title>Trusted proxy demo</title>
<style>body{font-family:system-ui;max-width:46rem;margin:3rem auto;padding:0 1rem}
button{padding:.4rem .8rem;margin:.2rem}pre{background:#f4f4f5;padding:1rem;border-radius:8px;
white-space:pre-wrap}</style>
<h2>Trusted-proxy demo</h2>
<p>Log in, then run a tool. The role is decided by this server, not by you.</p>
<div>
  <button onclick="login('alex')">alex (sre_lead)</button>
  <button onclick="login('riley')">riley (intern)</button>
  <button onclick="go('restart_service')">restart checkout-api</button>
  <button onclick="go('read_logs')">read logs</button>
</div>
<pre id=out>...</pre>
<script>
const out = document.getElementById('out');
const show = o => out.textContent = JSON.stringify(o, null, 2);
async function login(u){
  const r = await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:u,password:'demo'})});
  show(await r.json());
}
async function go(tool){
  // Note the forged header. It changes nothing — the server ignores it.
  const r = await fetch('/tool',{method:'POST',
    headers:{'Content-Type':'application/json','X-User-Role':'sre_lead'},
    body:JSON.stringify({tool, service:'checkout-api'})});
  show(await r.json());
}
</script>"""


# ── Prove it ─────────────────────────────────────────────────────────────

def attack():
    """Two forgeries, both of which must fail."""
    print(f"{B}Trusted proxy — what a forged role actually achieves{Z}\n")
    print(f"{DIM}Shield {SHIELD}   proxy token "
          f"{'set' if PROXY_TOKEN else R + 'NOT SET' + Z}{Z}\n")

    if not PROXY_TOKEN:
        print(f"{Y}SHIELD_PROXY_TOKEN is unset — Shield will treat this process "
              f"as untrusted and strict_proxy will refuse the role.{Z}\n")

    print(f"{B}1. Through your app, as riley (intern){Z}")
    role = role_for("riley")
    for tool_name in ("read_logs", "restart_service"):
        res = run_tool(tool_name, role, service="checkout-api")
        mark = f"{G}allowed{Z}" if res["ok"] else f"{R}refused{Z}"
        print(f"   {tool_name:<18} {mark}  {DIM}{res['detail']}{Z}")

    print(f"\n{B}2. Client forges X-User-Role at your app{Z}")
    print(f"   {DIM}The handler reads the session, not the request. The header "
          f"is never even looked at.{Z}")
    print(f"   {G}no effect{Z} — role stays {role_for('riley')!r}")

    print(f"\n{B}3. Client skips your app and hits Shield directly{Z}")
    try:
        r = requests.post(
            f"{SHIELD}/v1/shield/tool/check", timeout=TIMEOUT,
            headers={"Content-Type": "application/json", "X-API-Key": TENANT_KEY,
                     "X-Agent-Key": AGENT_KEY, "X-User-Role": "sre_lead"},
            json={"agent_key": AGENT_KEY, "tool_name": "restart_service",
                  "tool_input": "{}", "user_role": "sre_lead"})
        body = r.json() if r.status_code == 200 else {}
        allowed = bool(body.get("allowed", False))
        if allowed:
            print(f"   {R}ALLOWED{Z} — strict_proxy is not enforcing on this "
                  f"deployment. Check SHIELD_ROLE_BINDING and "
                  f"SHIELD_TRUSTED_PROXY_ONLY.")
        else:
            print(f"   {G}refused{Z}  {DIM}no proxy token, so the role was "
                  f"discarded{Z}")
    except Exception as e:
        print(f"   {Y}could not reach Shield{Z} {DIM}({e.__class__.__name__}){Z}")

    print(f"\n{DIM}The secret never leaves this process. That is the whole "
          f"mechanism.{Z}\n")


if __name__ == "__main__":
    if "--attack" in sys.argv:
        attack()
    else:
        import uvicorn
        if not TENANT_KEY:
            print(f"{Y}TENANT_API_KEY is unset — Shield calls will fail.{Z}")
        print(f"{DIM}http://localhost:8000  ·  Shield {SHIELD}{Z}")
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
