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
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

# The tools are declared inside build_tools() rather than here at module level,
# and that is the security design, not an accident. A module-level @tool is
# shared by every request, so the role would have to travel as a tool ARGUMENT
# — which hands the choice of role to the model. Building them per request lets
# each one close over the role from the session instead. See build_tools().

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


def stream_agent(question: str, role: str):
    """Server-sent events: tokens as the model produces them, and every Shield
    decision the moment it is made.

    The Shield events are the reason this is worth streaming at all. A user
    watching a tool get refused mid-answer understands the authorization model
    in a way a final JSON blob never conveys.

    `trace` is appended by guarded() on the same thread, so draining it between
    chunks emits decisions in the order they actually happened.
    """
    trace: list = []
    sent = 0

    def sse(payload: dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    try:
        agent = create_agent(
            ChatOpenAI(model=MODEL, temperature=0, streaming=True),
            build_tools(role, trace),
            system_prompt=SYSTEM,
        )
        yield sse({"type": "start", "role": role})

        for chunk, _meta in agent.stream(
                {"messages": [{"role": "user", "content": question}]},
                stream_mode="messages"):

            while sent < len(trace):                 # decisions made so far
                yield sse({"type": "shield", **trace[sent]})
                sent += 1

            # Tool results arrive on this stream too; only forward the model's
            # own words, or the transcript shows raw tool output as if the
            # assistant had said it.
            if getattr(chunk, "type", "") != "AIMessageChunk" and \
                    chunk.__class__.__name__ != "AIMessageChunk":
                continue
            text = getattr(chunk, "content", "")
            if isinstance(text, list):               # some providers chunk parts
                text = "".join(part.get("text", "") for part in text
                               if isinstance(part, dict))
            if text:
                yield sse({"type": "token", "text": text})

        while sent < len(trace):
            yield sse({"type": "shield", **trace[sent]})
            sent += 1
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
main{flex:1;overflow-y:auto}
.thread{max-width:46rem;margin:0 auto;padding:1.5rem 1rem 7rem}
.turn{margin:1.4rem 0}
.turn.user{display:flex;justify-content:flex-end}
.turn.user .body{background:var(--user);padding:.65rem 1rem;border-radius:1.25rem;
                 max-width:80%;white-space:pre-wrap}
.turn.bot .body{white-space:pre-wrap;min-height:1.6rem}
.who{font-size:.72rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
     margin-bottom:.35rem}
.chip{display:flex;width:fit-content;align-items:center;gap:.4rem;font-size:.78rem;
      padding:.25rem .6rem;border-radius:.6rem;margin:.15rem 0 .5rem;border:1px solid transparent}
.chip.ok{background:var(--okbg);color:var(--ok);border-color:var(--ok)}
.chip.no{background:var(--nobg);color:var(--no);border-color:var(--no)}
.chip code{font:inherit;font-weight:600}
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
  <button onclick="login('riley')">riley · intern</button>
</header>
<main id=main><div class=thread id=thread></div></main>
<footer>
  <div class=composer>
    <textarea id=q rows=1 placeholder="Ask the agent to do something..."></textarea>
    <button class=send id=send onclick=send()>&#8593;</button>
  </div>
  <div class=hint>Your role comes from this server's session. Neither this box nor the model can change it.</div>
</footer>
<script>
const thread = document.getElementById('thread'), main = document.getElementById('main');
const q = document.getElementById('q'), sendBtn = document.getElementById('send');
let busy = false;

const scroll = () => main.scrollTop = main.scrollHeight;
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
  let buf = '', answer = '';
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
      } else if (ev.type === 'shield'){
        const chip = document.createElement('span');
        chip.className = 'chip ' + (ev.allowed ? 'ok' : 'no');
        chip.innerHTML = `${ev.allowed ? '&#10003;' : '&#10007;'} <code>${ev.tool}</code> `
                       + `<span>${ev.allowed ? 'allowed' : 'denied'} for ${ev.role}</span>`;
        chip.title = ev.reason || '';
        cursor.insertAdjacentElement('beforebegin', chip);
      } else if (ev.type === 'error'){
        cursor.insertAdjacentText('beforebegin', '\n[' + ev.detail + ']');
      }
      scroll();
    }
  }
  cursor.remove();
  if (!answer.trim() && !body.querySelector('.chip')) body.textContent = '(no response)';
  busy = false; sendBtn.disabled = false; q.focus();
}

fetch('/whoami').then(r=>r.json()).then(j=>{
  if (j.role) document.getElementById('who').textContent = `${j.user} · ${j.role}`;
});
</script></body></html>"""


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
