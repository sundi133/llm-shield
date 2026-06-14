#!/usr/bin/env python3
"""End-to-end test for Shield MCP integration against a live deployment.

Tests, in order:
  0. Deploy readiness   — /health is up and the new /v1/openapi/* endpoints exist
  C. Shield's MCP tools — POST /mcp/message tools/list returns the shield_* tools
  A. Generated server   — register agent -> generate a governed MCP server -> run
                          it over HTTP -> drive it with a real MCP client; a
                          reader is blocked on a write tool, an admin is allowed
  B. votal SDK          — check_tool allow/deny (skipped if `votal` not installed)

Usage:
    pip install requests mcp httpx pydantic uvicorn        # + `votal` for Path B
    SHIELD_URL=https://shield.votal.ai \\
    SHIELD_API_KEY=tenant-...your-key... \\
    python mcp_e2e_test.py

Exit code 0 if every (non-skipped) check passes, else 1.
"""

import asyncio
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

SHIELD = os.environ.get("SHIELD_URL", "https://shield.votal.ai").rstrip("/")
KEY = os.environ.get("SHIELD_API_KEY", "")
PORT = int(os.environ.get("E2E_PORT", "8390"))
AGENT = "e2e-" + uuid.uuid4().hex[:8]            # fresh id avoids 409 on re-register
H = {"X-API-Key": KEY, "Content-Type": "application/json"}

SPEC = {
    "openapi": "3.0.0", "info": {"title": "httpbin", "version": "1.0"},
    "paths": {
        "/get": {"get": {"operationId": "get_demo",
            "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/post": {"post": {"operationId": "send_payment",
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "properties": {"amount": {"type": "number"}}}}}},
            "responses": {"200": {"description": "ok"}}}},
    },
}

_results = []


def check(ok, name, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    _results.append(bool(ok))
    return ok


def skip(name, why):
    print(f"  [SKIP] {name} — {why}")


# ── 0. readiness ──────────────────────────────────────────────────────
def step_readiness():
    print(f"\n0. Deploy readiness ({SHIELD})")
    try:
        r = requests.get(f"{SHIELD}/health", timeout=10)
        check(r.status_code == 200, "health", r.text[:50])
    except Exception as e:
        return check(False, "health", str(e))
    r = requests.get(f"{SHIELD}/v1/openapi/tools", headers=H, timeout=10)
    # 404 = old build (new endpoints not deployed); 401/200 = deployed
    return check(r.status_code != 404, "new endpoints deployed",
                 f"HTTP {r.status_code}" + (" (still old build)" if r.status_code == 404 else ""))


# ── C. Shield's own MCP guardrail tools ───────────────────────────────
def step_c():
    print("\nC. Shield's MCP guardrail tools (/mcp/message)")
    try:
        r = requests.post(f"{SHIELD}/mcp/message", headers=H,
                          json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, timeout=15)
        tools = [t["name"] for t in r.json()["result"]["tools"]]
        check("shield_check_tool" in tools, "tools/list", ", ".join(tools[:3]) + " …")
    except Exception as e:
        check(False, "tools/list", f"{e} | {getattr(r,'text','')[:80] if 'r' in dir() else ''}")


# ── A. generate → run → drive ─────────────────────────────────────────
def step_a():
    print("\nA. Generated governed MCP server")
    rr = requests.post(f"{SHIELD}/v1/agents/registry", headers=H, json={
        "agent_id": AGENT, "tools": ["get_demo", "send_payment"],
        "role_permissions": {"reader": ["get_demo"], "admin": ["get_demo", "send_payment"]}},
        timeout=15)
    if not check(rr.status_code in (200, 201), "register agent",
                 f"{AGENT} (HTTP {rr.status_code})"):
        return
    g = requests.post(f"{SHIELD}/v1/openapi/generate", headers=H, json={
        "language": "python", "style": "typed", "include_risky": True,
        "base_url": "https://httpbin.org", "spec": SPEC}, timeout=30)
    if not check(g.status_code == 200, "generate server", f"HTTP {g.status_code}"):
        print("       " + g.text[:160]); return
    files = g.json()["files"]
    d = tempfile.mkdtemp(prefix="mcp_e2e_")
    for n, c in files.items():
        p = os.path.join(d, n)
        os.makedirs(os.path.dirname(p) or d, exist_ok=True)
        open(p, "w").write(c)
    check("server.py" in files, "wrote files", f"{len(files)} files → {d}")
    _drive(os.path.join(d, "server.py"))


def _launch(server, role):
    env = dict(os.environ)
    env.update({"MCP_TRANSPORT": "http", "PORT": str(PORT), "API_BASE_URL": "https://httpbin.org",
                "SHIELD_URL": SHIELD, "SHIELD_API_KEY": KEY,
                "SHIELD_AGENT_KEY": AGENT, "SHIELD_USER_ROLE": role})
    return subprocess.Popen([sys.executable, server], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_up():
    for _ in range(40):
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1).status == 200:
                return True
        except Exception:
            time.sleep(0.5)
    return False


async def _call(tool, args):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    async with streamablehttp_client(f"http://127.0.0.1:{PORT}/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = [t.name for t in (await s.list_tools()).tools]
            res = await s.call_tool(tool, args)
            return tools, res.content[0].text


def _drive(server):
    try:
        import mcp  # noqa
    except ImportError:
        skip("drive via MCP client", "pip install mcp"); return

    p = _launch(server, "reader")
    try:
        if not check(_wait_up(), "server boots over HTTP (reader)"):
            return
        tools, pay = asyncio.run(_call("send_payment", {"amount": 9}))
        check("get_demo" in tools and "send_payment" in tools, "tools/list", ", ".join(tools))
        check("Blocked by Shield" in pay, "reader send_payment BLOCKED", pay[:60])
        _, get = asyncio.run(_call("get_demo", {"q": "hi"}))
        check("Blocked by Shield" not in get, "reader get_demo allowed", get[:40])
    finally:
        p.terminate(); p.wait()

    p = _launch(server, "admin")
    try:
        if not check(_wait_up(), "server boots over HTTP (admin)"):
            return
        _, pay = asyncio.run(_call("send_payment", {"amount": 9}))
        check("Blocked by Shield" not in pay, "admin send_payment allowed", pay[:40])
    finally:
        p.terminate(); p.wait()


# ── B. votal SDK ──────────────────────────────────────────────────────
def step_b():
    print("\nB. votal SDK")
    try:
        from votal import VotalShield
    except ImportError:
        skip("SDK check_tool", "pip install votal"); return
    s = VotalShield(shield_url=SHIELD, api_key=KEY, agent_id=AGENT, user_role="reader")
    check(s.health(), "sdk health")
    check(s.check_tool("get_demo", user_role="reader").allowed, "reader get_demo allowed")
    g = s.check_tool("send_payment", user_role="reader")
    check(not g.allowed, "reader send_payment blocked", g.reason[:50])
    check(s.check_tool("send_payment", user_role="admin").allowed, "admin send_payment allowed")


def main():
    print(f"Shield MCP end-to-end test\n  URL: {SHIELD}\n  key: {'set' if KEY else 'MISSING — most steps will 401'}")
    if not step_readiness():
        print("\nDeploy not ready (new endpoints 404 or health down). Stopping.")
        sys.exit(1)
    step_c()
    step_a()
    step_b()
    passed = sum(_results)
    total = len(_results)
    print(f"\n{'='*48}\nRESULT: {passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
