"""Live check for an OAuth-brokered MCP route (e.g. Google Drive) before deploying.

Runs the admin plane and the MCP gateway in ONE local process with in-memory
stores and the vault on, so the real connect -> sign-in -> call -> refresh path
can be exercised on a laptop. Spec: docs/specs/mcp-oauth-standard-providers.md,
task 4. Not for production: binds to 127.0.0.1 only and forgets everything on exit.

1. Serve (terminal 1):

    python scripts/mcp_oauth_live_check.py serve

   It creates a local tenant (key printed once) and prints the redirect URI to
   add to your Google OAuth client: http://localhost:8121/v1/tenant/me/mcp/oauth/callback

2. In the portal it prints (http://localhost:8121/tenant), register the route
   (MCP Gateway, Register a Server: gdrive, http,
   https://drivemcp.googleapis.com/mcp/v1), then OAuth on its card: enter your
   client ID and secret, tick drive.readonly, Connect, sign in.

3. Check (terminal 2):

    SHIELD_TENANT_KEY=<key from step 1> python scripts/mcp_oauth_live_check.py check --route gdrive

   It makes one read (list_recent_files: one file, no content) unless you name
   another with --call <tool> --args '<json>'. It never prints a token.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8121
BASE = f"http://localhost:{PORT}"
CALLBACK = f"{BASE}/v1/tenant/me/mcp/oauth/callback"
TENANT = "live-check"


def serve() -> None:
    # Everything in memory, vault on with a throwaway key, before any import
    # reads the environment.
    for k in ("REDIS_URL", "UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN"):
        os.environ.pop(k, None)
    kek = tempfile.NamedTemporaryFile("w", delete=False, prefix="shield-live-kek-")
    kek.write(secrets.token_hex(32))
    kek.close()
    os.chmod(kek.name, 0o600)
    os.environ.update({
        "SECRET_VAULT_ENABLED": "true",
        "SECRET_VAULT_KEK": kek.name,
        "SHIELD_OAUTH_REDIRECT_URI": CALLBACK,
    })

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    os.chdir(ROOT)                           # config and static files resolve from the repo
    import uvicorn
    from fastapi import Request
    from fastapi.responses import JSONResponse

    from admin_app import create_admin_app
    from api.routes_mcp_gateway_server import router as gateway_router
    from storage.tenant_store import create_tenant

    tenant_key = "sk-live-" + secrets.token_hex(16)
    create_tenant(TENANT, {"name": "Live check", "plan": "enterprise"}, api_keys=[tenant_key])

    app = create_admin_app()
    app.include_router(gateway_router)       # the data-plane gateway, same process

    @app.post("/_live_check/renew/{route}")
    async def renew_now(route: str, request: Request):
        """Force the refresh the gateway would do near expiry. Local harness only."""
        from core.mcp_credentials import renew_route
        if request.headers.get("x-api-key") != tenant_key:
            return JSONResponse({"error": "tenant key required"}, status_code=401)
        out = await renew_route(TENANT, route, actor="live-check")
        return JSONResponse({k: v for k, v in (out or {}).items() if "token" not in k})

    print(f"""
Shield live check running (local only, in memory).
  Portal:        {BASE}/tenant
  Tenant key:    {tenant_key}
  Redirect URI:  {CALLBACK}   <- add to your Google OAuth client (Web application)
Then follow steps 2 and 3 in the docstring. Ctrl+C to stop; nothing is kept.
""", flush=True)
    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
    finally:
        os.unlink(kek.name)


# ── check ──────────────────────────────────────────────────────────────────


def _http(method: str, path: str, key: str, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-API-Key": key, "Content-Type": "application/json",
                                          "X-Agent-Key": "live-check", "X-User-Role": "operator"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}


def _rpc(route: str, key: str, method: str, params=None):
    status, out = _http("POST", f"/gateway/{route}/mcp", key,
                        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    return status, out


def _status(route: str, key: str) -> dict:
    _, out = _http("GET", f"/v1/tenant/me/mcp/servers/{route}/oauth", key)
    return (out or {}).get("oauth") or {}


def _when(ts) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-"


def check(route: str, call: str | None, args: str | None) -> int:
    key = os.environ.get("SHIELD_TENANT_KEY", "").strip()
    if not key:
        print("Set SHIELD_TENANT_KEY to the key `serve` printed.")
        return 2
    ok = True

    st = _status(route, key)
    print(f"1. status: {st.get('status')}  profile={st.get('profile')}  "
          f"scopes={st.get('scopes')}  refresh_token_held={st.get('refresh_token_held')}  "
          f"header={st.get('authorization_header')}  valid_until={_when(st.get('expires_at'))}")
    if st.get("warning"):
        print(f"   warning: {st['warning']}")
    ok &= st.get("status") == "connected" and st.get("authorization_header") == "brokered"

    code, out = _rpc(route, key, "tools/list")
    tools = [t.get("name") for t in ((out or {}).get("result") or {}).get("tools", [])]
    print(f"2. tools/list through the gateway: HTTP {code}, {len(tools)} tool(s): {', '.join(tools[:12])}")
    if "error" in (out or {}):
        print(f"   error: {out['error'].get('message')}")
    ok &= bool(tools)

    # Google answers tools/list without a sign-in, so the list proves the path,
    # not the token. A read does. The harness's agent is registered for the
    # listed tools so Shield's own RBAC lets the call through.
    if tools:
        _http("POST", "/v1/agents/registry", key,
              {"agent_id": "live-check", "tools": tools, "role_permissions": {"operator": tools}})
    call = call or ("list_recent_files" if "list_recent_files" in tools else None)
    if call:
        call_args = json.loads(args) if args else (
            {"pageSize": 1, "excludeContentSnippets": True} if call == "list_recent_files" else {})
        code, out = _rpc(route, key, "tools/call", {"name": call, "arguments": call_args})
        res = (out or {}).get("result") or {}
        text = "".join(c.get("text", "") for c in res.get("content", []))
        print(f"3. tools/call {call} (needs the token): HTTP {code}, isError={res.get('isError')}, "
              f"{len(text)} characters returned")
        if res.get("isError") or "error" in (out or {}):
            print(f"   {(text or ((out or {}).get('error') or {}).get('message', ''))[:200]}")
        if code == 500:
            # Known gateway bug: an upstream that rejects the call (e.g. no or
            # an expired token, HTTP 401) surfaces as HTTP 500, not a JSON-RPC
            # error. Here it almost always means the route is not connected.
            print("   HTTP 500: the upstream most likely rejected the credential. Is the "
                  "route connected (step 1)?")
        ok &= res.get("isError") is False
    else:
        print("3. no read made: pass --call <tool> --args '<json>'")
        ok = False

    before = st.get("expires_at")
    code, out = _http("POST", f"/_live_check/renew/{route}", key)
    after = _status(route, key)
    print(f"4. forced refresh: HTTP {code}; valid_until {_when(before)} -> "
          f"{_when(after.get('expires_at'))}; status {after.get('status')}")
    ok &= code == 200 and after.get("status") == "connected"

    code, out = _rpc(route, key, "tools/list")
    n = len(((out or {}).get("result") or {}).get("tools", []))
    print(f"5. tools/list after the refresh: HTTP {code}, {n} tool(s)")
    ok &= n > 0

    print("\nPASS" if ok else "\nFAIL: see the lines above")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Live check for an OAuth-brokered MCP route.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the local admin plane + gateway")
    c = sub.add_parser("check", help="verify a connected route end to end")
    c.add_argument("--route", default="gdrive")
    c.add_argument("--call", help="a read-only tool to call once (see the tools/list output)")
    c.add_argument("--args", help="JSON arguments for --call")
    a = p.parse_args(argv)
    if a.cmd == "serve":
        serve()
        return 0
    return check(a.route, a.call, a.args)


if __name__ == "__main__":
    sys.exit(main())
