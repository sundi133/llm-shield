"""Discover an upstream's tools and grant them to an agent.

Replaces hand-writing a PUT to /v1/agents/registry with the tool names typed
out. Shield already knows the tools: the upstream declares them in tools/list.

    python scripts/grant_agent_tools.py --route bank-mcp --dry-run
    python scripts/grant_agent_tools.py --route bank-mcp \
        --deny wire_transfer_execute --deny email_send

Why a prefix flag exists: some clients rename tools before calling. JumpCloud's
AI Gateway prepends a per-server prefix, so `statement_generate` arrives as
`DEMO_statement_generate`. RBAC matches names as exact strings, so a grant list
written for one world silently denies everything in the other. Until the gateway
normalises prefixes itself, --prefix regenerates the list for whichever client
you are pointing at it:

    python scripts/grant_agent_tools.py --route bank-mcp --prefix DEMO_

Discovery queries the UPSTREAM directly, never the gateway. Asking the gateway
would return the already-filtered list, so a grant list rebuilt from it could
only ever shrink - one bad run and the agent is locked out of everything.

Env: SHIELD_API_KEY (required), SHIELD_BASE_URL (default production).
"""
import argparse
import json
import os
import sys

import httpx

BASE = os.environ.get("SHIELD_BASE_URL", "https://api.guardrails.votal.ai")
KEY = os.environ.get("SHIELD_API_KEY", "")


def _die(msg: str) -> "None":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def upstream_url(c: httpx.Client, route: str) -> str:
    r = c.get(f"{BASE}/v1/tenant/me/mcp-gateway/upstreams/{route}",
              headers={"X-API-Key": KEY})
    if r.status_code != 200:
        _die(f"route {route!r} not found ({r.status_code}). "
             f"List them: GET {BASE}/v1/tenant/me/mcp-gateway/upstreams")
    body = r.json()
    cfg = body.get("upstream", body)
    url = cfg.get("url")
    if not url:
        _die(f"route {route!r} has no url (transport={cfg.get('transport')!r}). "
             "Only http/sse upstreams can be discovered this way.")
    return url


def discover(c: httpx.Client, url: str) -> list:
    """tools/list straight from the upstream, bypassing Shield's filtering."""
    r = c.post(url, headers={"Content-Type": "application/json",
                             "Accept": "application/json, text/event-stream"},
               json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    try:
        body = r.json()
    except Exception:
        _die(f"upstream did not return JSON (HTTP {r.status_code}). "
             f"First bytes: {r.text[:120]!r}")
    if "error" in body:
        _die(f"upstream refused tools/list: {body['error']}")
    tools = (body.get("result") or {}).get("tools")
    if not tools:
        _die("upstream advertised no tools; refusing to write an empty grant list")
    return [t["name"] for t in tools]


def build(names: list, prefix: str, deny: set, roles: list) -> dict:
    """Full pool for admin, pool-minus-deny for every other role."""
    full = [prefix + n for n in names]
    safe = [prefix + n for n in names if n not in deny]
    perms = {r: (full if r == "admin" else safe) for r in roles}
    perms.setdefault("admin", full)
    return {"tools": full, "role_permissions": perms}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--route", required=True, help="gateway route name")
    p.add_argument("--agent", default="mcp-agent", help="agent_id to grant to")
    p.add_argument("--prefix", default="",
                   help="prepend to every granted name. NOT for JumpCloud: it "
                        "strips its own prefix before calling Shield, so a "
                        "prefixed grant matches nothing and shows an empty "
                        "connector. Only for clients that truly rename tools.")
    p.add_argument("--deny", action="append", default=[], metavar="TOOL",
                   help="withhold from non-admin roles (repeatable, unprefixed name)")
    p.add_argument("--role", action="append", default=[], metavar="ROLE",
                   help="roles to write (repeatable; default: '' and admin)")
    p.add_argument("--dry-run", action="store_true", help="print, do not write")
    a = p.parse_args()

    if not KEY:
        _die("set SHIELD_API_KEY")

    roles = a.role or ["", "admin"]
    with httpx.Client(timeout=60) as c:
        url = upstream_url(c, a.route)
        names = discover(c, url)
        print(f"  upstream   {url}")
        print(f"  discovered {len(names)}: {', '.join(names)}")

        unknown = set(a.deny) - set(names)
        if unknown:
            _die(f"--deny names not on this server: {sorted(unknown)}. "
                 "Use the upstream's own names, without --prefix.")

        payload = build(names, a.prefix, set(a.deny), roles)
        for role, granted in payload["role_permissions"].items():
            withheld = [t for t in payload["tools"] if t not in granted]
            label = repr(role) if role == "" else role
            print(f"  role {label:<10} {len(granted)} granted"
                  + (f", withheld: {', '.join(withheld)}" if withheld else ""))

        if a.dry_run:
            print("\n  --dry-run, nothing written. Payload:")
            print(json.dumps(payload, indent=2))
            return

        r = c.put(f"{BASE}/v1/agents/registry/{a.agent}",
                  headers={"X-API-Key": KEY, "Content-Type": "application/json"},
                  json=payload)
        if r.status_code == 404:
            r = c.post(f"{BASE}/v1/agents/registry",
                       headers={"X-API-Key": KEY, "Content-Type": "application/json"},
                       json={"agent_id": a.agent, "name": a.agent, **payload})
        if r.status_code not in (200, 201):
            _die(f"write failed HTTP {r.status_code}: {r.text[:200]}")
        print(f"\n  wrote {len(payload['tools'])} tools to agent {a.agent!r}")


if __name__ == "__main__":
    main()
