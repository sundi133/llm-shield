"""Seed one Shield tenant for the "agents launder confidential data" demo.

Uses only existing Shield APIs on the data plane, with the tenant's own API
key. Standard library only, so it runs anywhere Python does.

What it sets up for the tenant:
  1. Gateway route `workspace` -> the mock Workspace MCP server (via its
     public tunnel URL), with the server's key held by the gateway.
  2. Agent `workspace-assistant` with the six Drive/Gmail tools for role
     `employee`.
  3. A cross-app flow policy: anything read from Drive is confidential; mail
     to an address outside the company's domains is "external"; confidential
     -> external is blocked. Deterministic, no model involved.
  4. Optional (--tool-policy): gmail_send's own tool policy with the
     ready-made "Data sent outside your domains" protection, judged by the
     guard model, as a second layer.

Safe by default:
  * Without --apply it is a dry run: it prints every request it would make.
  * With --apply it first saves whatever it is about to overwrite (route,
    agent, flow policy, gmail_send policy) to a backup file, and
    --restore <file> puts it all back (deleting what did not exist before).
  * The flow policy REPLACES the tenant's flow policy. Use a demo tenant.

Environment:
    SHIELD_API          data plane, default https://api.guardrails.votal.ai
    SHIELD_TENANT_KEY   the demo tenant's API key (required)
    DEMO_UPSTREAM_URL   public URL of the mock server's /mcp, e.g. the ngrok URL + /mcp
    DEMO_UPSTREAM_KEY   the mock server's key (same value the server was started with)

Usage:
    python examples/workspace_exfil_demo/seed.py                 # dry run
    python examples/workspace_exfil_demo/seed.py --apply
    python examples/workspace_exfil_demo/seed.py --apply --tool-policy
    python examples/workspace_exfil_demo/seed.py --restore backup-<...>.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROUTE = "workspace"
AGENT = "workspace-assistant"
ROLE = "employee"
TOOLS = ["drive_search", "drive_read", "drive_share",
         "gmail_list_inbox", "gmail_read", "gmail_send"]
COMPANY_DOMAINS = ["bank.ae"]


# ── what gets written ──────────────────────────────────────────────────────


def upstream_config(url: str, key: str) -> dict:
    return {
        "transport": "http",
        "url": url,
        # Only the gateway holds the upstream's key. An agent pointed at the
        # gateway never sees it, so it cannot call the server around Shield.
        "headers": {"X-Demo-Key": key},
        "isolation_ack": False,
    }


def agent_entry() -> dict:
    return {"agent_id": AGENT, "name": "Workspace assistant",
            "description": "Demo: reads Drive, sends Gmail",
            "tools": TOOLS, "role_permissions": {ROLE: TOOLS}}


def flow_policy(mode: str = "enforce", domains: list[str] = COMPANY_DOMAINS) -> dict:
    """Confidential data read from Drive may not be emailed outside the company.

    principal_scope "agent": the gateway gives flow control no user, so what an
    agent read is remembered per agent (for principal_window_seconds).
    """
    return {
        "enabled": True,
        "mode": mode,
        "fail_closed": False,
        "session_ttl_seconds": 3600,
        "principal_scope": "agent",
        "principal_window_seconds": 1800,
        "default_exposure": "internal",
        "apps": {
            "google_drive": {"tools": ["drive_*"], "classification": "confidential",
                             "source_tools": ["drive_read*", "drive_search*"],
                             "description": "Documents; everything read is treated as confidential"},
            "gmail": {"tools": ["gmail_*"], "description": "Mail"},
        },
        "exposure_rules": [
            {"apps": ["gmail"], "param": "to", "domain_not_in": domains,
             "exposure": "external", "description": "Mail to any address outside the company"},
            {"tools": ["drive_share*"], "param": "email", "domain_not_in": domains,
             "exposure": "external", "description": "Sharing a file outside the company"},
        ],
        "rules": [
            {"id": "confidential-leaves-company",
             "description": "Anything read from Drive may not be sent outside the company",
             "source": {"min_classification": "confidential"},
             "destination": {"exposure": ["external"]},
             "action": "block"},
        ],
    }


def gmail_send_policy(library: list[dict], domains: list[str] = COMPANY_DOMAINS) -> dict:
    """gmail_send's own tool policy: the ready-made T12 protection with the
    company's domains filled in, as the portal's editor does."""
    t12 = next(e for e in library if e.get("id") == "call.T12")
    rule = t12["rule"].replace(t12.get("needs") or "<your-domains>", ", ".join(domains))
    return {"tool_name": "gmail_send",
            "role_policies": [{"role": "*", "action": "block", "input_rules": [rule]}]}


# ── HTTP ───────────────────────────────────────────────────────────────────


class Shield:
    def __init__(self, base: str, key: str, apply: bool):
        self.base, self.key, self.apply = base.rstrip("/"), key, apply

    def _req(self, method: str, path: str, body=None, *, write: bool):
        if write and not self.apply:
            shown = dict(body or {})
            if isinstance(shown.get("headers"), dict):  # never print the upstream's key
                shown["headers"] = {k: "***" for k in shown["headers"]}
            print(f"  [dry run] {method} {path}" + (f"\n    {json.dumps(shown)[:300]}" if body else ""))
            return None, None
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"X-API-Key": self.key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read().decode() or "{}"
                return r.status, json.loads(raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"raw": raw[:300]}

    def get(self, path):
        return self._req("GET", path, write=False)

    def write(self, method, path, body=None):
        status, out = self._req(method, path, body, write=True)
        if status is not None and status >= 300:
            raise SystemExit(f"{method} {path} failed: {status} {json.dumps(out)[:400]}")
        return out


# ── steps ──────────────────────────────────────────────────────────────────


def preflight(s: Shield) -> list[dict]:
    status, health = s.get("/health")
    print(f"  data plane /health: {status} {health}")
    status, body = s.get("/v1/tenant/me/flow-control/policy")
    if status == 401 or status == 403:
        raise SystemExit("  SHIELD_TENANT_KEY was rejected.")
    if status == 404 and "detail" in (body or {}) and "Not Found" in str(body):
        raise SystemExit("  Flow control is not deployed on this data plane.")
    status, lib = s.get("/v1/data-policies/library")
    return (lib or {}).get("entries", []) if status == 200 else []


def route_exists(s: Shield) -> bool:
    status, _ = s.get(f"/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}")
    return status == 200


def snapshot(s: Shield) -> dict:
    """What the demo is about to overwrite, so --restore can put it back.

    The route is recorded only as existed / did not exist: the API masks its
    headers, so a copy could not be written back without destroying the key.
    """
    _, agents = s.get("/v1/agents/registry")
    _, flow = s.get("/v1/tenant/me/flow-control/policy")
    _, tool = s.get("/v1/data-policies/tools/gmail_send/policy")
    agent_list = (agents or {}).get("agents") or {}
    if isinstance(agent_list, list):
        agent_list = {a.get("agent_id"): a for a in agent_list if isinstance(a, dict)}
    stored_tool = (tool or {}).get("policy") or {}
    return {
        "route_existed": route_exists(s),
        "agent": agent_list.get(AGENT),
        "flow_policy": (flow or {}).get("policy"),
        # GET returns an empty default when nothing is stored; a stored one has timestamps.
        "gmail_send_policy": stored_tool if stored_tool.get("created_at") else None,
    }


def seed(args) -> None:
    key = os.environ.get("SHIELD_TENANT_KEY", "").strip()
    url = os.environ.get("DEMO_UPSTREAM_URL", "").strip()
    up_key = os.environ.get("DEMO_UPSTREAM_KEY", "").strip()
    if not key:
        raise SystemExit("Set SHIELD_TENANT_KEY to the demo tenant's API key.")
    api = os.environ.get("SHIELD_API", "https://api.guardrails.votal.ai")
    local_shield = api.startswith(("http://localhost", "http://127.0.0.1"))
    if not url.rstrip("/").endswith("/mcp") or not (url.startswith("https://") or local_shield):
        raise SystemExit("Set DEMO_UPSTREAM_URL to the public https URL of the mock server's /mcp "
                         "(a hosted gateway cannot reach localhost).")
    if len(up_key) < 16:
        raise SystemExit("Set DEMO_UPSTREAM_KEY to the key the mock server was started with.")

    s = Shield(api, key, args.apply)
    print(f"Target {s.base} ({'APPLY' if args.apply else 'dry run'})")
    print("1. Preflight")
    library = preflight(s)
    if route_exists(s) and not args.force:
        raise SystemExit(f"  Route '{ROUTE}' already exists for this tenant. Re-run with --force "
                         "to replace it (its current headers cannot be restored afterwards).")

    if args.apply:
        backup = {"api": s.base, "taken_at": time.strftime("%Y-%m-%dT%H:%M:%S"), **snapshot(s)}
        path = f"backup-{ROUTE}-{time.strftime('%Y%m%d-%H%M%S')}.json"
        with open(path, "w") as f:
            json.dump(backup, f, indent=2)
        print(f"   backup of what will change: {path}")

    print(f"2. Gateway route '{ROUTE}' -> {url}")
    s.write("PUT", f"/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}", upstream_config(url, up_key))
    print(f"3. Agent '{AGENT}' with {len(TOOLS)} tools for role '{ROLE}'")
    s.write("POST", "/v1/agents/registry", agent_entry())
    print(f"4. Flow policy ({args.mode}): Drive -> mail outside {', '.join(COMPANY_DOMAINS)} is blocked")
    policy = flow_policy(args.mode)
    if args.apply:
        # Answers 200 either way; the verdict is in the body.
        checked = s.write("POST", "/v1/tenant/me/flow-control/validate", policy)
        if not (checked or {}).get("valid"):
            raise SystemExit(f"   the server rejected the flow policy: {(checked or {}).get('errors')}")
    s.write("PUT", "/v1/tenant/me/flow-control/policy", policy)
    if args.tool_policy:
        if not library:
            print("5. Skipped: this data plane has no /v1/data-policies/library (tool policy editor not deployed).")
        else:
            print("5. gmail_send tool policy: 'Data sent outside your domains' (judged by the guard model)")
            s.write("POST", "/v1/data-policies/tools/gmail_send/policy", gmail_send_policy(library))
    print("\nDone." if args.apply else "\nDry run only. Re-run with --apply to make these changes.")
    print(f"Gateway URL for agents: {s.base}/gateway/{ROUTE}/mcp")
    print(f"  headers: X-API-Key=<tenant key>, X-Agent-Key={AGENT}, X-User-Role={ROLE}")


def restore(args) -> None:
    key = os.environ.get("SHIELD_TENANT_KEY", "").strip()
    if not key:
        raise SystemExit("Set SHIELD_TENANT_KEY to the demo tenant's API key.")
    with open(args.restore) as f:
        b = json.load(f)
    s = Shield(os.environ.get("SHIELD_API", b.get("api") or "https://api.guardrails.votal.ai"), key, True)
    print(f"Restoring {s.base} from {args.restore}")
    if b.get("route_existed"):
        print(f"  Route '{ROUTE}' existed before the demo; left as the demo set it (its "
              "original headers were masked and cannot be restored).")
    else:
        s.write("DELETE", f"/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}")
    if b.get("agent"):
        s.write("POST", "/v1/agents/registry", b["agent"])
    else:
        s.write("DELETE", f"/v1/agents/registry/{AGENT}")
    if b.get("flow_policy"):
        s.write("PUT", "/v1/tenant/me/flow-control/policy", b["flow_policy"])
    else:
        s.write("DELETE", "/v1/tenant/me/flow-control/policy")
    if b.get("gmail_send_policy"):
        prev = {k: v for k, v in b["gmail_send_policy"].items() if k not in ("created_at", "updated_at")}
        s.write("POST", "/v1/data-policies/tools/gmail_send/policy", prev)
    else:
        _, tool = s.get("/v1/data-policies/tools/gmail_send/policy")
        if ((tool or {}).get("policy") or {}).get("created_at"):
            s.write("DELETE", "/v1/data-policies/tools/gmail_send/policy")
    print("Restored.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--apply", action="store_true", help="make the changes (default: dry run)")
    p.add_argument("--mode", choices=["enforce", "monitor"], default="enforce",
                   help="flow policy mode; monitor records would-blocks without blocking")
    p.add_argument("--tool-policy", action="store_true",
                   help="also set gmail_send's tool policy (ready-made T12, model-judged)")
    p.add_argument("--restore", metavar="BACKUP", help="put back what a previous --apply changed")
    p.add_argument("--force", action="store_true",
                   help=f"replace an existing '{ROUTE}' gateway route")
    args = p.parse_args(argv)
    restore(args) if args.restore else seed(args)


if __name__ == "__main__":
    sys.exit(main())
