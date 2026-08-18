#!/usr/bin/env python3
"""Emit the partner-facing subset of the OpenAPI spec.

The generated spec at /openapi.json describes every route the app mounts -
211 operations, including /v1/admin/tenants, /v1/shield/breakglass, and every
/v1/shield/policies/{tenant_id} write. That is the correct spec for the app and
the wrong thing to hand an integrator: it publishes the admin surface, and it
buries the fifteen operations a partner actually needs.

This filters by an explicit ALLOW list rather than a DENY list. A deny list
fails open - a route added next month is public until someone remembers to
exclude it, and nobody remembers. An allow list fails closed: new routes are
private until deliberately published, which is the direction an API surface
should drift.

Usage:
    python scripts/build_partner_openapi.py --url https://api.guardrails.votal.ai/openapi.json
    python scripts/build_partner_openapi.py --file openapi.json
    python scripts/build_partner_openapi.py            # imports the app directly

Writes docs/assets/openapi-partner.json by default.
"""
import argparse
import json
import sys
from pathlib import Path

# Exact paths a partner may see. Adding one here PUBLISHES it - it is a
# deliberate act, and the review question is "would we support this for five
# years", not "does it work".
ALLOW = {
    # ── Runtime: the guard calls ─────────────────────────────────────────
    "/v1/shield/guardrails": {"get"},   # the catalogue: which guardrails exist
    "/guardrails/input": {"post"},
    "/guardrails/output": {"post"},
    "/guardrails/file": {"post"},
    "/v1/shield/tool/check": {"post"},
    "/v1/shield/tool/output": {"post"},

    # ── Config: tenant-scoped, tenant derived from the key ───────────────
    # Nothing with {tenant_id} in the path belongs here. That shape lets the
    # caller name the tenant, which is what makes it an admin API.
    "/v1/tenant/me": {"get"},
    "/v1/tenant/me/policies": {"get", "put"},
    "/v1/tenant/me/policies/limits": {"get"},
    "/v1/tenant/me/tools": {"get", "put"},

    # One custom-policy namespace, not two. /me/policies/custom is the other
    # spelling of this and is deliberately NOT published - see the note in the
    # description below.
    "/v1/tenant/me/custom-policies/": {"get", "post"},
    "/v1/tenant/me/custom-policies/{policy_id}": {"get", "put", "delete"},
    "/v1/tenant/me/custom-policies/{policy_id}/enable": {"post"},
    "/v1/tenant/me/custom-policies/{policy_id}/disable": {"post"},
    "/v1/tenant/me/custom-policies/validate-prompt": {"post"},
    "/v1/tenant/me/custom-policies/limits/info": {"get"},

    # ── Credentials ──────────────────────────────────────────────────────
    "/v1/tenant/me/api-keys": {"get", "post", "delete"},
    "/v1/tenant/me/key-scope": {"get"},

    # ── Observability ────────────────────────────────────────────────────
    "/v1/tenant/me/usage": {"get"},
    "/v1/tenant/me/telemetry": {"get"},
    "/v1/tenant/me/audit": {"get"},
    "/v1/tenant/me/guardrails/metrics": {"get"},
}

# Partner-facing names. FastAPI derives summaries from handler function names,
# so /guardrails/input arrives titled "Classify" and carries no tag at all - the
# two most important operations in the API render as an internal verb in an
# unnamed bucket. The grouping is equally internal: "tenant-self" describes our
# router layout, not anything an integrator is trying to do.
#
# (tag, summary) per path+method. Ordered by what a reader needs first: call it,
# then configure it, then watch it.
GROUPS = [
    ("Guard: content", "Screen prompts and responses. Call these around your model."),
    ("Guard: tools", "Authorize a tool call before it runs, and screen what it returns. "
                     "An MCP gateway calls these two."),
    ("Policies", "Which guardrails run for your tenant, and how they behave."),
    ("Custom policies", "Your own policies, expressed as prompts, with validation and limits."),
    ("Tool policies", "Per-tool rules."),
    ("API keys", "Issue, label, expire and rotate the keys that authenticate the calls above."),
    ("Usage and audit", "What ran, what it decided, and what it cost."),
]

OPERATIONS = {
    ("/guardrails/input", "post"): ("Guard: content", "Screen a prompt (pre-call)"),
    ("/guardrails/output", "post"): ("Guard: content", "Screen a response (post-call)"),
    ("/guardrails/file", "post"): ("Guard: content", "Screen a file"),

    ("/v1/shield/tool/check", "post"): ("Guard: tools", "Authorize a tool call (pre-execution)"),
    ("/v1/shield/tool/output", "post"): ("Guard: tools", "Screen tool output (post-execution)"),

    ("/v1/shield/guardrails", "get"): ("Policies", "List available guardrails"),
    ("/v1/tenant/me/policies", "get"): ("Policies", "Get my policy configuration"),
    ("/v1/tenant/me/policies", "put"): ("Policies", "Replace my policy configuration"),
    ("/v1/tenant/me/policies/limits", "get"): ("Policies", "Get my policy limits"),

    ("/v1/tenant/me/custom-policies/", "get"): ("Custom policies", "List custom policies"),
    ("/v1/tenant/me/custom-policies/", "post"): ("Custom policies", "Create a custom policy"),
    ("/v1/tenant/me/custom-policies/{policy_id}", "get"): ("Custom policies", "Get a custom policy"),
    ("/v1/tenant/me/custom-policies/{policy_id}", "put"): ("Custom policies", "Update a custom policy"),
    ("/v1/tenant/me/custom-policies/{policy_id}", "delete"): ("Custom policies", "Delete a custom policy"),
    ("/v1/tenant/me/custom-policies/{policy_id}/enable", "post"): ("Custom policies", "Enable a custom policy"),
    ("/v1/tenant/me/custom-policies/{policy_id}/disable", "post"): ("Custom policies", "Disable a custom policy"),
    ("/v1/tenant/me/custom-policies/validate-prompt", "post"): ("Custom policies", "Validate a policy prompt before saving"),
    ("/v1/tenant/me/custom-policies/limits/info", "get"): ("Custom policies", "Get custom-policy limits"),

    ("/v1/tenant/me/tools", "get"): ("Tool policies", "Get my tool policies"),
    ("/v1/tenant/me/tools", "put"): ("Tool policies", "Replace my tool policies"),

    ("/v1/tenant/me/api-keys", "get"): ("API keys", "List my API keys"),
    ("/v1/tenant/me/api-keys", "post"): ("API keys", "Create an API key"),
    ("/v1/tenant/me/api-keys", "delete"): ("API keys", "Revoke an API key"),
    ("/v1/tenant/me/key-scope", "get"): ("API keys", "What this key may do"),

    ("/v1/tenant/me", "get"): ("Usage and audit", "Get my tenant"),
    ("/v1/tenant/me/usage", "get"): ("Usage and audit", "Get my usage"),
    ("/v1/tenant/me/telemetry", "get"): ("Usage and audit", "Get my telemetry"),
    ("/v1/tenant/me/audit", "get"): ("Usage and audit", "Get my audit log"),
    ("/v1/tenant/me/guardrails/metrics", "get"): ("Usage and audit", "Get guardrail metrics"),
}

DESCRIPTION = """\
The partner-facing subset of the Votal Shield API.

Two things to call, and a few to configure:

* **Guard the content path** - `POST /guardrails/input` before the model,
  `POST /guardrails/output` after it.
* **Guard the tool path** - `POST /v1/shield/tool/check` before a tool runs,
  `POST /v1/shield/tool/output` on the way back. An MCP gateway calls these.
* **Configure** - `PUT /v1/tenant/me/policies` and the custom-policy routes.

Authentication is a tenant API key in `X-API-Key`. The tenant is derived from
the key, never from the request, so a key can only ever read and write its own
configuration.

Keys carry a scope. A `runtime` key may call the guard endpoints; an `admin`
key may additionally change configuration. Issue runtime keys to anything on
the hot path.

Not included here: administrative routes, tenant provisioning, and anything
taking a tenant id in the path. Those exist and are not part of the partner
contract.
"""


def load_spec(url: str | None, file: str | None) -> dict:
    if url:
        import urllib.request
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.load(r)
    if file:
        return json.loads(Path(file).read_text())
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.app import create_app          # noqa: E402
    return create_app().openapi()


def filter_spec(spec: dict) -> tuple[dict, list[str], list[str]]:
    """Return (filtered spec, allow-listed-but-absent, published-but-unnamed)."""
    paths = spec.get("paths", {})
    kept: dict = {}
    unnamed: list[str] = []
    for path, methods in ALLOW.items():
        ops = paths.get(path)
        if not ops:
            continue
        selected = {m: op for m, op in ops.items() if m.lower() in methods}
        for method, op in selected.items():
            rename = OPERATIONS.get((path, method.lower()))
            if rename:
                tag, summary = rename
                op["tags"] = [tag]
                op["summary"] = summary
            else:
                # Published but unnamed: it would render under whatever internal
                # tag the router carries. Louder than a silent passthrough,
                # because the whole point of this file is that a partner never
                # sees our router layout.
                unnamed.append(f"{method.upper()} {path}")
        if selected:
            kept[path] = selected

    missing = sorted(set(ALLOW) - set(kept))

    out = {
        "openapi": spec.get("openapi", "3.1.0"),
        "info": {
            "title": "Votal Shield API",
            "version": spec.get("info", {}).get("version", "1.0.0"),
            "description": DESCRIPTION,
        },
        "servers": [{"url": "https://api.guardrails.votal.ai"}],
        "paths": kept,
        # Order here is the order Redoc renders the nav in.
        "tags": [{"name": n, "description": d} for n, d in GROUPS],
    }
    # Carry only the schemas the kept operations actually reference. Copying
    # every component would leak the shape of admin request bodies through the
    # back door, which is the same disclosure this script exists to prevent.
    blob = json.dumps(kept)
    comps = spec.get("components", {}).get("schemas", {})
    needed, frontier = set(), [n for n in comps if f'"#/components/schemas/{n}"' in blob]
    while frontier:
        name = frontier.pop()
        if name in needed:
            continue
        needed.add(name)
        sub = json.dumps(comps.get(name, {}))
        frontier += [n for n in comps if f'"#/components/schemas/{n}"' in sub and n not in needed]
    if needed:
        out["components"] = {"schemas": {n: comps[n] for n in sorted(needed)}}

    out["components"] = out.get("components", {})
    out["components"]["securitySchemes"] = {
        "TenantApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    }
    out["security"] = [{"TenantApiKey": []}]
    return out, missing, unnamed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url")
    ap.add_argument("--file")
    ap.add_argument("--out", default="docs/assets/openapi-partner.json")
    args = ap.parse_args()

    spec = load_spec(args.url, args.file)
    out, missing, unnamed = filter_spec(spec)

    ops = sum(len(m) for m in out["paths"].values())
    total = sum(len(m) for m in spec.get("paths", {}).values())
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2) + "\n")

    print(f"{dest}: {len(out['paths'])} paths, {ops} operations "
          f"(source had {total})")
    if unnamed:
        print("\nWARNING - published without a partner-facing name/tag:")
        for o in unnamed:
            print(f"  {o}")
    if missing:
        # Loud, because the usual cause is a route that was renamed - and a
        # silently shrinking partner spec is how you break an integrator.
        print("\nWARNING - allow-listed but not present in the source spec:")
        for p in missing:
            print(f"  {p}")
        return 1
    return 1 if unnamed else 0


if __name__ == "__main__":
    raise SystemExit(main())
