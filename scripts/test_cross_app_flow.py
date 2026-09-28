#!/usr/bin/env python3
"""Self-test for cross-app flow control against a running Shield.

Runs the real flows through /v1/shield/tool/check with a throwaway agent and
throwaway session ids, and prints PASS / FAIL per step:

  1. Drive read, then a PUBLIC GitHub repo          -> blocked
  2. Same session, a PRIVATE repo                   -> allowed
  3. A fresh session, public repo                   -> allowed
  4. Drive read, then a Slack post                  -> allowed with a warning
  5. Salesforce read, then mail to another company  -> held for approval,
     approved through the API, retried with the signed grant -> allowed,
     the same grant replayed -> blocked
  6. The session lineage view lists what was read

Safe on a live tenant: the tenant's existing flow policy is saved first and
put back at the end (or deleted if there was none), the sessions it used are
cleared, and the test agent is removed. Pass --keep to leave the demo policy
in place. Stdlib only.

    python scripts/test_cross_app_flow.py --base-url https://shield.example.com --api-key sk-...

With SHIELD_REGISTRY_WRITE_SCOPE=enforce, use an admin-scoped key: the script
saves and restores the policy, which runtime keys may not do.

If the data plane and the portal are separate hosts, pass --admin-url for the
portal (policy, registry and approval APIs); --base-url is the data plane.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

AGENT = "xflow-selftest-bot"
ROLE = "xflow-selftest"
TOOLS = ["drive_read_file", "github_create_repo", "salesforce_get_account",
         "gmail_send", "slack_post_message"]
MAIL_DOMAIN = "example.com"          # "internal" domain in the demo policy
FLOW = "/v1/tenant/me/flow-control"


class Api:
    def __init__(self, base, key, role):
        self.base = base.rstrip("/")
        self.key = key
        self.role = role

    def call(self, method, path, body=None, ok=(200,)):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "X-API-Key": self.key, "X-User-Role": self.role,
            "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            payload = {"raw": raw.decode(errors="replace")}
        if status not in ok:
            raise RuntimeError(f"{method} {path} -> HTTP {status}: {json.dumps(payload)[:400]}")
        return status, payload


results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def flow_of(resp):
    return next((g for g in resp.get("guardrail_results", [])
                 if g.get("guardrail") == "cross_app_flow"), None)


def demo_policy():
    return {
        "enabled": True, "mode": "enforce",
        "apps": {
            "google_drive": {"tools": ["drive_*", "drive.*"], "classification": "confidential"},
            "salesforce": {"tools": ["salesforce_*", "salesforce.*"],
                           "classification": "confidential",
                           "source_tools": ["salesforce_get*", "salesforce.get*"]},
            "github": {"tools": ["github_*", "github.*"], "classification": "internal"},
            "gmail": {"tools": ["gmail_*", "gmail.*"]},
            "slack": {"tools": ["slack_*", "slack.*"], "classification": "internal"},
        },
        "exposure_rules": [
            {"tools": ["github_create_repo*", "github.create_repo*"], "param": "private",
             "equals": False, "exposure": "public"},
            {"tools": ["github_create_repo*", "github.create_repo*"], "param": "private",
             "missing": True, "exposure": "public"},
            {"apps": ["gmail"], "param": "*", "domain_not_in": [MAIL_DOMAIN],
             "exposure": "external"},
        ],
        "rules": [
            {"id": "confidential-to-public", "source": {"min_classification": "confidential"},
             "destination": {"exposure": ["public"]}, "action": "block"},
            {"id": "customer-data-external", "source": {"apps": ["salesforce"]},
             "destination": {"exposure": ["external"]}, "action": "require_approval"},
            {"id": "confidential-to-chat", "source": {"apps": ["google_drive"]},
             "destination": {"apps": ["slack"]}, "action": "warn"},
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base-url", required=True, help="data plane (serves /v1/shield/tool/check)")
    ap.add_argument("--admin-url", help="portal / admin plane, when it is a different host")
    ap.add_argument("--api-key", required=True, help="tenant API key")
    ap.add_argument("--settle", type=float, default=6.0,
                    help="seconds to wait after saving the policy (replica cache, default 6)")
    ap.add_argument("--keep", action="store_true", help="leave the demo policy in place")
    args = ap.parse_args()

    dp = Api(args.base_url, args.api_key, ROLE)
    admin = Api(args.admin_url or args.base_url, args.api_key, ROLE)
    run = uuid.uuid4().hex[:8]
    s1, s2, s3 = f"xflow-{run}-a", f"xflow-{run}-b", f"xflow-{run}-c"

    print("Setup")
    _, before = admin.call("GET", f"{FLOW}/policy")
    backup = before.get("policy") if before.get("configured") else None
    print(f"  existing policy: {'saved for restore' if backup else 'none'}")
    status, _ = admin.call("POST", "/v1/agents/registry", ok=(200, 409), body={
        "agent_id": AGENT, "name": "Cross-app flow self-test", "tools": TOOLS,
        "role_permissions": {ROLE: TOOLS}})
    print(f"  test agent {AGENT}: {'created' if status == 200 else 'already registered'}")
    admin.call("PUT", f"{FLOW}/policy", demo_policy())
    print(f"  demo policy saved (enforce); waiting {args.settle:.0f}s for every replica")
    time.sleep(args.settle)

    def tool(name, params, session, **extra):
        _, d = dp.call("POST", "/v1/shield/tool/check", {
            "agent_key": AGENT, "tool_name": name, "tool_params": params,
            "session_id": session, "user_role": ROLE, **extra})
        return d

    try:
        print("\n1. Confidential Drive read, then a public GitHub repo")
        d = tool("drive_read_file", {"file_id": "contract-9281"}, s1)
        if not d.get("allowed"):
            print(f"  cannot run: the read itself was denied: "
                  f"{[g['message'] for g in d.get('guardrail_results', []) if not g['passed']]}")
            print("  Check that the tenant's RBAC accepts the X-User-Role header for this agent.")
            return 2
        check("drive_read_file allowed", d.get("allowed"))
        d = tool("github_create_repo", {"name": "customer-dump", "private": False}, s1)
        f = flow_of(d) or {}
        check("public repo blocked", d.get("allowed") is False and f.get("action") == "block",
              f.get("message", "no cross_app_flow result")[:140])

        print("\n2. Same session, private repo")
        d = tool("github_create_repo", {"name": "customer-dump", "private": True}, s1)
        check("private repo allowed", d.get("allowed") is True)

        print("\n3. Fresh session, public repo")
        d = tool("github_create_repo", {"name": "open-source-lib", "private": False}, s2)
        check("allowed (nothing confidential read)", d.get("allowed") is True)

        print("\n4. Drive read, then Slack")
        d = tool("slack_post_message", {"channel": "general", "text": "summary"}, s1)
        check("allowed with a warning", d.get("allowed") is True and d.get("action") == "warn",
              f"action={d.get('action')}")

        print("\n5. Salesforce read, then mail to another company")
        tool("salesforce_get_account", {"id": "001"}, s3)
        mail = {"to": "buyer@partner-corp.com", "subject": "Q3", "body": "account summary"}
        d = tool("gmail_send", mail, s3)
        f = flow_of(d) or {}
        rid = (f.get("details") or {}).get("request_id")
        check("held for approval", d.get("action") == "pending_confirmation" and rid, f"request {rid}")
        d_retry = tool("gmail_send", mail, s3)
        check("a retry reuses the same request",
              ((flow_of(d_retry) or {}).get("details") or {}).get("request_id") == rid)
        internal = tool("gmail_send", {**mail, "to": f"cfo@{MAIL_DOMAIN}"}, s3)
        check("mail inside the company is not held", internal.get("allowed") is True)
        if rid:
            _, appr = admin.call("POST", f"/v1/tenant/me/agentic/approvals/{rid}/approve",
                                 {"approver": "selftest@shield", "reason": "cross-app flow self-test"})
            grant = appr.get("approval_grant")
            if not grant:
                print(f"  [SKIP] approved, but no signed grant was issued (status "
                      f"{appr.get('status')}). Configure SHIELD_APPROVAL_TOKEN_PRIVATE_KEY "
                      f"on the portal to test the grant path.")
            else:
                d = tool("gmail_send", mail, s3, approval_grant=grant)
                check("approved send allowed with the signed grant", d.get("allowed") is True)
                d = tool("gmail_send", mail, s3, approval_grant=grant)
                check("replaying the grant is refused", d.get("allowed") is False)

        print("\n6. Session lineage")
        _, lin = admin.call("GET", f"{FLOW}/sessions/{s1}")
        tools_read = [r["tool"] for r in lin.get("records", [])]
        check("lineage lists the Drive read", "drive_read_file" in tools_read, ", ".join(tools_read))
    finally:
        print("\nCleanup")
        for s in (s1, s2, s3):
            try:
                admin.call("DELETE", f"{FLOW}/sessions/{s}")
            except Exception as e:
                print(f"  could not clear {s}: {e}")
        if args.keep:
            print("  --keep: demo policy left in place")
        elif backup:
            admin.call("PUT", f"{FLOW}/policy", backup)
            print("  original policy restored")
        else:
            admin.call("DELETE", f"{FLOW}/policy")
            print("  demo policy deleted (there was none before)")
        try:
            admin.call("DELETE", f"/v1/agents/registry/{AGENT}", ok=(200, 204, 404))
            print(f"  test agent {AGENT} removed")
        except Exception as e:
            print(f"  could not remove {AGENT}: {e}")

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
