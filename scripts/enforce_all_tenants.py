#!/usr/bin/env python3
"""Switch every tenant still in monitor mode to enforce.

A dry run by default: it lists each tenant's mode and which would change, and
changes nothing. With --apply it asks once, then switches each monitor tenant
through the admin API (PUT /v1/admin/tenants/{id}/policy-mode), so every change
is in the admin audit log like a change made by hand. Tenants already in
enforce, and tenants with no mode set (which enforce already), are left alone.

    python scripts/enforce_all_tenants.py                     # dry run
    python scripts/enforce_all_tenants.py --apply             # asks, then switches
    python scripts/enforce_all_tenants.py --apply --exclude acme --exclude globex
    python scripts/enforce_all_tenants.py --only acme --apply --yes

The admin key comes from SHIELD_ADMIN_KEY or a hidden prompt; it is never
printed. Talks to the guardrail service (--api), which serves the
policy-mode route. Standard library only. Exit code: 0 done, 1 any tenant
failed, 2 bad usage or no access.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API = "https://api.guardrails.votal.ai"
TIMEOUT_S = 30


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def _call(api: str, key: str, method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        api.rstrip("/") + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-Admin-Key": key, "Content-Type": "application/json",
                 "User-Agent": "votal-enforce-all-tenants"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}")
            msg = detail.get("detail") or detail.get("error") or str(detail)
        except ValueError:
            msg = e.reason
        raise ApiError(e.code, str(msg)) from None
    except urllib.error.URLError as e:
        raise ApiError(0, f"could not reach {api}: {e.reason}") from None


def plan(tenants: list[dict], *, only: set, exclude: set) -> list[dict]:
    """Which tenants to switch: those whose mode is monitor, after --only and
    --exclude. Pure, so it is tested without a server."""
    out = []
    for t in tenants:
        tid = t["tenant_id"]
        if (only and tid not in only) or tid in exclude:
            continue
        if t.get("policy_mode") == "monitor":
            out.append(t)
    return out


def _modes(api: str, key: str, tenants: list[dict]) -> list[dict]:
    """Each tenant with its stored mode. Asks per tenant, so it also works
    against a Shield whose tenant list does not report the mode yet."""
    out = []
    for t in tenants:
        tid = t["tenant_id"]
        mode = t.get("policy_mode")
        if mode is None:
            try:
                mode = _call(api, key, "GET",
                             f"/v1/admin/tenants/{urllib.parse.quote(tid, safe='')}/policy-mode"
                             ).get("policy_mode", "enforce")
            except ApiError as e:
                mode = f"unknown ({e})"
        out.append({**t, "policy_mode": mode})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--api", default=os.environ.get("SHIELD_API", DEFAULT_API),
                    help=f"the guardrail service (default {DEFAULT_API})")
    ap.add_argument("--apply", action="store_true", help="switch them; without it, a dry run")
    ap.add_argument("--yes", action="store_true", help="with --apply, do not ask")
    ap.add_argument("--only", action="append", default=[], metavar="TENANT_ID",
                    help="only this tenant (repeatable)")
    ap.add_argument("--exclude", action="append", default=[], metavar="TENANT_ID",
                    help="leave this tenant as it is (repeatable)")
    args = ap.parse_args(argv)

    key = os.environ.get("SHIELD_ADMIN_KEY", "").strip()
    if not key:
        if not sys.stdin.isatty():
            print("error: set SHIELD_ADMIN_KEY (no terminal to ask on)", file=sys.stderr)
            return 2
        key = getpass.getpass("Admin key (input hidden): ").strip()
    if not key:
        print("error: no admin key", file=sys.stderr)
        return 2

    try:
        tenants = _call(args.api, key, "GET", "/v1/admin/tenants").get("tenants", [])
    except ApiError as e:
        print(f"error: could not list tenants: {e}", file=sys.stderr)
        return 2
    tenants = _modes(args.api, key, tenants)
    targets = plan(tenants, only=set(args.only), exclude=set(args.exclude))
    unknown = sorted(set(args.only) - {t["tenant_id"] for t in tenants})
    if unknown:
        print(f"error: no such tenant: {', '.join(unknown)}", file=sys.stderr)
        return 2

    width = max([len(t["tenant_id"]) for t in tenants] + [9])
    print(f"{'TENANT':<{width}}  {'MODE':<10}  ACTION")
    target_ids = {t["tenant_id"] for t in targets}
    for t in tenants:
        tid = t["tenant_id"]
        action = ("switch to enforce" if tid in target_ids
                  else "excluded" if tid in args.exclude or (args.only and tid not in args.only)
                  else "leave")
        print(f"{tid:<{width}}  {str(t['policy_mode']):<10}  {action}")
    print(f"\n{len(tenants)} tenants; {len(targets)} in monitor to switch.")

    if not targets:
        return 0
    if not args.apply:
        print("Dry run: nothing changed. Run again with --apply to switch them.")
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            print("error: --apply without a terminal needs --yes", file=sys.stderr)
            return 2
        answer = input(f"Switch {len(targets)} tenant(s) to enforce at {args.api}? "
                       "Their policies will start blocking. Type 'enforce' to go on: ")
        if answer.strip() != "enforce":
            print("Nothing changed.")
            return 0

    failed = 0
    for t in targets:
        tid = t["tenant_id"]
        try:
            _call(args.api, key, "PUT",
                  f"/v1/admin/tenants/{urllib.parse.quote(tid, safe='')}/policy-mode",
                  {"mode": "enforce"})
            print(f"  {tid}: enforce")
        except ApiError as e:
            failed += 1
            print(f"  {tid}: FAILED {e}")
    print(f"\nSwitched {len(targets) - failed} of {len(targets)}."
          + (f" {failed} failed: run again to retry them." if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
