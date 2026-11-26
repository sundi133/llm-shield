#!/usr/bin/env python3
"""Seed Shield's AI Inventory with a first-party and third-party AI demo.

Spec: docs/specs/ai-discovery.md. Each step feeds one discovery source with
the fixtures next to this file, through the same routes a real deployment
uses. Standard library only; run it from anywhere inside the repository.

    python examples/ai-discovery-demo/seed.py \\
        --shield-url http://localhost:8080 --portal-url http://localhost:8099 \\
        --api-key "$TENANT_KEY"

    --admin-key KEY     also create the tenant (--tenant, default "acme") with --api-key
    --only a,b          run only these steps (default: all, in order)
    --dry-run           print what each step would send; no network calls

Steps:

  First party (AI your own teams build)
    tenant   create the demo tenant (only with --admin-key)
    agents   register "claims-assistant" and make one tool call, so it turns governed
    shadow   an unregistered agent ("invoice-scraper-bot") calls Shield
    scan     code scan of fixtures/claims-agent, sent as a repo_scan batch
    dns      import fixtures/dns.csv (servers calling AI providers directly)

  Third party (AI tools your employees use)
    proxy    the proxy's sightings: employees using ChatGPT, Claude, Gemini, ...
    laptop   enroll a demo laptop and send the collector's findings for
             fixtures/laptop/alice in its heartbeat (needs
             SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY on Shield, else skipped)

The data plane (--shield-url) takes the guard, ingest and device calls; the
admin plane (--portal-url, default the same URL) takes the log import and the
enrollment token. Re-running is safe: entries merge, nothing is duplicated.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FIXTURES = HERE / "fixtures"
STEPS = ("tenant", "agents", "shadow", "scan", "dns", "proxy", "laptop")

SANCTIONED_AGENT = "claims-assistant"
SHADOW_AGENT = "invoice-scraper-bot"
SCAN_REPO = "acme/claims-agent"
LAPTOP_HOSTNAME = "alice-mbp"

PROXY_OBSERVATIONS = [
    {"kind": "domain", "domain": "chatgpt.com", "subject": {"type": "user", "id": "alice@acme.example"}},
    {"kind": "domain", "domain": "claude.ai", "subject": {"type": "user", "id": "bob@acme.example"}},
    {"kind": "domain", "domain": "gemini.google.com", "subject": {"type": "user", "id": "carol@acme.example"}},
    {"kind": "domain", "domain": "www.perplexity.ai", "subject": {"type": "user", "id": "alice@acme.example"}},
    {"kind": "domain", "domain": "api.deepseek.com", "subject": {"type": "user", "id": "dave@acme.example"}},
]


# ── fixtures to observations (offline) ────────────────────────────────

def _repo_paths() -> None:
    for p in (REPO, REPO / "packages" / "shield-mcp" / "src"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))


def scan_observations() -> list[dict]:
    """What `shield-mcp discover --post` sends for the demo repository."""
    _repo_paths()
    from shield_mcp import discover
    report = discover.scan(str(FIXTURES / "claims-agent"), repo=SCAN_REPO)
    return discover.observations(report)


def _collector():
    """The device agent's collector, loaded from its file: the package's
    __init__ needs the agent's own dependencies, the collector does not."""
    path = REPO / "packages" / "votal-device-agent" / "votal_device_agent" / "discovery.py"
    spec = importlib.util.spec_from_file_location("_demo_device_discovery", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def laptop_observations() -> list[dict]:
    """What the device agent's collector reports for fixtures/laptop/alice.
    Only the fixture home is read: the system bin folders, the PATH and the
    local ports of the machine running this script are left out."""
    _repo_paths()
    from core.discovery import catalog
    col = _collector()
    col.SYSTEM_BIN_DIRS = ()
    home = FIXTURES / "laptop" / "alice"
    return col.collect(catalog.device_bundle(""), os_name="macos", homes=[home],
                       app_dirs=[home / "Applications"], which=lambda name: None,
                       port_open=lambda port: False)


# ── HTTP ──────────────────────────────────────────────────────────────

class Shield:
    def __init__(self, shield_url: str, portal_url: str, api_key: str, timeout: float = 20.0):
        self.dp = shield_url.rstrip("/")
        self.portal = (portal_url or shield_url).rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def call(self, method: str, url: str, *, body=None, data: bytes | None = None,
             content_type: str = "application/json", headers: dict | None = None,
             key: str | None = None) -> tuple[int, object]:
        h = {"Content-Type": content_type, "Accept": "application/json"}
        if key is None:
            key = self.key
        if key:
            h["Authorization"] = f"Bearer {key}"
        h.update(headers or {})
        payload = data if data is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(url, data=payload, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        except urllib.error.URLError as e:
            return 0, {"error": f"cannot reach {url}: {e.reason}"}
        try:
            return status, json.loads(raw) if raw else {}
        except ValueError:
            return status, {"body": raw[:300].decode(errors="replace")}


def _detail(out) -> str:
    if isinstance(out, dict):
        return str(out.get("detail") or out.get("error") or out)[:300]
    return str(out)[:300]


class StepError(RuntimeError):
    pass


class Skip(RuntimeError):
    pass


# ── steps ─────────────────────────────────────────────────────────────

def step_tenant(s: Shield, a) -> str:
    if not a.admin_key:
        raise Skip("no --admin-key; using the existing tenant of --api-key")
    st, out = s.call("POST", f"{s.dp}/v1/admin/tenants", key="",
                     headers={"X-Admin-Key": a.admin_key},
                     body={"tenant_id": a.tenant, "api_keys": [a.api_key]})
    if st == 409:
        return f"tenant {a.tenant} already exists"
    if st != 200:
        raise StepError(f"create tenant: HTTP {st}: {_detail(out)}")
    return f"tenant {a.tenant} created"


def step_agents(s: Shield, a) -> str:
    st, out = s.call("POST", f"{s.dp}/v1/agents/registry", body={
        "agent_id": SANCTIONED_AGENT, "name": "Claims assistant",
        "description": "Sanctioned first-party agent (AI discovery demo)"})
    if st not in (200, 201, 409):
        raise StepError(f"register {SANCTIONED_AGENT}: HTTP {st}: {_detail(out)}")
    registered = "registered" if st != 409 else "already registered"
    # A registered agent is governed once Shield sees it on the guard path
    # making tool calls (tool/check, cap/mint or the MCP gateway); the
    # verdict of this call does not matter, only that Shield saw it.
    st, out = s.call("POST", f"{s.dp}/v1/shield/tool/check",
                     headers={"X-Agent-Key": SANCTIONED_AGENT},
                     body={"tool_name": "lookup_claim", "arguments": {"claim_id": "C-1001"},
                           "agent_key": SANCTIONED_AGENT, "user_role": "adjuster"})
    if st not in (200, 403):
        raise StepError(f"tool call for {SANCTIONED_AGENT}: HTTP {st}: {_detail(out)}")
    return f"{SANCTIONED_AGENT} {registered}, one tool call made (governed within about a minute)"


def step_shadow(s: Shield, a) -> str:
    st, out = s.call("POST", f"{s.dp}/guardrails/input", headers={"X-Agent-Key": SHADOW_AGENT},
                     body={"message": "Summarize this month's vendor invoices"})
    if st == 403 and isinstance(out, dict) and out.get("error") in ("unregistered_agent", "agent_blocked"):
        return f"{SHADOW_AGENT} seen and refused ({out['error']})"
    if st != 200:
        raise StepError(f"shadow agent call: HTTP {st}: {_detail(out)}")
    return f"{SHADOW_AGENT} called Shield without being registered"


def _batch(s: Shield, source: str, obs: list) -> dict:
    st, out = s.call("POST", f"{s.dp}/v1/shield/discovery/batch",
                     body={"source": source, "observations": obs})
    if not 200 <= st < 300:
        raise StepError(f"{source} batch: HTTP {st}: {_detail(out)}")
    return out


def step_scan(s: Shield, a) -> str:
    out = _batch(s, "repo_scan", scan_observations())
    return f"repo {SCAN_REPO}: {out.get('accepted')} accepted, {out.get('new_entries')} new"


def step_dns(s: Shield, a) -> str:
    data = (FIXTURES / "dns.csv").read_bytes()
    st, job = s.call("POST", f"{s.portal}/v1/tenant/me/discovery/import?source=dns_log&format=csv&name=demo-dns",
                     data=data, content_type="text/csv")
    if not 200 <= st < 300:
        raise StepError(f"log import: HTTP {st}: {_detail(job)}")
    for _ in range(40):
        if job.get("state") in ("done", "failed"):
            break
        time.sleep(0.25)
        st, job = s.call("GET", f"{s.portal}/v1/tenant/me/discovery/import/{job['id']}")
        if st != 200:
            raise StepError(f"log import status: HTTP {st}: {_detail(job)}")
    if job.get("state") != "done":
        raise StepError(f"log import {job.get('state')}: {job.get('error') or 'still running'}")
    return f"{job.get('rows')} log rows, {job.get('matched')} matched AI hosts, {job.get('new_entries')} new"


def step_proxy(s: Shield, a) -> str:
    out = _batch(s, "proxy", PROXY_OBSERVATIONS)
    return f"{out.get('accepted')} accepted, {out.get('new_entries')} new"


def step_laptop(s: Shield, a) -> str:
    obs = laptop_observations()
    st, tok = s.call("POST", f"{s.portal}/v1/tenant/me/devices/enrollment-tokens",
                     body={"fleet": "demo", "uses": 1, "expires_in_days": 1})
    if st == 404:
        raise Skip(f"the device agent is off on this Shield: {_detail(tok)}")
    if st != 200:
        raise StepError(f"enrollment token: HTTP {st}: {_detail(tok)}")
    st, dev = s.call("POST", f"{s.dp}/v1/devices/enroll", key="",
                     headers={"X-Enrollment-Token": tok["enrollment_token"]},
                     body={"hostname": LAPTOP_HOSTNAME, "os": "macos", "os_version": "15.1",
                           "agent_version": "demo"})
    if st == 503:
        raise Skip("Shield has no bundle signing key, so no laptop can enroll; set "
                   "SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY on the data plane")
    if st != 200:
        raise StepError(f"enroll: HTTP {st}: {_detail(dev)}")
    st, out = s.call("POST", f"{s.dp}/v1/devices/heartbeat", key=dev["api_key"],
                     body={"state": "ok", "mode": "monitor", "ai_inventory": obs})
    if st != 204:
        raise StepError(f"heartbeat: HTTP {st}: {_detail(out)}")
    return f"laptop {LAPTOP_HOSTNAME} enrolled ({dev['device_id']}), {len(obs)} findings sent"


RUN = {"tenant": step_tenant, "agents": step_agents, "shadow": step_shadow, "scan": step_scan,
       "dns": step_dns, "proxy": step_proxy, "laptop": step_laptop}


def dry_run(steps: list[str]) -> None:
    show = {
        "scan": lambda: scan_observations(),
        "proxy": lambda: PROXY_OBSERVATIONS,
        "laptop": lambda: laptop_observations(),
        "dns": lambda: (FIXTURES / "dns.csv").read_text().splitlines(),
    }
    for name in steps:
        print(f"== {name}")
        if name in show:
            for item in show[name]():
                print("  ", item if isinstance(item, str) else json.dumps(item))
        else:
            print("   (calls Shield; nothing to show offline)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--shield-url", help="the data plane, for example http://localhost:8080")
    p.add_argument("--portal-url", default="", help="the admin plane (default: --shield-url)")
    p.add_argument("--api-key", help="the tenant API key")
    p.add_argument("--admin-key", default="", help="SHIELD_ADMIN_KEY, to create the tenant")
    p.add_argument("--tenant", default="acme", help="tenant id to create with --admin-key")
    p.add_argument("--only", default="", help=f"comma list of steps: {', '.join(STEPS)}")
    p.add_argument("--dry-run", action="store_true", help="print what would be sent; no network")
    a = p.parse_args(argv)

    steps = [x.strip() for x in a.only.split(",") if x.strip()] or list(STEPS)
    unknown = [x for x in steps if x not in STEPS]
    if unknown:
        p.error(f"unknown step(s): {', '.join(unknown)}; steps are {', '.join(STEPS)}")
    steps = [x for x in STEPS if x in steps]
    if a.dry_run:
        dry_run(steps)
        return 0
    if not a.shield_url or not a.api_key:
        p.error("--shield-url and --api-key are required (or use --dry-run)")

    s = Shield(a.shield_url, a.portal_url, a.api_key)
    failed = 0
    for name in steps:
        try:
            print(f"[ok]   {name:7} {RUN[name](s, a)}")
        except Skip as e:
            print(f"[skip] {name:7} {e}")
        except StepError as e:
            failed += 1
            print(f"[fail] {name:7} {e}")
    print()
    print(f"Open {s.portal}/tenant, sign in with the tenant key, then AI Assets > AI Inventory.")
    print("Try: filter 'Not governed', block ChatGPT, register the shadow agent.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
