"""Customer demo — three things Shield does for MCP, one script.

  PART 1  Pre-flight scan     audit an MCP server BEFORE you connect it
  PART 2  Secret vault        keep credentials out of the LLM/agent path
  PART 3  Output DLP          redact PII from tool results, per role

Parts 1 and 2 run on any laptop with NO Shield deployment (Part 1 shells out to
`shield-mcp scan`; Part 2 drives Shield's real vault core in-process with a demo
key). Part 3 makes one HTTP hop through a deployed Shield gateway to show output
DLP on live model-backed redaction, and skips itself cleanly if you have not
pointed it at a Shield data plane.

    cd examples/mcp_gateway
    pip install -r requirements.txt          # mcp + repo deps (Part 2 imports core/)

    # Parts 1 + 2 only (no Shield needed):
    python customer_demo.py

    # Add Part 3 (output DLP) against your Shield:
    export SHIELD_URL=https://api.guardrails.votal.ai   # your data plane
    export TENANT_KEY=sk-...                             # your tenant key
    export UPSTREAM_URL=http://localhost:9200/mcp        # reachable FROM the gateway
    python customer_demo.py
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ── repo root on sys.path so Part 2 can import Shield's real vault core ─────────
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Enable the vault in software-key mode BEFORE importing core (Part 2). This is a
# throwaway demo KEK; production uses a real software KEK or HashiCorp Vault Transit.
os.environ.setdefault("SECRET_VAULT_ENABLED", "true")
os.environ.setdefault("SECRET_VAULT_KEY_PROVIDER", "software")
os.environ.setdefault(
    "SECRET_VAULT_KEK",
    base64.b64encode(b"customer-demo-kek-customer-demo-").decode(),  # 32 bytes
)

SHIELD = os.environ.get("SHIELD_URL", "").rstrip("/")
TENANT_KEY = os.environ.get("TENANT_KEY", "")
UPSTREAM = os.environ.get("UPSTREAM_URL", "http://localhost:9200/mcp")
UPSTREAM_HOST = "localhost:9200"
AGENT = "customer-demo-agent"
ROUTE = "partner"
HERE = Path(__file__).resolve().parent


def hr(title: str) -> None:
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


# ─────────────────────────────────────────────────────────────────────────────
# Upstream lifecycle: an UNMODIFIED sample MCP server (customer_demo_upstream.py)
# ─────────────────────────────────────────────────────────────────────────────
def start_upstream():
    """Launch the sample upstream over streamable-HTTP on :9200; return the proc."""
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "customer_demo_upstream.py")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # wait for the port to answer
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://{UPSTREAM_HOST}/mcp", timeout=1)
        except urllib.error.HTTPError:
            return proc  # any HTTP response means it's up
        except Exception:
            time.sleep(0.25)
    return proc


def scanner_cmd():
    """Locate the shield-mcp CLI (pip/pipx install shield-mcp, or npx @votal/mcp-scan)."""
    exe = shutil.which("shield-mcp") or str(Path(sys.executable).parent / "shield-mcp")
    return [exe] if Path(exe).exists() else None


# ─────────────────────────────────────────────────────────────────────────────
# PART 1 — Pre-flight scan (npm-audit for MCP). No Shield deployment needed.
# ─────────────────────────────────────────────────────────────────────────────
def part1_preflight_scan():
    hr("PART 1 — Pre-flight scan: audit the MCP server BEFORE you connect it")
    cmd = scanner_cmd()
    if not cmd:
        print("  (skipped) shield-mcp CLI not found. Install it with one of:")
        print("      pipx install shield-mcp        # Python")
        print("      npx @votal/mcp-scan <target>   # Node")
        return
    target = f"http:http://{UPSTREAM_HOST}/mcp"
    print(f"  $ shield-mcp scan {target}\n")
    # exit code: 0 clean, 2 gating findings, 3 unreachable — we don't fail the demo on 2
    res = subprocess.run(cmd + ["scan", target], capture_output=True, text=True)
    print(res.stdout.strip() or res.stderr.strip())
    print("\n  -> The scanner reads only tool/resource/prompt METADATA. It flags the")
    print("     poisoned descriptions and the over-broad `run_shell` tool before an")
    print("     agent ever calls them. Gate CI on this (exit code 2 = findings).")


# ─────────────────────────────────────────────────────────────────────────────
# PART 2 — Secret vault. Runs Shield's real vault core in-process (no deployment).
# ─────────────────────────────────────────────────────────────────────────────
def part2_secret_vault():
    hr("PART 2 — Secret vault: keep the credential out of the LLM/agent path")
    from storage.vault_store import create_vault_entry, delete_vault_entry
    from core.secret_vault.materialize import materialize_obj, retokenize

    tenant = "customer-demo-tenant"
    REAL_KEY = "sk-partner-LIVE-9f3ab204"

    # Register the secret, BOUND to exactly one tool. The developer/agent only ever
    # holds the placeholder `shield://partner_key` — never the real value.
    delete_vault_entry(tenant, "partner_key")  # idempotent re-run
    entry = create_vault_entry(
        tenant, "partner_key", REAL_KEY,
        bindings=["call_partner_api"],   # for MCP, the destination IS the tool name
        tool_ids=["call_partner_api"],   # tier-1: only this tool may use it
    )
    print(f"  registered secret: ref=shield://{entry['ref']}  token={entry['token']}")
    print(f"  bound to tool(s): {entry['bindings']}   (real value is never returned)\n")

    placeholder = "shield://partner_key"
    print(f"  the agent passes only the placeholder:  {placeholder!r}\n")

    # (a) legit tool -> materialized to the real key on the hop to the upstream
    legit = materialize_obj(tenant, {"api_key": placeholder}, "call_partner_api",
                            tool_id="call_partner_api")
    print(f"  [call_partner_api]  arg the UPSTREAM receives -> {legit}")
    print("     the bound tool gets the REAL key at the last hop.\n")

    # (b) any other tool (e.g. an exfil sink / injected call) -> stays inert
    exfil = materialize_obj(tenant, {"api_key": placeholder}, "send_to_pastebin",
                            tool_id="send_to_pastebin")
    print(f"  [send_to_pastebin]  arg the UPSTREAM receives -> {exfil}")
    print("     a DIFFERENT destination gets only the inert placeholder — the")
    print("     confused-deputy / exfiltration control (key never leaves for pastebin).\n")

    # (c) if a tool result ever echoes the real value, it is scrubbed before the model
    echoed = retokenize(tenant, {"log": f"authenticated with {REAL_KEY} at 10:01"})
    print(f"  [output re-tokenize] tool echoed the key -> model sees -> {echoed}")

    delete_vault_entry(tenant, "partner_key")
    print("\n  -> Same materialize/retokenize runs INSIDE the gateway on every")
    print("     tools/call. The LLM context never contains the real credential.")


# ─────────────────────────────────────────────────────────────────────────────
# PART 3 — Output DLP through the gateway. Needs SHIELD_URL + TENANT_KEY.
# ─────────────────────────────────────────────────────────────────────────────
def _is_local(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def _is_remote(url: str) -> bool:
    return bool(urllib.parse.urlsplit(url).hostname) and not _is_local(url)


def _admin(method, path, body):
    data = json.dumps(body).encode()
    h = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY}
    req = urllib.request.Request(f"{SHIELD}{path}", data, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")
    except Exception as e:
        return 0, {"error": str(e)}


def _mcp(role, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    h = {"Content-Type": "application/json", "X-API-Key": TENANT_KEY,
         "X-Agent-Key": AGENT, "X-User-Role": role}
    req = urllib.request.Request(f"{SHIELD}/gateway/{ROUTE}/mcp",
                                 json.dumps(body).encode(), h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": {"code": e.code, "message": e.read().decode()[:200]}}
    except Exception as e:
        return {"error": {"message": str(e)}}


def part3_output_dlp():
    hr("PART 3 — Output DLP: redact PII from tool results (needs your Shield)")
    if not SHIELD or not TENANT_KEY:
        print("  (skipped) set SHIELD_URL + TENANT_KEY to run live output DLP.")
        print("  This is the one part that needs a deployed Shield: redaction is")
        print("  model-backed and runs on the data plane, not on your laptop.")
        return

    # Reachability guard — the #1 live-demo failure. A REMOTE gateway (e.g.
    # api.guardrails.votal.ai) connects to the upstream from the cloud and cannot
    # reach your laptop's localhost. Catch that here with an actionable fix rather
    # than letting the tools/call fail later with an opaque -32603 transport error.
    if _is_remote(SHIELD) and _is_local(UPSTREAM):
        print(f"  (skipped) SHIELD_URL is remote ({SHIELD})")
        print(f"            but UPSTREAM_URL is local ({UPSTREAM}).")
        print("  The cloud gateway can't reach your laptop. Expose the upstream first:")
        print("      ngrok http 9200        # -> https://<id>.ngrok-free.app")
        print("      export UPSTREAM_URL=https://<id>.ngrok-free.app/mcp")
        print("  ...then re-run. (Or deploy the upstream — see RAILWAY.md.)")
        return

    # sanity: is the gateway present on this deployment?
    probe = urllib.request.Request(f"{SHIELD}/gateway/_probe/mcp",
                                   b"{}", {"X-API-Key": TENANT_KEY})
    try:
        urllib.request.urlopen(probe, timeout=10)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"  (skipped) gateway not deployed at {SHIELD} (probe -> 404).")
            print("  Deploy a build with the MCP gateway, then re-run.")
            return
    except Exception as e:
        print(f"  (skipped) {SHIELD} unreachable: {e}")
        return

    code, _ = _admin("POST", "/v1/agents/registry", {
        "agent_id": AGENT,
        "tools": ["account_details", "call_partner_api"],
        "role_permissions": {
            "support": ["account_details"],
            "admin": ["account_details", "call_partner_api"],
        },
    })
    print(f"  register agent -> {code}")
    code, resp = _admin("PUT", f"/v1/tenant/me/mcp-gateway/upstreams/{ROUTE}", {
        "transport": "http", "url": UPSTREAM,
        "enforcement_backend": "inprocess", "isolation_ack": True,
    })
    print(f"  configure route {ROUTE} -> {UPSTREAM} -> {code}")
    if code >= 400:
        print(f"  (skipped) route config failed: {resp}")
        return

    print("\n  The upstream's account_details returns  owner / SSN / email / balance.")
    print("  We call the SAME tool as two roles and let Shield's data policy decide")
    print("  what each one is allowed to see, on the way OUT (before the model):\n")
    for role in ("support", "admin"):
        r = _mcp(role, "tools/call",
                 {"name": "account_details", "arguments": {"account_id": "acct_1001"}})
        print(f"  [{role}] {_describe_dlp(r, 'acct_1001')}")
    print("\n  -> Same policy the portal shows: withhold vs. mask vs. full record, per")
    print("     role, on an UNMODIFIED upstream. Tune each role's policy in the portal.")


def _describe_dlp(resp: dict, account_id: str) -> str:
    """Narrate a gateway tools/call outcome as the actual DLP decision, whatever it is:
    RBAC-blocked, output withheld, redacted/masked, or the full record."""
    err = resp.get("error")
    if err:  # transport / JSON-RPC error (e.g. RBAC block -> -32000)
        msg = (err.get("message") or "").strip()
        low = msg.lower()
        if "not allowed" in low or "rbac" in low or err.get("code") == -32000:
            return f"RBAC: not permitted to call this tool -> {msg[:120]}"
        return f"error -> {msg[:140]}"
    result = resp.get("result") or {}
    text = ""
    for block in result.get("content", []):
        if block.get("type") == "text":
            text += block.get("text", "")
    if result.get("isError") or "blocked by shield" in text.lower():
        return f"WITHHELD (output blocked by data policy) -> {text.strip()[:120]}"
    # Some real value came back — did the sensitive fields survive?
    masked = ("123-45-6789" not in text) or ("jane.doe@example.com" not in text)
    tag = "MASKED (SSN/email redacted)" if masked else "FULL RECORD (no redaction)"
    return f"{tag} -> {text.strip()[:160]}"


def main():
    print("Shield × MCP — customer demo (scan · vault · output DLP)")
    up = start_upstream()
    try:
        part1_preflight_scan()
        part2_secret_vault()
        part3_output_dlp()
    finally:
        up.terminate()
    print("\nDone.")


if __name__ == "__main__":
    main()
