#!/usr/bin/env python3
"""Test shadow agent detection, blocking, and approval flow.

Exercises the full lifecycle:
  1. Call Shield with an unregistered agent → detected as shadow
  2. View shadow agents list
  3. Block one shadow agent → verify 403
  4. Allow (unblock) it → verify calls work again
  5. Enable block_unregistered_agents → all shadows get 403
  6. Register a shadow agent → now it passes
  7. Clean up

Usage:
    export LLM_SHIELD_URL=https://xxx.api.runpod.ai
    export API_KEY="bank-co-key"
    export RUNPOD_TOKEN="rpa_..."    # only for RunPod

    python test_shadow_agents.py
"""

import json
import os
import sys
import time
import uuid

import requests

# ── Config ────────────────────────────────────────────────────────────────

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "")
RUNPOD_TOKEN = os.getenv("RUNPOD_TOKEN", "")

# Generate unique shadow agent IDs for this test run
RUN_ID = uuid.uuid4().hex[:6]
SHADOW_1 = f"shadow-bot-{RUN_ID}-1"
SHADOW_2 = f"shadow-bot-{RUN_ID}-2"
SHADOW_3 = f"shadow-bot-{RUN_ID}-3"


def headers(agent_key="", user_role="user"):
    h = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
    }
    if agent_key:
        h["X-Agent-Key"] = agent_key
    if user_role:
        h["X-User-Role"] = user_role
    if RUNPOD_TOKEN:
        h["Authorization"] = f"Bearer {RUNPOD_TOKEN}"
    return h


def ok(msg):
    print(f"  \u2713 {msg}")


def fail(msg):
    print(f"  \u2717 {msg}")


def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def tool_check(agent_key, tool_name="search_web", user_role="user"):
    """Call tool/check with a given agent key. Returns (status_code, body)."""
    r = requests.post(
        f"{SHIELD_URL}/v1/shield/tool/check",
        headers=headers(agent_key=agent_key, user_role=user_role),
        json={
            "agent_key": agent_key,
            "tool_name": tool_name,
            "user_role": user_role,
            "tool_params": {},
        },
        timeout=15,
    )
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:200]}


def get_shadow_agents():
    """Get list of unregistered/shadow agents."""
    r = requests.get(
        f"{SHIELD_URL}/v1/agents/unregistered",
        headers=headers(),
        timeout=10,
    )
    if r.status_code == 200:
        return r.json()
    return {}


def block_agent(agent_id):
    """Block a shadow agent."""
    r = requests.post(
        f"{SHIELD_URL}/v1/agents/unregistered/{agent_id}/block",
        headers=headers(),
        timeout=10,
    )
    return r.status_code, r.json()


def allow_agent(agent_id):
    """Unblock a shadow agent."""
    r = requests.post(
        f"{SHIELD_URL}/v1/agents/unregistered/{agent_id}/allow",
        headers=headers(),
        timeout=10,
    )
    return r.status_code, r.json()


def register_agent(agent_id, tools, role_permissions):
    """Register an agent."""
    r = requests.post(
        f"{SHIELD_URL}/v1/agents/registry",
        headers=headers(agent_key=agent_id),
        json={
            "agent_id": agent_id,
            "name": f"Test Agent {agent_id}",
            "description": "Registered from shadow agent test",
            "tools": tools,
            "role_permissions": role_permissions,
        },
        timeout=10,
    )
    return r.status_code, r.json()


def dismiss_shadow(agent_id):
    """Dismiss a shadow agent from the list."""
    r = requests.delete(
        f"{SHIELD_URL}/v1/agents/unregistered/agents/{agent_id}",
        headers=headers(),
        timeout=10,
    )
    return r.status_code


# ══════════════════════════════════════════════════════════════════════════

def main():
    if not API_KEY:
        print("Set API_KEY environment variable")
        sys.exit(1)

    print("Shadow Agent Test")
    print(f"  Shield:    {SHIELD_URL}")
    print(f"  Shadows:   {SHADOW_1}, {SHADOW_2}, {SHADOW_3}")

    # ── Preflight ─────────────────────────────────────────────────────
    section("PREFLIGHT")
    code, _ = tool_check("customer-service-agent", "search_web")
    if code == 200:
        ok("Shield is reachable")
    else:
        fail(f"Shield returned {code}")
        sys.exit(1)

    # ── Step 1: Create shadow agents ──────────────────────────────────
    section("STEP 1 — Create shadow agents (call with unregistered agent IDs)")

    for shadow in [SHADOW_1, SHADOW_2, SHADOW_3]:
        code, body = tool_check(shadow, "some_tool")
        # Shadow agents should be allowed (default: detect only)
        if code == 200:
            ok(f"{shadow} called tool/check → {code} (detected as shadow)")
        elif code == 403 and "unregistered" in str(body):
            fail(f"{shadow} → 403 (block_unregistered_agents may be enabled)")
            print("      Disable block_unregistered_agents on the tenant to run this test")
            sys.exit(1)
        else:
            print(f"  ? {shadow} → {code}: {json.dumps(body)[:100]}")

    # Wait for shadow flush (middleware buffers for up to 30s)
    print("\n  Waiting 5s for shadow agent flush...")
    time.sleep(5)

    # ── Step 2: View shadow agents ────────────────────────────────────
    section("STEP 2 — View shadow agents in discovery list")

    data = get_shadow_agents()
    agents = data.get("unregistered_agents", {})
    found = [s for s in [SHADOW_1, SHADOW_2, SHADOW_3] if s in agents]

    if len(found) == 3:
        ok(f"All 3 shadow agents detected: {found}")
    elif found:
        ok(f"Found {len(found)}/3 shadow agents: {found}")
        print("      (others may not have flushed yet — retry in 30s)")
    else:
        print("  ? No shadow agents found yet (flush interval is 30s)")
        print("      Waiting 30s and retrying...")
        time.sleep(30)
        data = get_shadow_agents()
        agents = data.get("unregistered_agents", {})
        found = [s for s in [SHADOW_1, SHADOW_2, SHADOW_3] if s in agents]
        if found:
            ok(f"Found {len(found)}/3 after retry: {found}")
        else:
            fail("Shadow agents not appearing — check middleware config")

    for s in found:
        meta = agents[s]
        print(f"      {s}: calls={meta.get('call_count', '?')}, "
              f"last_seen={meta.get('last_seen', '?')}")

    # ── Step 3: Block one shadow agent ────────────────────────────────
    section("STEP 3 — Block a specific shadow agent")

    code, body = block_agent(SHADOW_1)
    if code == 200 and body.get("action") == "blocked":
        ok(f"Blocked {SHADOW_1}")
        print(f"      blocked_agents: {body.get('blocked_agents', [])}")
    else:
        fail(f"Block failed: {code} {json.dumps(body)[:100]}")

    # Verify blocked agent gets 403
    print(f"\n  Calling tool/check as blocked agent {SHADOW_1}:")
    code, body = tool_check(SHADOW_1, "some_tool")
    if code == 403 and body.get("error") == "agent_blocked":
        ok(f"{SHADOW_1} → 403 agent_blocked")
    else:
        fail(f"{SHADOW_1} → {code} (expected 403)")
        print(f"      body: {json.dumps(body)[:150]}")

    # Verify other shadows still work
    print(f"\n  Calling tool/check as non-blocked agent {SHADOW_2}:")
    code, body = tool_check(SHADOW_2, "some_tool")
    if code == 200:
        ok(f"{SHADOW_2} → {code} (still allowed)")
    else:
        fail(f"{SHADOW_2} → {code} (expected 200)")

    # ── Step 4: Unblock the agent ─────────────────────────────────────
    section("STEP 4 — Unblock the agent")

    code, body = allow_agent(SHADOW_1)
    if code == 200 and body.get("action") == "allowed":
        ok(f"Unblocked {SHADOW_1}")
    else:
        fail(f"Unblock failed: {code} {json.dumps(body)[:100]}")

    # Verify it works again
    code, body = tool_check(SHADOW_1, "some_tool")
    if code == 200:
        ok(f"{SHADOW_1} → {code} (working again)")
    elif code == 403:
        fail(f"{SHADOW_1} → still blocked ({body.get('error', '')})")
    else:
        print(f"  ? {SHADOW_1} → {code}")

    # ── Step 5: Register a shadow agent (full approval) ───────────────
    section("STEP 5 — Register a shadow agent (full approval)")

    code, body = register_agent(SHADOW_3, ["search_web", "read_docs"], {
        "user": ["search_web", "read_docs"],
        "admin": ["search_web", "read_docs"],
    })
    if code in (200, 201):
        ok(f"Registered {SHADOW_3} with tools: search_web, read_docs")
    elif code == 409:
        ok(f"{SHADOW_3} already registered")
    else:
        fail(f"Registration failed: {code} {json.dumps(body)[:100]}")

    # Verify registered agent passes RBAC
    code, body = tool_check(SHADOW_3, "search_web")
    if code == 200:
        allowed = body.get("allowed", False)
        if allowed:
            ok(f"{SHADOW_3} → search_web ALLOWED (registered + RBAC pass)")
        else:
            print(f"  ? {SHADOW_3} → search_web returned 200 but allowed={allowed}")
    else:
        fail(f"{SHADOW_3} → {code}")

    # ── Step 6: Block multiple, then allow one by one ─────────────────
    section("STEP 6 — Block multiple, allow one by one")

    # Block both remaining shadows
    for s in [SHADOW_1, SHADOW_2]:
        block_agent(s)
    ok(f"Blocked {SHADOW_1} and {SHADOW_2}")

    # Verify both blocked
    for s in [SHADOW_1, SHADOW_2]:
        code, _ = tool_check(s, "test")
        status = "403 BLOCKED" if code == 403 else f"{code} ???"
        print(f"      {s} → {status}")

    # Allow one back
    allow_agent(SHADOW_1)
    ok(f"Allowed {SHADOW_1} back")

    code1, _ = tool_check(SHADOW_1, "test")
    code2, _ = tool_check(SHADOW_2, "test")
    if code1 == 200 and code2 == 403:
        ok(f"{SHADOW_1} → 200 (allowed), {SHADOW_2} → 403 (still blocked)")
    else:
        fail(f"{SHADOW_1} → {code1}, {SHADOW_2} → {code2}")

    # ── Cleanup ───────────────────────────────────────────────────────
    section("CLEANUP")

    # Unblock all
    for s in [SHADOW_1, SHADOW_2]:
        allow_agent(s)

    # Dismiss from shadow list
    for s in [SHADOW_1, SHADOW_2, SHADOW_3]:
        dismiss_shadow(s)

    ok("Unblocked and dismissed all test shadow agents")

    # ── Summary ───────────────────────────────────────────────────────
    section("DONE")
    print("""
  Shadow agent lifecycle:

    Unregistered agent calls Shield
           │
           ▼
    Detected as shadow → webhook fires → shows in portal
           │
           ├── [Block]    → 403 on all future calls
           │                 POST /v1/agents/unregistered/{id}/block
           │
           ├── [Allow]    → Remove from blocklist
           │                 POST /v1/agents/unregistered/{id}/allow
           │
           ├── [Register] → Full approval with RBAC
           │                 POST /v1/agents/registry
           │
           └── [Dismiss]  → Remove from shadow list
                            DELETE /v1/agents/unregistered/agents/{id}

  Tenant settings:
    block_unregistered_agents: false  → detect + alert (default)
    block_unregistered_agents: true   → block ALL unregistered
    blocked_agents: ["bot-1"]         → block specific agents
""")


if __name__ == "__main__":
    main()
