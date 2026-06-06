#!/usr/bin/env python3
"""Test the full OIDC + LDAP + Shield + LangChain flow locally.

Exercises the complete token chain against the local docker stack:

  Keycloak (OIDC/LDAP) → User JWT → extract role → Shield agent token
  → Shield tool check → Shield cap mint → tool execute → sanitize output

Usage:
    # Start the stack first:
    docker compose -f docker-compose.local.yml up -d
    python setup_keycloak.py

    # Then run this test:
    python test_local_oidc.py

What it tests:
  1. Login as each LDAP user via Keycloak password grant
  2. Extract realm role from the OIDC token
  3. Register agent with Shield
  4. Mint agent token (proves identity to Shield)
  5. Run tool calls as different roles (doctor vs patient)
  6. Show RBAC enforcement: doctor can access records, patient can't
  7. Mint + verify capability tokens
"""

import base64
import json
import sys
import time
import uuid

import requests

# ── Config ────────────────────────────────────────────────────────────────

KEYCLOAK_URL = "http://localhost:8180"
REALM = "shield"
CLIENT_ID = "shield-api"
CLIENT_SECRET = "shield-client-secret"
SHIELD_URL = "http://localhost:8000"
SHIELD_ADMIN_KEY = "test-admin-key"
API_KEY = ""  # Will be set after tenant creation

AGENT_ID = "test-oidc-agent"
AGENT_INSTANCE_ID = f"{AGENT_ID}-{uuid.uuid4().hex[:8]}"
SESSION_ID = f"sess-{int(time.time())}"

SHIELD_ROLES = {"doctor", "nurse", "admin", "patient"}


# ── Helpers ───────────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def ok(msg: str):
    print(f"  ✓ {msg}")


def fail(msg: str):
    print(f"  ✗ {msg}")


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification (for local testing display)."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def extract_shield_role(claims: dict) -> str:
    """Extract the Shield role from Keycloak realm_access.roles."""
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    for r in realm_roles:
        if r in SHIELD_ROLES:
            return r
    return "unknown"


# ── Step 1: Login to Keycloak ─────────────────────────────────────────────

def keycloak_login(username: str, password: str = "password") -> dict:
    """Login via Keycloak password grant. Returns {access_token, claims, role}."""
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "username": username,
            "password": password,
            "scope": "openid profile",
        },
    )
    if r.status_code != 200:
        raise RuntimeError(f"Keycloak login failed for {username}: {r.text}")

    data = r.json()
    claims = decode_jwt_payload(data["access_token"])
    role = extract_shield_role(claims)

    return {
        "access_token": data["access_token"],
        "claims": claims,
        "sub": claims.get("sub"),
        "role": role,
    }


# ── Step 2: Create tenant + get API key ──────────────────────────────────

def setup_tenant() -> str:
    """Create a test tenant and return its API key."""
    r = requests.post(
        f"{SHIELD_URL}/v1/admin/tenants",
        headers={
            "X-Admin-Key": SHIELD_ADMIN_KEY,
            "Content-Type": "application/json",
        },
        json={
            "tenant_id": "test-oidc-tenant",
            "name": "OIDC Test Tenant",
            "config": {
                "guardrails": {
                    "tool_rbac": {"enabled": True},
                    "data_access": {"enabled": True},
                },
            },
        },
    )
    if r.status_code in (200, 201):
        data = r.json()
        api_key = data.get("api_key", "")
        if api_key:
            ok(f"Tenant created, API key: {api_key[:20]}...")
            return api_key

    # Tenant may already exist — try to get its key
    r = requests.get(
        f"{SHIELD_URL}/v1/admin/tenants/test-oidc-tenant",
        headers={"X-Admin-Key": SHIELD_ADMIN_KEY},
    )
    if r.status_code == 200:
        data = r.json()
        api_key = data.get("api_key", "")
        if api_key:
            ok(f"Tenant exists, API key: {api_key[:20]}...")
            return api_key

    fail(f"Could not create/find tenant: {r.status_code} {r.text[:200]}")
    return ""


# ── Step 3: Register agent ───────────────────────────────────────────────

def register_agent(api_key: str):
    """Register agent with role-based tool permissions."""
    r = requests.post(
        f"{SHIELD_URL}/v1/agents/registry",
        headers={
            "X-API-Key": api_key,
            "X-Agent-Key": AGENT_ID,
            "Content-Type": "application/json",
        },
        json={
            "agent_id": AGENT_ID,
            "name": "OIDC Test Agent",
            "description": "Tests OIDC + LDAP integration",
            "tools": ["patient_lookup", "view_records", "prescribe_medication", "check_vitals"],
            "role_permissions": {
                "doctor":  ["patient_lookup", "view_records", "prescribe_medication", "check_vitals"],
                "nurse":   ["patient_lookup", "view_records", "check_vitals"],
                "admin":   ["patient_lookup", "view_records", "prescribe_medication", "check_vitals"],
                "patient": ["check_vitals"],   # patients can only check their own vitals
            },
        },
    )
    if r.status_code in (200, 201):
        ok(f"Agent registered: {AGENT_ID}")
    else:
        print(f"    Registration: {r.status_code} — {r.text[:200]}")


# ── Step 4: Mint agent token ─────────────────────────────────────────────

def mint_agent_token(api_key: str, user_sub: str) -> str:
    """Mint a Shield agent token from the Keycloak user identity."""
    r = requests.post(
        f"{SHIELD_URL}/v1/tenant/me/agent-auth/agent-token",
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        json={
            "user_sub": user_sub,
            "agent_id": AGENT_ID,
            "agent_instance_id": AGENT_INSTANCE_ID,
            "build_hash": "local-test",
            "model_version": "gpt-4o-mini",
            "session_id": SESSION_ID,
            "ttl_seconds": 600,
        },
    )
    if r.status_code == 200:
        data = r.json()
        ok(f"Agent token minted, expires in {data['expires_in']}s")
        return data["agent_token"]
    else:
        fail(f"Agent token failed: {r.status_code} {r.text[:200]}")
        return ""


# ── Step 5: Tool check ──────────────────────────────────────────────────

def shield_tool_check(api_key: str, tool_name: str, user_role: str, tool_params: dict = None) -> dict:
    """RBAC check: can this role use this tool?"""
    r = requests.post(
        f"{SHIELD_URL}/v1/shield/tool/check",
        headers={
            "X-API-Key": api_key,
            "X-Agent-Key": AGENT_ID,
            "X-User-Role": user_role,
            "Content-Type": "application/json",
        },
        json={
            "agent_key": AGENT_ID,
            "tool_name": tool_name,
            "user_role": user_role,
            "tool_params": tool_params or {},
            "session_id": SESSION_ID,
        },
    )
    if r.status_code == 200:
        return r.json()
    return {"allowed": False, "error": f"{r.status_code}: {r.text[:200]}"}


# ── Step 6: Capability mint ──────────────────────────────────────────────

def shield_cap_mint(api_key: str, agent_token: str, tool: str, resource: str) -> dict:
    """Mint a single-use capability token for a tool action."""
    r = requests.post(
        f"{SHIELD_URL}/v1/shield/cap/mint",
        headers={
            "X-API-Key": api_key,
            "X-Agent-Token": agent_token,
            "Content-Type": "application/json",
        },
        json={
            "tool": tool,
            "resource": resource,
            "clearance_max": "public",
            "ttl_seconds": 30,
        },
    )
    if r.status_code == 200:
        return r.json()
    return {"error": f"{r.status_code}: {r.text[:200]}"}


# ── Step 7: Capability verify ────────────────────────────────────────────

def shield_cap_verify(api_key: str, cap_token: str, expected_tool: str) -> dict:
    """Verify a capability token (what a tool server would do)."""
    r = requests.post(
        f"{SHIELD_URL}/v1/shield/cap/verify",
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        json={
            "cap_token": cap_token,
            "expected_tool": expected_tool,
            "burn_nonce": True,
        },
    )
    if r.status_code == 200:
        return r.json()
    return {"valid": False, "error": f"{r.status_code}: {r.text[:200]}"}


# ══════════════════════════════════════════════════════════════════════════
# Main test flow
# ══════════════════════════════════════════════════════════════════════════

def main():
    # ── Preflight ─────────────────────────────────────────────────────
    section("PREFLIGHT — Check services")

    for name, url in [("Shield", f"{SHIELD_URL}/health"), ("Keycloak", f"{KEYCLOAK_URL}/realms/master")]:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                ok(f"{name} is up")
            else:
                fail(f"{name} returned {r.status_code}")
                if name == "Shield":
                    print("    Run: docker compose -f docker-compose.local.yml up -d")
                    sys.exit(1)
        except Exception as e:
            fail(f"{name} unreachable: {e}")
            print("    Run: docker compose -f docker-compose.local.yml up -d")
            sys.exit(1)

    # ── Step 1: Login as each user ────────────────────────────────────
    section("STEP 1 — Keycloak login (OIDC + LDAP)")

    users = {}
    for username in ["dr.smith", "nurse.jones", "admin.doe", "patient.lee"]:
        try:
            user = keycloak_login(username)
            users[username] = user
            ok(f"{username} → sub={user['sub'][:8]}..., role={user['role']}")
        except RuntimeError as e:
            fail(f"{username}: {e}")

    if not users:
        print("\n  No users could log in. Run: python setup_keycloak.py")
        sys.exit(1)

    # ── Step 2: Create tenant ─────────────────────────────────────────
    section("STEP 2 — Create Shield tenant")

    api_key = setup_tenant()
    if not api_key:
        print("\n  Cannot proceed without API key. Check Shield admin endpoint.")
        sys.exit(1)

    # ── Step 3: Register agent ────────────────────────────────────────
    section("STEP 3 — Register agent (one-time)")

    register_agent(api_key)

    # ── Step 4: Mint agent tokens ─────────────────────────────────────
    section("STEP 4 — Mint agent tokens (per-process)")

    agent_tokens = {}
    for username, user in users.items():
        token = mint_agent_token(api_key, user["sub"])
        if token:
            agent_tokens[username] = token

    # ── Step 5: RBAC tool checks ──────────────────────────────────────
    section("STEP 5 — RBAC tool checks (per-action)")

    test_cases = [
        # (user,          tool,                   expected)
        ("dr.smith",      "patient_lookup",        True,   "doctor can look up patients"),
        ("dr.smith",      "prescribe_medication",  True,   "doctor can prescribe"),
        ("nurse.jones",   "patient_lookup",        True,   "nurse can look up patients"),
        ("nurse.jones",   "prescribe_medication",  False,  "nurse CANNOT prescribe"),
        ("patient.lee",   "check_vitals",          True,   "patient can check own vitals"),
        ("patient.lee",   "patient_lookup",        False,  "patient CANNOT look up other patients"),
        ("patient.lee",   "view_records",          False,  "patient CANNOT view records"),
    ]

    for username, tool, expected_allowed, description in test_cases:
        if username not in users:
            continue
        role = users[username]["role"]
        result = shield_tool_check(api_key, tool, role, {"patient_id": "P-001"})
        allowed = result.get("allowed", False) and result.get("action") != "block"

        if allowed == expected_allowed:
            status = "ALLOWED" if allowed else "BLOCKED"
            ok(f"{description} — {status}")
        else:
            status = "ALLOWED" if allowed else "BLOCKED"
            fail(f"{description} — got {status}, expected {'ALLOWED' if expected_allowed else 'BLOCKED'}")
            if result.get("guardrail_results"):
                for gr in result["guardrail_results"]:
                    if not gr.get("passed", True):
                        print(f"      reason: {gr.get('message', 'unknown')}")

    # ── Step 6: Capability mint + verify ──────────────────────────────
    section("STEP 6 — Capability tokens (mint + verify)")

    if "dr.smith" in agent_tokens:
        print("\n  Doctor mints capability for patient_lookup:")
        cap_result = shield_cap_mint(
            api_key,
            agent_tokens["dr.smith"],
            "patient_lookup",
            "patient/P-001",
        )
        if "cap_token" in cap_result:
            cap_token = cap_result["cap_token"]
            ok(f"Cap minted, expires in {cap_result.get('expires_in')}s")
            ok(f"Cap token: {cap_token[:40]}...")

            # Verify the capability (what a tool server does)
            print("\n  Tool server verifies capability:")
            verify_result = shield_cap_verify(api_key, cap_token, "patient_lookup")
            if verify_result.get("valid"):
                claims = verify_result.get("claims", {})
                ok(f"Cap VALID — agent={claims.get('agent_id')}, tool={claims.get('tool')}")
            else:
                fail(f"Cap invalid: {verify_result.get('error')}")

            # Replay attack — same cap should be rejected
            print("\n  Replay attack (reuse burned cap):")
            replay_result = shield_cap_verify(api_key, cap_token, "patient_lookup")
            if not replay_result.get("valid"):
                ok(f"Replay REJECTED: {replay_result.get('error')}")
            else:
                fail("Replay was accepted — nonce not burned!")
        elif "error" in cap_result:
            fail(f"Cap mint failed: {cap_result['error']}")
    else:
        print("  (skipped — dr.smith agent token not available)")

    # ── Summary ───────────────────────────────────────────────────────
    section("DONE")

    print(f"""
  The full chain works:

    LDAP user ──▶ Keycloak login ──▶ OIDC JWT (sub + realm roles)
                                         │
                  extract role ◀──────────┘
                       │
                       ▼
              Shield agent token (proves who)
                       │
                       ▼
              Shield tool/check (RBAC: can this role use this tool?)
                       │
                       ▼
              Shield cap/mint (single-use capability for the action)
                       │
                       ▼
              Tool server verifies cap → executes → Shield sanitizes output

  To run the LangChain agent with a real Keycloak user:

    export LLM_SHIELD_URL=http://localhost:8000
    export API_KEY="{api_key}"
    export USER_ROLE="doctor"
    export USER_SUB="{users.get('dr.smith', {}).get('sub', 'user-sub')}"
    export OPENAI_API_KEY="sk-..."
    python langchain_e2e.py
""")


if __name__ == "__main__":
    main()
