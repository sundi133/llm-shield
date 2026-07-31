#!/usr/bin/env python3
"""Configure Keycloak realm, LDAP federation, roles, and client for Shield.

Run AFTER docker compose is up:
    python setup_keycloak.py

This script:
  1. Creates the "shield" realm
  2. Adds realm roles: doctor, nurse, admin, patient
  3. Creates OIDC client "shield-api" (confidential, direct-access enabled)
  4. Connects LDAP federation to OpenLDAP
  5. Syncs LDAP users into Keycloak
  6. Assigns roles to users (dr.smith→doctor, nurse.jones→nurse, etc.)
  7. Prints a test token for each user

Requires: pip install requests
"""

import json
import sys
import time
import requests

KC_URL = "http://localhost:8180"
KC_ADMIN = "admin"
KC_ADMIN_PASS = "admin"
REALM = "shield"
CLIENT_ID = "shield-api"
CLIENT_SECRET = "shield-client-secret"  # fixed for local testing
PUBLIC_CLIENT_ID = "demo-cli"           # public: CLI demos have nowhere to keep a secret
# Must equal SHIELD_WORKLOAD_OIDC_AUDIENCE on the verifying plane, or the token
# is refused. Shield treats a missing audience as fatal rather than optional.
AUDIENCE = "votal-shield"

LDAP_URL = "ldap://openldap:389"  # Keycloak resolves this via docker network
LDAP_BIND_DN = "cn=admin,dc=shield,dc=local"
LDAP_BIND_PASS = "adminpassword"
LDAP_BASE_DN = "dc=shield,dc=local"

# These MUST match the role names in the Shield agent's role_permissions. A
# verified claim only means something if the policy knows the role: a token
# asserting a role Shield has never heard of resolves to no grants, which looks
# exactly like role binding being broken.
#
# Mirrors the `test-oidc-agent` registry entry (tools: patient_lookup,
# view_records, prescribe_medication, check_vitals).
ROLES = ["doctor", "nurse", "admin", "patient",
         # SRE copilot demo (examples/langchain/interactive_demo_sre.py)
         "sre_lead", "oncall_engineer", "contractor", "ci_bot", "intern"]

# Created directly in Keycloak rather than via LDAP: the healthcare personas
# come from OpenLDAP, but these exist only for the demo and adding LDAP entries
# for them buys nothing. Same password as the others so one instruction covers
# every login.
SRE_USERS = {
    "alex.chen":  ("sre_lead", "Alex", "Chen"),
    "sam.patel":  ("oncall_engineer", "Sam", "Patel"),
    "jordan.ext": ("contractor", "Jordan", "Ext"),
    "riley.grad": ("intern", "Riley", "Grad"),
    # No human behind this one — that is the point of demoing it. It cannot be
    # phished and cannot be MFA'd, so role scoping is the only control it has.
    "ci-bot":     ("ci_bot", "CI", "Bot"),
}

# Usernames are healthcare personas, so the roles are too. They previously mapped
# to banking roles (branch_manager, compliance_officer, ...) left over from a
# different demo — names that matched neither the users nor Shield's config.
USER_ROLES = {
    # Grants as the tenant registry actually has them, probed rather than
    # assumed. Shield is the authority here; these comments are a convenience
    # and will drift if the registry changes.
    "dr.smith":    "doctor",    # patient_lookup, check_vitals, prescribe_medication
    "nurse.jones": "nurse",     # check_vitals only
    "admin.doe":   "admin",     # patient_lookup, view_records, check_vitals
    "patient.lee": "patient",   # check_vitals only
    # NB: view_records is admin-only — not even doctor has it. If that is not
    # what you intended, fix the registry, not this comment.
}


def wait_for_keycloak():
    print("Waiting for Keycloak to be ready...", end="", flush=True)
    for _ in range(60):
        try:
            # Dev mode doesn't expose /health — check the master realm endpoint
            r = requests.get(f"{KC_URL}/realms/master", timeout=3)
            if r.status_code == 200:
                print(" ready!")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(2)
    print("\nERROR: Keycloak not ready after 2 minutes")
    sys.exit(1)


def get_admin_token() -> str:
    r = requests.post(f"{KC_URL}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "client_credentials",
        "client_id": "admin-cli",
        "username": KC_ADMIN,
        "password": KC_ADMIN_PASS,
        "grant_type": "password",
    })
    r.raise_for_status()
    return r.json()["access_token"]


def admin_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_realm(token: str):
    print("Creating realm 'shield'...")
    r = requests.post(f"{KC_URL}/admin/realms", headers=admin_headers(token), json={
        "realm": REALM,
        "enabled": True,
        "registrationAllowed": False,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
    })
    if r.status_code == 409:
        print("  Realm already exists — OK")
    elif r.status_code == 201:
        print("  Created!")
    else:
        print(f"  ERROR {r.status_code}: {r.text}")
        r.raise_for_status()


def create_roles(token: str):
    print("Creating realm roles...")
    for role in ROLES:
        r = requests.post(
            f"{KC_URL}/admin/realms/{REALM}/roles",
            headers=admin_headers(token),
            json={"name": role},
        )
        if r.status_code == 409:
            print(f"  {role} — already exists")
        elif r.status_code == 201:
            print(f"  {role} — created")
        else:
            print(f"  {role} — ERROR {r.status_code}: {r.text}")


def create_client(token: str):
    print(f"Creating OIDC client '{CLIENT_ID}'...")
    r = requests.post(f"{KC_URL}/admin/realms/{REALM}/clients", headers=admin_headers(token), json={
        "clientId": CLIENT_ID,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": CLIENT_SECRET,
        "directAccessGrantsEnabled": True,       # enables password grant for testing
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": True,
        "redirectUris": ["http://localhost:*"],
        "webOrigins": ["*"],
        "defaultClientScopes": ["openid", "profile", "email", "roles"],
        # Map realm roles into the access token
        "attributes": {
            "use.refresh.tokens": "true",
        },
    })
    if r.status_code == 409:
        print("  Client already exists — OK")
    elif r.status_code == 201:
        print("  Created!")
    else:
        print(f"  ERROR {r.status_code}: {r.text}")


def create_sre_users(token: str):
    """Create the SRE demo users and bind each to its realm role.

    Without these, the SRE demo needs /role <name> — a role claimed in a header
    and provably nothing else. With them /login works the same way it does for
    dr.smith, so the role arrives in a signed token and the demo can show the
    difference between claiming a role and proving one.
    """
    print("Creating SRE demo users...")
    roles = {r["name"]: r for r in requests.get(
        f"{KC_URL}/admin/realms/{REALM}/roles", headers=admin_headers(token)).json()}
    for username, (role, first, last) in SRE_USERS.items():
        r = requests.post(f"{KC_URL}/admin/realms/{REALM}/users",
                          headers=admin_headers(token), json={
                              "username": username, "enabled": True,
                              "firstName": first, "lastName": last,
                              "email": f"{username}@example.com",
                              "emailVerified": True,
                              "credentials": [{"type": "password",
                                               "value": "password",
                                               "temporary": False}]})
        if r.status_code not in (201, 409):
            print(f"  {username} — ERROR {r.status_code}: {r.text[:120]}")
            continue
        found = requests.get(f"{KC_URL}/admin/realms/{REALM}/users",
                             headers=admin_headers(token),
                             params={"username": username, "exact": "true"}).json()
        if not found:
            print(f"  {username} — created but not found, skipping role")
            continue
        uid = found[0]["id"]
        if role not in roles:
            print(f"  {username} — realm role '{role}' missing, skipping")
            continue
        m = requests.post(
            f"{KC_URL}/admin/realms/{REALM}/users/{uid}/role-mappings/realm",
            headers=admin_headers(token), json=[roles[role]])
        ok = "OK" if m.status_code in (204, 409) else f"ERROR {m.status_code}"
        print(f"  {username} -> {role} — {ok}")


def create_public_client(token: str):
    """The client the demos actually authenticate with.

    shield-api above is confidential, so a password grant that sends only a
    client_id fails with `unauthorized_client` — which reads like bad
    credentials rather than a client-type mismatch. The demos are CLIs with no
    place to keep a secret, so they need a public client.
    """
    print(f"Creating public client '{PUBLIC_CLIENT_ID}'...")
    r = requests.post(f"{KC_URL}/admin/realms/{REALM}/clients", headers=admin_headers(token), json={
        "clientId": PUBLIC_CLIENT_ID,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
        "directAccessGrantsEnabled": True,   # password grant, for scripted demos
        "standardFlowEnabled": True,
        "redirectUris": ["http://localhost:*"],
    })
    if r.status_code == 409:
        print("  Client already exists — OK")
    elif r.status_code != 201:
        return print(f"  ERROR {r.status_code}: {r.text}")
    else:
        print("  Created!")

    # Shield's oidc_sa provider REFUSES a token with no audience, by design:
    # issuer alone means "anyone this IdP will sign for", so without `aud` any
    # token from the realm would authorize against Shield. Keycloak does not
    # add an audience for a client that isn't itself a resource, so without
    # this mapper every demo token verifies as None and role binding silently
    # falls back to the X-User-Role header — the exact failure it demonstrates.
    cid = _client_uuid(token, PUBLIC_CLIENT_ID)
    if not cid:
        return print("  WARNING: client not found, skipping audience mapper")
    m = requests.post(
        f"{KC_URL}/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models",
        headers=admin_headers(token),
        json={"name": f"{AUDIENCE}-audience", "protocol": "openid-connect",
              "protocolMapper": "oidc-audience-mapper",
              "config": {"included.custom.audience": AUDIENCE,
                         "access.token.claim": "true", "id.token.claim": "false"}})
    if m.status_code == 409:
        print(f"  Audience mapper '{AUDIENCE}' already exists — OK")
    elif m.status_code == 201:
        print(f"  Audience mapper '{AUDIENCE}' created!")
    else:
        print(f"  ERROR {m.status_code}: {m.text}")


def _client_uuid(token: str, client_id: str) -> str:
    r = requests.get(f"{KC_URL}/admin/realms/{REALM}/clients",
                     headers=admin_headers(token), params={"clientId": client_id})
    found = r.json() if r.status_code == 200 else []
    return found[0]["id"] if found else ""


def setup_ldap_federation(token: str):
    print("Setting up LDAP federation...")
    r = requests.post(
        f"{KC_URL}/admin/realms/{REALM}/components",
        headers=admin_headers(token),
        json={
            "name": "openldap",
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
            "config": {
                "vendor": ["other"],
                "connectionUrl": [LDAP_URL],
                "bindDn": [LDAP_BIND_DN],
                "bindCredential": [LDAP_BIND_PASS],
                "usersDn": [LDAP_BASE_DN],
                "usernameLDAPAttribute": ["uid"],
                "rdnLDAPAttribute": ["uid"],
                "uuidLDAPAttribute": ["entryUUID"],
                "userObjectClasses": ["inetOrgPerson"],
                "editMode": ["READ_ONLY"],
                "syncRegistrations": ["false"],
                "importEnabled": ["true"],
                "batchSizeForSync": ["100"],
                "fullSyncPeriod": ["-1"],
                "changedSyncPeriod": ["-1"],
                "searchScope": ["2"],         # SUBTREE
                "trustEmail": ["true"],
                "enabled": ["true"],
                "priority": ["0"],
            },
        },
    )
    if r.status_code == 201:
        component_id = r.headers.get("Location", "").split("/")[-1]
        print(f"  LDAP federation created (id: {component_id})")
        # Trigger initial sync
        print("  Syncing LDAP users...")
        sync_r = requests.post(
            f"{KC_URL}/admin/realms/{REALM}/user-storage/{component_id}/sync?action=triggerFullSync",
            headers=admin_headers(token),
        )
        if sync_r.status_code == 200:
            data = sync_r.json()
            print(f"  Synced: {data.get('added', 0)} added, {data.get('updated', 0)} updated")
        else:
            print(f"  Sync response: {sync_r.status_code}")
    elif r.status_code == 409:
        print("  LDAP federation already exists — OK")
    else:
        print(f"  ERROR {r.status_code}: {r.text}")


def assign_roles(token: str):
    print("Assigning roles to users...")

    # Get all users
    r = requests.get(
        f"{KC_URL}/admin/realms/{REALM}/users?max=100",
        headers=admin_headers(token),
    )
    r.raise_for_status()
    users = {u["username"]: u["id"] for u in r.json()}

    # Get all roles
    r = requests.get(
        f"{KC_URL}/admin/realms/{REALM}/roles",
        headers=admin_headers(token),
    )
    r.raise_for_status()
    roles = {role["name"]: role for role in r.json()}

    for username, role_name in USER_ROLES.items():
        if username not in users:
            # If LDAP sync didn't bring the user, create locally
            print(f"  {username} not found — creating locally...")
            cr = requests.post(
                f"{KC_URL}/admin/realms/{REALM}/users",
                headers=admin_headers(token),
                json={
                    "username": username,
                    "enabled": True,
                    "email": f"{username.replace('.', '')}@shield.local",
                    "emailVerified": True,
                    "firstName": username.split(".")[0].capitalize(),
                    "lastName": username.split(".")[-1].capitalize(),
                    "requiredActions": [],
                    "credentials": [{"type": "password", "value": "password", "temporary": False}],
                },
            )
            if cr.status_code == 201:
                user_id = cr.headers.get("Location", "").split("/")[-1]
                users[username] = user_id
            elif cr.status_code == 409:
                # Re-fetch
                rr = requests.get(
                    f"{KC_URL}/admin/realms/{REALM}/users?username={username}&exact=true",
                    headers=admin_headers(token),
                )
                if rr.json():
                    users[username] = rr.json()[0]["id"]
            else:
                print(f"    Create failed: {cr.status_code}")
                continue

        if username not in users:
            print(f"  {username} — SKIP (user not found)")
            continue

        user_id = users[username]
        role = roles.get(role_name)
        if not role:
            print(f"  {username} — SKIP (role '{role_name}' not found)")
            continue

        # Set profile fields + clear required actions so password grant works
        # Keycloak 26 VERIFY_PROFILE blocks login if firstName/lastName missing
        parts = username.split(".")
        requests.put(
            f"{KC_URL}/admin/realms/{REALM}/users/{user_id}",
            headers=admin_headers(token),
            json={
                "firstName": parts[0].capitalize(),
                "lastName": parts[-1].capitalize(),
                "email": f"{username.replace('.', '')}@shield.local",
                "emailVerified": True,
                "requiredActions": [],
            },
        )

        # Set password (non-temporary)
        requests.put(
            f"{KC_URL}/admin/realms/{REALM}/users/{user_id}/reset-password",
            headers=admin_headers(token),
            json={"type": "password", "value": "password", "temporary": False},
        )

        r = requests.post(
            f"{KC_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
            headers=admin_headers(token),
            json=[{"id": role["id"], "name": role["name"]}],
        )
        if r.status_code == 204:
            print(f"  {username} → {role_name}")
        else:
            print(f"  {username} → {role_name} (status {r.status_code})")


def get_user_token(username: str, password: str = "password") -> dict:
    """Get an OIDC token for a test user via password grant."""
    r = requests.post(
        f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token",
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
        return {"error": r.text}
    return r.json()


def print_test_tokens():
    print("\n" + "=" * 60)
    print("TEST TOKENS (password grant — local testing only)")
    print("=" * 60)

    for username, role in USER_ROLES.items():
        token_data = get_user_token(username)
        if "error" in token_data:
            print(f"\n  {username} ({role}): ERROR — {token_data['error'][:100]}")
            continue

        access_token = token_data["access_token"]

        # Decode JWT payload (no verification — just for display)
        import base64
        payload = access_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))

        realm_roles = claims.get("realm_access", {}).get("roles", [])
        shield_role = next((r for r in realm_roles if r in ROLES), "unknown")

        # Keycloak 26 puts sub in id_token, not access_token
        sub = claims.get("sub")
        if not sub and "id_token" in token_data:
            id_payload = token_data["id_token"].split(".")[1]
            id_payload += "=" * (-len(id_payload) % 4)
            id_claims = json.loads(base64.urlsafe_b64decode(id_payload))
            sub = id_claims.get("sub")
        if not sub:
            sub = claims.get("preferred_username", username)

        print(f"\n  {username} ({role}):")
        print(f"    sub: {sub}")
        print(f"    realm_roles: {realm_roles}")
        print(f"    shield_role: {shield_role}")
        print(f"    token: {access_token[:50]}...")

    print(f"\n  OIDC Discovery URL:")
    print(f"    {KC_URL}/realms/{REALM}/.well-known/openid-configuration")
    print(f"\n  Client: {CLIENT_ID} / {CLIENT_SECRET}")


# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()

    create_realm(token)
    # Re-authenticate against the new realm's master
    token = get_admin_token()

    create_roles(token)
    create_client(token)
    create_public_client(token)
    create_sre_users(token)
    setup_ldap_federation(token)

    # Wait for LDAP sync to complete
    time.sleep(3)

    assign_roles(token)
    print_test_tokens()

    print("\n" + "=" * 60)
    print("DONE! Keycloak is configured.")
    print("=" * 60)
    print(f"  Keycloak admin:  {KC_URL}  (admin / admin)")
    print(f"  OIDC realm:      {KC_URL}/realms/{REALM}")
    print(f"  Shield API:      http://localhost:8000")
    print(f"\n  Next: python test_local_oidc.py")
