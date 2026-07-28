#!/usr/bin/env python3
"""Keycloak → Shield: a signed role claim beating a forged header.

Runs the real path with a real token. Keycloak issues it, Shield's OIDC
workload provider verifies the signature against the realm's JWKS, and
resolve_identity() decides which role the authorization decision uses.

    docker run -d --name kc -p 8085:8080 \
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
      -v $PWD/examples/identity/keycloak:/opt/keycloak/data/import:ro \
      quay.io/keycloak/keycloak:26.0 start-dev --import-realm

    python examples/langchain/keycloak_binding_demo.py

Why this runs in-process rather than against a deployed Shield: the resolver is
where the decision is made, and Shield must reach the issuer's JWKS. A cloud
Shield cannot fetch keys from a Keycloak on localhost, so pointing this at a
remote data plane would prove nothing about binding.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import requests  # noqa: E402

KC = os.getenv("KEYCLOAK_URL", "http://localhost:8085").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", "bank")
CLIENT = os.getenv("KEYCLOAK_CLIENT", "demo-cli")
USER = os.getenv("KC_USER", "omar")
PASSWORD = os.getenv("KC_PASSWORD", "demo-only-change-me")
FORGED = os.getenv("FORGED_ROLE", "branch_manager")

ISSUER = f"{KC}/realms/{REALM}"
AUDIENCE = os.getenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", "votal-shield")

G, R, Y, B, DIM, Z = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"


def get_token():
    r = requests.post(f"{ISSUER}/protocol/openid-connect/token", timeout=20,
                      data={"grant_type": "password", "client_id": CLIENT,
                            "username": USER, "password": PASSWORD})
    if r.status_code != 200:
        sys.exit(f"could not get a token from Keycloak: {r.status_code} {r.text[:200]}")
    return r.json()["access_token"]


def peek(token):
    """Decode for DISPLAY only — Shield verifies it, we never trust this."""
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def main():
    # Shield trusts this issuer, and requires the token be minted FOR Shield.
    os.environ["SHIELD_WORKLOAD_IDENTITY_PROVIDERS"] = "admin_key,oidc_sa"
    os.environ["SHIELD_WORKLOAD_OIDC_ISSUERS"] = ISSUER
    os.environ["SHIELD_WORKLOAD_OIDC_AUDIENCE"] = AUDIENCE

    from core.identity_resolution import clear_role_binding_cache_for_tests, resolve_identity
    from core.workload_identity import resolve_workload_identity

    token = get_token()
    c = peek(token)
    print(f"\n{B}1. Keycloak issued a token{Z}")
    print(f"   iss    {c.get('iss')}")
    print(f"   sub    {c.get('sub')}  ({c.get('preferred_username')})")
    print(f"   aud    {c.get('aud')}")
    print(f"   roles  {G}{(c.get('realm_access') or {}).get('roles')}{Z}")

    req = SimpleNamespace(
        headers={"Authorization": "Bearer " + token,
                 # The attacker's move: claim a different role in a header.
                 "X-User-Role": FORGED},
        state=SimpleNamespace(identity=None),
        method="POST", url="https://shield.local/v1/shield/tool/check")

    print(f"\n{B}2. Shield verifies it{Z}")
    wi = resolve_workload_identity(req)
    if wi is None:
        sys.exit(f"   {R}the OIDC provider did not accept the token{Z} — check the "
                 f"issuer allowlist and that aud={AUDIENCE!r} is present")
    print(f"   {G}verified{Z} by provider {B}{wi.provider}{Z}, trust={wi.trust_level}")
    req.state.workload_identity = wi

    print(f"\n{B}3. The same request, with the caller also claiming "
          f"X-User-Role: {FORGED}{Z}")
    for mode in ("off", "prefer"):
        os.environ["SHIELD_ROLE_BINDING"] = mode
        clear_role_binding_cache_for_tests()
        r = resolve_identity(req, tenant_id="bankco")
        colour = G if r.role_verified else R
        verdict = "the signed claim won" if r.role_verified else "the forged header won"
        print(f"   SHIELD_ROLE_BINDING={mode:<7} role={colour}{r.user_role:<18}{Z}"
              f"source={r.role_source:<12} {DIM}{verdict}{Z}")

    print(f"\n{DIM}Authorization then intersects this role with the agent's own grant —"
          f"\ntool_allowlist enforces agent AND role, so neither can exceed theirs.{Z}\n")


if __name__ == "__main__":
    main()
