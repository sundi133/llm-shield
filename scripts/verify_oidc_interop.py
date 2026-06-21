#!/usr/bin/env python3
"""Verify OIDC interoperability with a real IdP — using Shield's own validator.

Proves the "Standards-based" interop rows on the Agentic Identity 1-pager are
real: it runs the SAME code path Shield uses (core/oauth/oidc_client) to
(1) fetch the IdP's OpenID discovery doc, (2) resolve + fetch its JWKS, and
(3) optionally validate a real id_token (signature / issuer / audience / expiry).

Prints PASS/FAIL and a copy-paste evidence line for the validation 1-pager.

Examples:
  # discovery + JWKS reachability (no login needed) — works for any public IdP:
  python3 scripts/verify_oidc_interop.py --issuer https://accounts.google.com

  # full validation of a real login token (the gold-standard proof):
  python3 scripts/verify_oidc_interop.py \
      --issuer https://<tenant>.okta.com \
      --audience <client_id> --id-token "<paste id_token>"
"""
import argparse
import asyncio
import os
import sys

# allow running as `python3 scripts/verify_oidc_interop.py` from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _claim(claims, *names):
    for n in names:
        if n in claims:
            return claims[n]
    return "?"


async def main() -> int:
    ap = argparse.ArgumentParser(description="Verify OIDC interop with an IdP via Shield's validator.")
    ap.add_argument("--issuer", required=True, help="IdP issuer URL, e.g. https://<tenant>.okta.com")
    ap.add_argument("--client-id", default="", help="Shield's client_id at the IdP (aud check)")
    ap.add_argument("--audience", default="", help="Expected aud (defaults to client_id)")
    ap.add_argument("--jwks-uri", default="", help="Override JWKS URI (else auto-discovered)")
    ap.add_argument("--id-token", default="", help="A real id_token to validate (optional but recommended)")
    a = ap.parse_args()

    try:
        from core.oauth.oidc_client import (
            OIDCProvider, discover_openid_config, _resolve_jwks_uri,
            validate_id_token, OIDCValidationError,
        )
        from core.oauth.jwks_cache import get_jwks
    except Exception as e:
        print(f"ERROR: run from the repo root so core/ is importable: {e}")
        return 2

    provider = OIDCProvider(issuer=a.issuer, client_id=a.client_id,
                            audience=a.audience, jwks_uri=a.jwks_uri)
    counts = {"p": 0, "f": 0}
    def ok(m): counts["p"] += 1; print(f"  \033[32mPASS\033[0m {m}")
    def no(m): counts["f"] += 1; print(f"  \033[31mFAIL\033[0m {m}")

    print(f"\nIdP issuer: {a.issuer}\n")

    # 1) discovery
    jwks_uri = None
    try:
        cfg = await discover_openid_config(a.issuer)
        jwks_uri = cfg.get("jwks_uri", "")
        algs = cfg.get("id_token_signing_alg_values_supported", [])
        ok(f"OpenID discovery reachable (.well-known/openid-configuration)")
        print(f"       jwks_uri: {jwks_uri}")
        print(f"       signing algs: {', '.join(algs) if algs else '(unspecified)'}")
    except Exception as e:
        no(f"discovery failed: {e}")

    # 2) JWKS
    try:
        uri = a.jwks_uri or jwks_uri
        if not uri:
            no("no jwks_uri (discovery gave none and none provided)")
        else:
            jwks = await get_jwks(a.issuer, uri)
            n = len(jwks.get("keys", []))
            ok(f"JWKS fetched ({n} signing key{'s' if n != 1 else ''})") if n else no("JWKS has no keys")
    except Exception as e:
        no(f"JWKS fetch failed: {e}")

    # 3) full id_token validation (optional)
    if a.id_token:
        try:
            claims = await validate_id_token(a.id_token, provider)
            ok("id_token validated (signature, issuer, audience, expiry)")
            print(f"       sub={_claim(claims,'sub')}  iss={_claim(claims,'iss')}  aud={_claim(claims,'aud')}")
        except OIDCValidationError as e:
            no(f"id_token validation failed: {e}")
        except Exception as e:
            no(f"id_token validation error: {e}")
    else:
        print("  NOTE: pass --id-token <real login token> for full end-to-end validation (gold-standard proof).")

    # evidence line
    print("\n--- evidence (for the validation 1-pager) ---")
    status = "VALIDATED" if (counts["f"] == 0 and a.id_token) else \
             ("DISCOVERY+JWKS OK (provide --id-token to mark VALIDATED)" if counts["f"] == 0 else "FAILED")
    print(f"{a.issuer}  ->  OIDC {status}  (discovery+JWKS checks: {counts['p']} pass / {counts['f']} fail)")
    return 1 if counts["f"] else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
