#!/usr/bin/env python3
"""Fetch, verify and write a Shield runtime bundle for a sandbox.

Run this where the sandbox is created (the broker, CI runner or host), never
inside the sandbox: it uses the tenant API key.

    python examples/runtime/shield_runtime_sync.py \
        --shield https://api.guardrails.votal.ai --profile research-agent \
        --out ./research-agent.openshell.yaml
    openshell sandbox create --policy ./research-agent.openshell.yaml -- <agent command>

The key is read from the SHIELD_API_KEY environment variable (never a flag, so
it stays out of shell history and process listings).

What it guarantees:
  * The policy was signed by your Shield (EdDSA, checked against
    /v1/edge/runtime-bundle/jwks) and names this tenant, profile and target.
  * The artifact is byte-for-byte the one that was signed (sha256 in the claims).
  * Nothing is written unless both hold. Exit code 1 means "do not start".
    --allow-unsigned accepts a bundle from a Shield with no signing key
    configured (development only); a bad signature is never accepted.
  * With --etag-file, an unchanged bundle is a cheap 304 and the file stays as is.

Needs the `cryptography` package (already a Shield dependency).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _get(url: str, key: str, etag: str | None = None):
    headers = {"X-API-Key": key}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}"), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, None, etag
        raise SystemExit(f"shield: {url} -> HTTP {e.code}: {e.read()[:300]!r}")


def verify(bundle: dict, jwks: dict, *, tenant: str | None, profile: str, target: str) -> dict:
    """Raise ValueError unless the bundle's signature and claims check out."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    token = bundle.get("signature") or ""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("bundle signature is not a compact JWS")
    h, p, s = parts
    header = json.loads(_b64d(h))
    if header.get("alg") != "EdDSA":
        raise ValueError(f"unexpected signature algorithm {header.get('alg')!r}")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise ValueError(f"no published key for kid {header.get('kid')!r}")
    try:
        Ed25519PublicKey.from_public_bytes(_b64d(key["x"])).verify(_b64d(s), f"{h}.{p}".encode())
    except InvalidSignature:
        raise ValueError("bundle signature does not verify") from None
    claims = json.loads(_b64d(p))
    digest = "sha256:" + hashlib.sha256(bundle["artifact"].encode("utf-8")).hexdigest()
    checks = {
        "aud": (claims.get("aud"), "shield-runtime-bundle"),
        "profile": (claims.get("profile"), profile),
        "target": (claims.get("target"), target),
        "artifact_sha256": (claims.get("artifact_sha256"), digest),
    }
    if tenant:
        checks["tenant_id"] = (claims.get("tenant_id"), tenant)
    for name, (got, want) in checks.items():
        if got != want:
            raise ValueError(f"claim {name} is {got!r}, expected {want!r}")
    return claims


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--shield", required=True, help="Shield base URL")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--target", default="openshell")
    ap.add_argument("--out", required=True, help="where to write the policy file")
    ap.add_argument("--tenant", help="expected tenant id (recommended)")
    ap.add_argument("--shield-url", help="Shield URL as the sandbox reaches it, if different")
    ap.add_argument("--etag-file", help="remember the bundle version between runs")
    ap.add_argument("--allow-unsigned", action="store_true",
                    help="accept an unsigned bundle (development only)")
    args = ap.parse_args()

    key = os.environ.get("SHIELD_API_KEY", "").strip()
    if not key:
        print("set SHIELD_API_KEY", file=sys.stderr)
        return 1
    base = args.shield.rstrip("/")
    q = {"profile": args.profile, "target": args.target}
    if args.shield_url:
        q["shield_url"] = args.shield_url
    etag = None
    if args.etag_file and os.path.exists(args.etag_file) and os.path.exists(args.out):
        etag = open(args.etag_file).read().strip() or None

    status, bundle, new_etag = _get(f"{base}/v1/edge/runtime-bundle?{urllib.parse.urlencode(q)}",
                                    key, etag)
    if status == 304:
        print(f"unchanged: {args.out}")
        return 0

    if bundle.get("signed"):
        _, jwks, _ = _get(f"{base}/v1/edge/runtime-bundle/jwks", key)
        try:
            claims = verify(bundle, jwks, tenant=args.tenant, profile=args.profile,
                            target=args.target)
        except ValueError as e:
            print(f"REFUSED: {e}. Nothing written; do not start the sandbox.", file=sys.stderr)
            return 1
        print(f"verified: signed by kid {json.loads(_b64d(bundle['signature'].split('.')[0]))['kid']}"
              f", profile {claims['profile']} {claims['profile_hash']}")
    elif args.allow_unsigned:
        print("WARNING: bundle is unsigned (this Shield has no SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY)",
              file=sys.stderr)
    else:
        print("REFUSED: bundle is unsigned. Configure SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY on "
              "Shield, or pass --allow-unsigned for development.", file=sys.stderr)
        return 1

    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        f.write(bundle["artifact"])
    os.replace(tmp, args.out)
    if args.etag_file and new_etag:
        with open(args.etag_file, "w") as f:
            f.write(new_etag)
    for u in bundle.get("unsupported") or []:
        print(f"not enforced by {args.target}: {u}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
