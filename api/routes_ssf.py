"""Shared Signals Framework (SSF) endpoints — CAEP receiver + transmitter metadata.

  GET  /v1/shield/ssf/.well-known/ssf-configuration  — transmitter metadata
  POST /v1/shield/ssf/events                          — receive a pushed SET

The receiver lets external IdPs/EDRs (CrowdStrike, Okta, Entra, …) drive Shield
revocation: a CAEP session-revoked / credential-change / non-compliant
device-compliance-change event revokes the matching agent instance or user.

Security: this endpoint can revoke access, so it is CLOSED by default. It only
acts when SHIELD_SSF_RECEIVER_TOKEN is configured and the caller presents it as a
bearer token. (Production deployments should additionally verify the SET
signature against the transmitter's JWKS / mTLS; see TODO below.)
"""

from __future__ import annotations

import os
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.caep import (
    apply_set_claims, issuer, audience,
    EVT_SESSION_REVOKED, EVT_CREDENTIAL_CHANGE, EVT_DEVICE_COMPLIANCE, EVT_ASSURANCE_CHANGE,
)

logger = logging.getLogger("votal.ssf")
router = APIRouter(prefix="/v1/shield/ssf", tags=["ssf"])


@router.get("/.well-known/ssf-configuration")
async def ssf_configuration(request: Request):
    # Use the public base URL (SHIELD_PUBLIC_BASE_URL / forwarded headers) so the
    # transmitter metadata never advertises the internal proxy host:port.
    from api.routes_mcp_server import _public_base_url
    base = _public_base_url(request)
    return {
        "issuer": issuer(),
        "spec_version": "1_0",
        "configuration_endpoint": f"{base}/v1/shield/ssf/.well-known/ssf-configuration",
        "delivery_methods_supported": [
            "urn:ietf:rfc:8935",  # push
        ],
        "events_supported": [
            EVT_SESSION_REVOKED, EVT_CREDENTIAL_CHANGE,
            EVT_DEVICE_COMPLIANCE, EVT_ASSURANCE_CHANGE,
        ],
        "default_subjects": "ALL",
    }


@router.post("/events")
async def receive_events(request: Request):
    """Receive a Security Event Token (SET) and apply it."""
    expected = os.environ.get("SHIELD_SSF_RECEIVER_TOKEN", "").strip()
    if not expected:
        # Closed by default — never an open revoke endpoint.
        return JSONResponse(
            status_code=503,
            content={"error": "ssf_receiver_disabled",
                     "detail": "Set SHIELD_SSF_RECEIVER_TOKEN to enable the SSF receiver."},
        )
    auth = request.headers.get("authorization", "")
    presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    import hmac
    if not presented or not hmac.compare_digest(presented, expected):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    # Body is a compact JWS SET (application/secevent+jwt) or a JSON SET.
    raw = (await request.body()).decode("utf-8", "replace").strip()
    try:
        if raw.startswith("{"):
            import json
            claims = json.loads(raw)
        else:
            # TODO(prod): verify signature against the transmitter JWKS before trusting.
            from core.jwt_utils import decode_jwt_unverified
            claims = decode_jwt_unverified(raw.strip('"'))
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "invalid_set", "detail": str(e)})

    # Optional issuer allowlist.
    allow = os.environ.get("SHIELD_SSF_TRUSTED_ISSUERS", "").strip()
    if allow:
        trusted = {i.strip() for i in allow.split(",") if i.strip()}
        if claims.get("iss") not in trusted:
            return JSONResponse(status_code=403,
                                content={"error": "untrusted_issuer", "iss": claims.get("iss")})

    summary = apply_set_claims(claims)
    logger.info("ssf: applied=%s ignored=%s", summary.get("applied"), summary.get("ignored"))
    return JSONResponse(status_code=202, content={"status": "accepted", **summary})
