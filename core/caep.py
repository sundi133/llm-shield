"""CAEP / SSF — Continuous Access Evaluation over the Shared Signals Framework.

Lets Shield interoperate with IdPs (Okta, Entra) and EDRs (e.g. CrowdStrike)
that speak the OpenID Shared Signals Framework:

  * EMIT — when Shield revokes an agent (auto-revoke or manual), it builds a
    standard CAEP `session-revoked` Security Event Token (SET, RFC 8417 — a
    signed JWT) and pushes it to a configured receiver, so the rest of the
    ecosystem drops the agent too.
  * CONSUME — Shield accepts pushed SETs (see api/routes_ssf.py). A
    `session-revoked` / `credential-change` / non-compliant
    `device-compliance-change` for a subject revokes the matching agent
    instance or user in Shield. That is how external posture drives Shield
    revocation without Shield building endpoint telemetry itself.

Everything here is best-effort and defensive: a signalling failure must never
break the security action that triggered it.

Config:
  SHIELD_SSF_ISSUER         transmitter iss (default https://votal-shield)
  SHIELD_SSF_AUDIENCE       SET aud (default ssf-receivers)
  SHIELD_SSF_PUSH_URL       receiver endpoint to POST emitted SETs to (optional)
  SHIELD_SSF_PUSH_TOKEN     bearer token for the push (optional)
  SHIELD_SSF_PRIVATE_KEY    hex Ed25519 key to sign SETs (else ephemeral)
"""

from __future__ import annotations

import logging
import os
import uuid
import time
from typing import Optional

logger = logging.getLogger("votal.caep")

# Official CAEP event-type URIs.
EVT_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
EVT_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
EVT_DEVICE_COMPLIANCE = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
EVT_ASSURANCE_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

_set_signer_cache: dict = {}


def issuer() -> str:
    return os.environ.get("SHIELD_SSF_ISSUER", "https://votal-shield")


def audience() -> str:
    return os.environ.get("SHIELD_SSF_AUDIENCE", "ssf-receivers")


def _get_set_signer():
    kid = os.environ.get("SHIELD_SSF_KID", "ssf-env")
    if kid in _set_signer_cache:
        return _set_signer_cache[kid]
    from core.signers import build_signer
    signer = build_signer(
        kid=kid,
        backend_env="SHIELD_SIGNER_BACKEND",
        local_key_env="SHIELD_SSF_PRIVATE_KEY",
    )
    _set_signer_cache[kid] = signer
    return signer


def reset_set_signer_cache_for_tests() -> None:
    _set_signer_cache.clear()


def build_set(event_type: str, subject: dict, event_payload: Optional[dict] = None) -> str:
    """Build and sign a Security Event Token (SET) for one CAEP event.

    `subject` follows the SSF subject shape; we additionally carry the raw
    identifiers we understand (agent_instance_id / user_sub) so receivers that
    are Shield can act on them directly.
    """
    now = int(time.time())
    payload = dict(event_payload or {})
    payload["subject"] = subject
    payload.setdefault("event_timestamp", now)
    claims = {
        "iss": issuer(),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "aud": audience(),
        "events": {event_type: payload},
    }
    from core.jwt_utils import encode_jwt
    return encode_jwt(claims, _get_set_signer())


async def emit_event(
    event_type: str,
    *,
    subject: dict,
    event_payload: Optional[dict] = None,
) -> Optional[str]:
    """Build a SET and push it to the configured SSF receiver. Best-effort.

    Returns the SET (so callers/tests can inspect it), or None on build failure.
    """
    try:
        token = build_set(event_type, subject, event_payload)
    except Exception as e:
        logger.warning("caep: SET build failed: %s: %s", type(e).__name__, e)
        return None

    push_url = os.environ.get("SHIELD_SSF_PUSH_URL", "").strip()
    if push_url:
        try:
            import httpx
            headers = {"Content-Type": "application/secevent+jwt"}
            tok = os.environ.get("SHIELD_SSF_PUSH_TOKEN", "").strip()
            if tok:
                headers["Authorization"] = f"Bearer {tok}"
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(push_url, content=token, headers=headers)
        except Exception as e:
            logger.warning("caep: SET push to %s failed: %s", push_url, e)
    logger.info("caep: emitted %s for %s", event_type.rsplit("/", 1)[-1], subject)
    return token


async def emit_session_revoked(
    *,
    agent_instance_id: Optional[str] = None,
    user_sub: Optional[str] = None,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    reason: str = "",
) -> Optional[str]:
    """Convenience emitter for the revoke loop."""
    subject = {"format": "opaque"}
    if agent_instance_id:
        subject["agent_instance_id"] = agent_instance_id
        subject["id"] = agent_instance_id
    if user_sub:
        subject["user_sub"] = user_sub
    extra = {"reason": reason[:240], "initiating_entity": "policy"}
    if agent_id:
        extra["agent_id"] = agent_id
    if tenant_id:
        extra["tenant_id"] = tenant_id
    return await emit_event(EVT_SESSION_REVOKED, subject=subject, event_payload=extra)


# ── Receiver side: apply an inbound SET ─────────────────────────────────

_REVOKING_EVENTS = {EVT_SESSION_REVOKED, EVT_CREDENTIAL_CHANGE, EVT_DEVICE_COMPLIANCE}


def _subject_ids(event_type: str, payload: dict) -> list[tuple[str, str]]:
    """Extract (kind, id) pairs to revoke from one event payload.

    device-compliance-change only revokes when the new status is not compliant.
    """
    if event_type == EVT_DEVICE_COMPLIANCE:
        status = str(payload.get("current_status", payload.get("status", ""))).lower()
        if status in ("compliant", "", "ok"):
            return []
    subj = payload.get("subject", {}) or {}
    out: list[tuple[str, str]] = []
    inst = subj.get("agent_instance_id") or (subj.get("id") if subj.get("format") == "opaque" else None)
    if inst:
        out.append(("instance", inst))
    if subj.get("user_sub"):
        out.append(("user", subj["user_sub"]))
    if subj.get("email"):
        out.append(("user", subj["email"]))
    return out


def apply_set_claims(claims: dict) -> dict:
    """Apply a decoded SET's events to Shield's revocation store.

    Returns a summary; never raises.
    """
    from storage.revocation import revoke_instance, revoke_user
    summary = {"applied": [], "ignored": []}
    try:
        events = claims.get("events", {}) or {}
        for event_type, payload in events.items():
            if event_type not in _REVOKING_EVENTS:
                summary["ignored"].append(event_type)
                continue
            ids = _subject_ids(event_type, payload or {})
            if not ids:
                summary["ignored"].append(event_type)
                continue
            for kind, ident in ids:
                if kind == "instance":
                    revoke_instance(ident)
                else:
                    revoke_user(ident)
                summary["applied"].append({"event": event_type.rsplit("/", 1)[-1],
                                           "type": kind, "id": ident})
                # Telemetry: count as a revoke attributed via SSF.
                try:
                    from storage import agent_auth_stats as _stats
                    _stats.record(
                        tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                        event=_stats.EVENT_REVOKE,
                        reason=f"ssf:{event_type.rsplit('/', 1)[-1]}:{kind}:{ident}"[:240],
                    )
                except Exception:
                    pass
    except Exception as e:
        logger.warning("caep: apply_set_claims failed: %s: %s", type(e).__name__, e)
        summary["error"] = str(e)
    return summary
