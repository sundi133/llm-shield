"""Closed-loop auto-revoke: detection -> response.

When a high-signal guardrail (prompt injection, system-prompt-leak, permission
misuse) fires on a request that carries a *verified agent identity*, Shield can
automatically revoke that agent INSTANCE — instead of only blocking the single
request and waiting for a human to hit the kill switch.

Because both ``verify_agent_token`` and ``verify_cap`` honour instance
revocation, one ``revoke_instance`` call kills the agent's token AND all of its
outstanding capability tokens. That is the "revoke before more damage" loop.

Safety:
  * Disabled by default. Enable with ``SHIELD_ENABLE_AUTO_REVOKE=true``.
  * Only fires when a verified agent identity (instance id) is present, so plain
    tenant-key chat traffic is never affected.
  * Fully defensive — a failure here never breaks the request being served.

Config (all optional):
  SHIELD_ENABLE_AUTO_REVOKE        "true"/"1"/"yes" to enable (default off)
  SHIELD_AUTO_REVOKE_GUARDRAILS    comma list of guardrail names that trigger it
                                   (default: adversarial_detection,system_prompt_leak)
  SHIELD_AUTO_REVOKE_TTL_SECONDS   revocation TTL (default 3600)
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("votal.auto_revoke")

_DEFAULT_TRIGGER_GUARDRAILS = ("adversarial_detection", "system_prompt_leak")


def is_enabled() -> bool:
    return os.environ.get("SHIELD_ENABLE_AUTO_REVOKE", "").strip().lower() in ("1", "true", "yes")


def _trigger_guardrails() -> set[str]:
    raw = os.environ.get("SHIELD_AUTO_REVOKE_GUARDRAILS", "").strip()
    if not raw:
        return set(_DEFAULT_TRIGGER_GUARDRAILS)
    return {g.strip() for g in raw.split(",") if g.strip()}


def _revoke_ttl() -> int:
    try:
        return int(os.environ.get("SHIELD_AUTO_REVOKE_TTL_SECONDS", "3600"))
    except ValueError:
        return 3600


async def maybe_auto_revoke(
    *,
    tenant_id: Optional[str],
    agent_instance_id: Optional[str],
    agent_id: Optional[str] = None,
    user_sub: Optional[str] = None,
    trigger: str,
    reason: str = "",
    ttl: Optional[int] = None,
) -> dict:
    """Revoke an agent instance in response to a detection. Never raises.

    Returns a small dict describing what happened so callers/tests can assert.
    """
    out = {"revoked": False, "agent_instance_id": agent_instance_id, "trigger": trigger}
    try:
        if not is_enabled():
            out["skipped"] = "disabled"
            return out
        if not agent_instance_id:
            out["skipped"] = "no_instance"
            return out

        from storage.revocation import revoke_instance
        revoke_instance(agent_instance_id, ttl=ttl or _revoke_ttl())
        out["revoked"] = True

        # Telemetry counter (reuses the agent-auth stats plumbing).
        try:
            from storage import agent_auth_stats as _stats
            _stats.record(
                tenant_id=tenant_id,
                event=_stats.EVENT_AUTO_REVOKE,
                agent_id=agent_id,
                user_sub=user_sub,
                reason=(reason or trigger)[:240],
            )
        except Exception:
            pass

        # Audit trail.
        try:
            from storage.audit_log import audit_logger
            await audit_logger.log({
                "agent_key": agent_id or "",
                "endpoint": "auto_revoke",
                "input_text": f"auto_revoke:{trigger}",
                "action_taken": "revoke",
                "guardrails_triggered": [trigger],
                "latency_ms": 0,
                "metadata": {
                    "kind": "auto_revoke",
                    "tenant_id": tenant_id or "",
                    "agent_instance_id": agent_instance_id,
                    "agent_id": agent_id,
                    "user_sub": user_sub,
                    "trigger": trigger,
                    "reason": reason[:500],
                },
            })
        except Exception:
            pass

        # CAEP/SSF: tell the wider ecosystem (IdP/EDR/SIEM) to drop this agent too.
        try:
            from core.caep import emit_session_revoked
            await emit_session_revoked(
                agent_instance_id=agent_instance_id,
                user_sub=user_sub,
                agent_id=agent_id,
                tenant_id=tenant_id,
                reason=reason or trigger,
            )
        except Exception:
            pass

        logger.warning(
            "auto-revoke: instance=%s agent=%s trigger=%s reason=%s",
            agent_instance_id, agent_id, trigger, (reason or "")[:160],
        )
    except Exception as e:  # never break the caller's request
        logger.warning("auto-revoke failed: %s: %s", type(e).__name__, e)
        out["error"] = str(e)
    return out


async def autorevoke_from_request(request, tenant_id, guardrail_results) -> Optional[dict]:
    """Hook for guardrail decision points.

    Fires only when (a) auto-revoke is enabled, (b) the request carries a
    verified agent identity, and (c) a configured trigger guardrail blocked.
    Returns the maybe_auto_revoke result, or None if nothing was attempted.
    """
    try:
        if not is_enabled():
            return None
        identity = getattr(request.state, "identity", None) if hasattr(request, "state") else None
        if not identity:
            return None
        instance = getattr(identity, "agent_instance_id", None)
        if not instance:
            return None

        triggers = _trigger_guardrails()
        fired = [
            gr for gr in (guardrail_results or [])
            if not gr.get("passed") and gr.get("guardrail") in triggers
        ]
        if not fired:
            return None

        reason = "; ".join(
            f"{gr.get('guardrail')}: {gr.get('message', '')}" for gr in fired
        )[:240]
        return await maybe_auto_revoke(
            tenant_id=tenant_id,
            agent_instance_id=instance,
            agent_id=getattr(identity, "agent_id", None),
            user_sub=getattr(identity, "user_sub", None),
            trigger=",".join(sorted({gr.get("guardrail") for gr in fired})),
            reason=reason,
        )
    except Exception as e:
        logger.warning("autorevoke_from_request failed: %s: %s", type(e).__name__, e)
        return None
