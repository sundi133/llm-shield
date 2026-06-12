"""Policy enforcement mode — monitor (dry-run) vs enforce.

Security teams rarely flip a brand-new policy straight to "block" in
production. This module lets a tenant run its policy in **monitor** mode:
guardrails still evaluate and every finding is still recorded, but a would-be
block is *not* actually enforced. Operators review what *would* have been
blocked, then flip the same policy to **enforce**.

Design guarantee: in ``enforce`` mode the decision is returned untouched, so
the production code path is provably identical to before this module existed.
The only behavioural change happens when a tenant explicitly opts into
``monitor``.
"""

from __future__ import annotations

from typing import Iterable, Optional

ENFORCE = "enforce"
MONITOR = "monitor"

# Actions that actually stop a request when enforced.
BLOCKING_ACTIONS = ("block", "pending_confirmation")

# Top-level action reported when monitor mode suppresses a would-be block.
MONITORED = "monitor"


def resolve_mode(tenant_config: Optional[dict], default: str = ENFORCE) -> str:
    """Resolve the enforcement mode for a tenant.

    Reads ``policy_mode`` from the tenant config. Anything other than the
    literal ``"monitor"`` resolves to ``enforce`` so the safe (blocking)
    behaviour is the default for misconfiguration.
    """
    if not tenant_config:
        return default
    mode = tenant_config.get("policy_mode", default)
    return MONITOR if mode == MONITOR else ENFORCE


def would_block(result: dict) -> bool:
    """True if a single guardrail result represents a would-be block."""
    return (not result.get("passed", True)) and result.get("action") in BLOCKING_ACTIONS


def is_administrative(result: dict) -> bool:
    """True for explicit operator kill actions (agent disabled, kill switch).

    Administrative blocks enforce even in monitor mode: an operator who
    toggled an agent off expects it off, regardless of the policy dry-run.
    """
    return bool((result.get("details") or {}).get("administrative"))


def apply(results: Iterable[dict], allowed: bool, action: str, mode: str) -> dict:
    """Apply the enforcement mode to a computed decision.

    Args:
        results: the per-guardrail result dicts (each has ``guardrail``,
            ``passed``, ``action``). Mutated in monitor mode: a would-be
            blocking result gains ``"enforced": False``.
        allowed: the natively-computed allow/deny for the request.
        action: the natively-computed top-level action.
        mode: ``ENFORCE`` or ``MONITOR``.

    Returns a dict: ``{allowed, action, mode, would_block}`` where
    ``would_block`` is the list of guardrail names that were (or would be)
    blocking. In enforce mode ``allowed``/``action`` are returned unchanged.
    """
    results = list(results)
    blocking_names = [r.get("guardrail", "") for r in results if would_block(r)]

    if mode != MONITOR:
        # Enforce: identical to pre-existing behaviour.
        return {
            "allowed": allowed,
            "action": action,
            "mode": ENFORCE,
            "would_block": blocking_names,
        }

    # Administrative blocks (agent disabled, kill switch) enforce even in
    # monitor mode — they are operator kill actions, not policy findings.
    if any(would_block(r) and is_administrative(r) for r in results):
        return {
            "allowed": allowed,
            "action": action,
            "mode": MONITOR,
            "would_block": blocking_names,
        }

    # Monitor: never actually block; surface what would have blocked.
    for r in results:
        if would_block(r):
            r["enforced"] = False
    new_action = MONITORED if blocking_names else action
    return {
        "allowed": True,
        "action": new_action,
        "mode": MONITOR,
        "would_block": blocking_names,
    }


def apply_to_response(response: dict, mode: str) -> dict:
    """Apply monitor mode to a classify-style response in place.

    The response shape is ``{"safe", "action", "guardrail_results", ...}``.
    Adds ``mode`` and ``would_block`` and, in monitor mode, flips ``safe`` to
    True and downgrades ``action`` when something would have blocked.
    """
    results = response.get("guardrail_results", [])
    native_allowed = response.get("safe", True)
    native_action = response.get("action", "pass")
    decision = apply(results, native_allowed, native_action, mode)
    response["safe"] = decision["allowed"]
    response["action"] = decision["action"]
    response["mode"] = decision["mode"]
    response["would_block"] = decision["would_block"]
    return response
