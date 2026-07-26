"""Shared tenant-config → guardrail-pipeline wiring.

The single place that turns a tenant's configured guardrails into
``(guardrail set, per-request config)`` and runs the pipeline with that config
installed on the ``_request_configs`` contextvar.

Why this module exists: policy-driven guardrails (``custom_policy_input`` /
``custom_policy_output``) read their policy list *out of that contextvar*
(``guardrails.base.BaseGuardrail._get_request_config``). Any caller that runs
the pipeline without setting it gets those guardrails executing against an
empty policy list — they run, find nothing, and pass. That is a silent
no-enforcement bug, and it is exactly what happened on the chat proxies while
``/guardrails/*`` was wired correctly. Keeping the wiring in one module is what
stops the two paths from drifting apart again.

Two modes, deliberately different:

``REPLACE``
    Run *only* the tenant's configured guardrails. This is the long-standing
    ``/guardrails/input`` and ``/guardrails/output`` behavior — the tenant's
    list is the whole pipeline.

``UNION``
    Run the stage's default guardrails **plus** the tenant's configured ones,
    with the tenant's settings winning for any guardrail it names. Used by the
    chat proxies. ``REPLACE`` would be wrong there: a tenant whose config lists
    only a custom policy would silently *lose* the default guards (prompt
    injection, PII, ...) on proxied traffic, trading one enforcement hole for
    another. ``UNION`` is strictly additive, so no tenant ends up with fewer
    guardrails than before.

The proxy path is therefore a deliberate superset of ``/guardrails/*``, not a
byte-identical copy. Both modes are tested so the difference stays intentional.
"""

from __future__ import annotations

import os
from typing import Optional

from core.models import PipelineResult
from core.pipeline import run_pipeline
from core.policy_mode import BLOCKING_ACTIONS, MONITOR
from guardrails.base import _request_configs
from guardrails.registry import get_by_stage, get_guardrail

REPLACE = "replace"
UNION = "union"

# Per-stage defaults, mirroring the two _classify_tenant implementations this
# module replaces. Input defaults to "block", output to "warn"; each stage
# auto-enables its own role-based policy guardrail when role context is present.
_STAGE_SPEC = {
    "input": {
        "default_action": "block",
        "role_guardrail": "role_based_input_policy",
        "role_action": "block",  # Block unauthorized input by default
        "config_key": "input_guardrails",
    },
    "output": {
        "default_action": "warn",
        "role_guardrail": "role_based_policy",
        "role_action": "warn",  # Default to warn for safety
        "config_key": "output_guardrails",
    },
}


def tenant_policy_disabled_on_proxy() -> bool:
    """Escape hatch: restore the pre-fix proxy behavior (defaults only).

    Read live from the environment rather than cached at import so rollout and
    tests can flip it without a restart, matching ``a2a_enforce_mode()``.
    """
    return os.environ.get("SHIELD_DISABLE_TENANT_POLICY_ON_PROXY", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def resolve_tenant_guardrails(
    stage: str,
    tenant_guardrails: Optional[dict],
    context: Optional[dict],
    mode: str,
) -> tuple[dict, list]:
    """Build the ``(configs, guardrails)`` pair for a tenant-configured run.

    ``configs`` is what gets installed on the ``_request_configs`` contextvar;
    ``guardrails`` is the singleton list handed to ``run_pipeline``.
    """
    spec = _STAGE_SPEC[stage]
    context = context or {}
    tenant_guardrails = tenant_guardrails or {}

    configs: dict[str, dict] = {}
    singletons: list = []
    seen: set[str] = set()

    for name, gcfg in tenant_guardrails.items():
        if not gcfg.get("enabled", True):
            # An explicit tenant disable has to be recorded in configs, not just
            # skipped. In UNION mode the guardrail is also in the stage defaults,
            # and a guardrail absent from configs falls through to the *global*
            # config — which would silently resurrect something the tenant turned
            # off. Writing enabled=False here makes run_pipeline filter it out.
            configs[name] = {
                "enabled": False,
                "action": gcfg.get("action", spec["default_action"]),
                "settings": gcfg.get("settings", {}),
            }
            continue

        configs[name] = {
            "enabled": True,
            "action": gcfg.get("action", spec["default_action"]),
            "settings": gcfg.get("settings", {}),
        }
        g = get_guardrail(name)
        if g and g.name not in seen:
            singletons.append(g)
            seen.add(g.name)

    # Auto-enable the role-based policy guardrail when role context is available.
    role_name = spec["role_guardrail"]
    if (
        (context.get("user_role") or context.get("role"))
        and context.get("tenant_id")
        and role_name not in configs
    ):
        configs[role_name] = {
            "enabled": True,
            "action": spec["role_action"],
            "settings": {},
        }
        g = get_guardrail(role_name)
        if g and g.name not in seen:
            singletons.append(g)
            seen.add(g.name)

    if mode == UNION:
        # Add the stage defaults the tenant did not name. They carry no entry in
        # configs, so they read their settings from the global config exactly as
        # they do today — the tenant's policies are layered on top, not swapped in.
        for g in get_by_stage(stage):
            if g.name not in seen:
                singletons.append(g)
                seen.add(g.name)

    return configs, singletons


async def run_tenant_pipeline(
    stage: str,
    content: str,
    context: Optional[dict],
    tenant_guardrails: Optional[dict],
    mode: str = REPLACE,
) -> PipelineResult:
    """Run ``stage``'s pipeline with the tenant's guardrail config installed."""
    configs, singletons = resolve_tenant_guardrails(
        stage, tenant_guardrails, context, mode
    )
    token = _request_configs.set(configs)
    try:
        return await run_pipeline(singletons, content, context)
    finally:
        _request_configs.reset(token)


def _stage_config(tenant_config: Optional[dict], stage: str) -> Optional[dict]:
    """Pull a stage's guardrail dict out of a tenant config, if present."""
    if not tenant_config:
        return None
    return tenant_config.get(_STAGE_SPEC[stage]["config_key"])


def resolve_proxy_guardrails(
    stage: str,
    context: Optional[dict],
    tenant_config: Optional[dict],
) -> tuple[dict, list]:
    """Resolve ``(configs, guardrails)`` for a chat proxy request.

    Falls back to the plain default guardrail set — and an empty config, so
    every guardrail reads the global config as before — when there is no
    tenant, no configured guardrails for this stage, or the kill switch is set.
    That fallback is byte-identical to the pre-fix behavior.

    Exposed separately from :func:`run_proxy_pipeline` because the streaming
    path has to install the config itself: its incremental checks read
    ``guardrail.enabled`` / ``configured_action`` off the contextvar from inside
    the SSE generator, which runs after the request handler has returned.
    """
    stage_guardrails = _stage_config(tenant_config, stage)
    if not stage_guardrails or tenant_policy_disabled_on_proxy():
        return {}, get_by_stage(stage)

    return resolve_tenant_guardrails(stage, stage_guardrails, context, UNION)


async def run_proxy_pipeline(
    stage: str,
    content: str,
    context: Optional[dict],
    tenant_config: Optional[dict],
) -> PipelineResult:
    """Run a chat proxy's guardrail pipeline, applying tenant policies.

    Fail-open on *policy resolution* (no tenant resolved -> defaults only) so a
    Redis outage degrades enforcement rather than taking down all traffic. The
    guardrails themselves stay fail-closed: callers wrap this in try/except and
    refuse on error.
    """
    configs, singletons = resolve_proxy_guardrails(stage, context, tenant_config)
    token = _request_configs.set(configs)
    try:
        return await run_pipeline(singletons, content, context)
    finally:
        _request_configs.reset(token)


async def run_proxy_input_pipeline(
    content: str,
    context: Optional[dict],
    tenant_config: Optional[dict],
) -> PipelineResult:
    """Input-stage :func:`run_proxy_pipeline` — the chat proxies' entry point."""
    return await run_proxy_pipeline("input", content, context, tenant_config)


async def run_proxy_output_pipeline(
    content: str,
    context: Optional[dict],
    tenant_config: Optional[dict],
) -> PipelineResult:
    """Output-stage :func:`run_proxy_pipeline` — the chat proxies' entry point."""
    return await run_proxy_pipeline("output", content, context, tenant_config)


def apply_mode_to_pipeline_result(
    result: PipelineResult, mode: str
) -> PipelineResult:
    """Apply a tenant's enforcement mode to a proxy pipeline decision.

    In ``monitor`` (dry-run) mode a would-be block is recorded but not enforced,
    so operators can review what a new policy *would* have stopped before
    flipping it to ``enforce``. Without this the proxies would hard-block
    monitor-mode tenants the moment tenant policies started applying here —
    the precise failure ``core.policy_mode`` exists to prevent.

    In ``enforce`` mode the result is returned untouched.
    """
    if mode != MONITOR or result.allowed:
        return result

    blocking = [
        r for r in result.results if not r.passed and r.action in BLOCKING_ACTIONS
    ]
    if not blocking:
        return result

    # Administrative blocks (kill switch, disabled agent) are operator kill
    # actions, not policy findings — they enforce even during a dry-run.
    if any((r.details or {}).get("administrative") for r in blocking):
        return result

    for r in blocking:
        details = dict(r.details or {})
        details["enforced"] = False
        details["would_block"] = True
        r.details = details

    result.allowed = True
    return result
