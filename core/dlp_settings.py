"""Operator knobs for the LLM-backed data-policy tier.

Three things every judge on that tier (tool_output_sanitization, the
data_sanitization_ai reasoner, payload_risk) used to hard-code:

* the HTTP timeout of the model call: the shared client's 300 s, so a stalled
  model held the guard path for five minutes;
* what an error means: always fail-open, returning the original, with no way
  for an operator whose data policies ARE the control to choose otherwise;
* the confidence floor below which a verdict becomes `allow`: 0.75, in three
  places.

All three are read live (not cached at import) so a rollout or rollback takes
effect without a restart. Stdlib only: this module is COPY'd into the admin
image because api/routes_data_policies.py reaches it at module load.
Spec: docs/spec-runtime-dlp-gaps.md, PR 3 (G6).
"""
import os
from typing import Optional

DEFAULT_LLM_TIMEOUT_S = 20.0
DEFAULT_CONFIDENCE_FLOOR = 0.75

_TRUE = ("1", "on", "true", "yes")


def dlp_fail_closed() -> bool:
    """SHIELD_DLP_FAIL_CLOSED=on: a judge that errors or times out BLOCKS.

    Off by default, which is the historic fail-open, so no tenant's traffic
    changes on upgrade. On means a payload no policy actually judged is
    withheld rather than delivered.
    """
    return os.environ.get("SHIELD_DLP_FAIL_CLOSED", "").strip().lower() in _TRUE


def dlp_llm_timeout_s(settings: Optional[dict] = None) -> Optional[float]:
    """Seconds a data-policy model call may take. None means no bound.

    Precedence: the guardrail's `llm_timeout_s` setting, then the
    SHIELD_DLP_LLM_TIMEOUT_S env var, then DEFAULT_LLM_TIMEOUT_S. A value of
    0 or below disables the bound and falls back to the client default.
    """
    raw = None
    if settings and settings.get("llm_timeout_s") is not None:
        raw = settings.get("llm_timeout_s")
    else:
        raw = os.environ.get("SHIELD_DLP_LLM_TIMEOUT_S")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_LLM_TIMEOUT_S
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_LLM_TIMEOUT_S
    return value if value > 0 else None


def confidence_floor(settings: Optional[dict] = None) -> float:
    """Verdicts below this confidence become `allow`.

    Precedence: the guardrail's `confidence_floor` setting, then the
    SHIELD_DLP_CONFIDENCE_FLOOR env var, then DEFAULT_CONFIDENCE_FLOOR.
    Clamped to [0, 1]; anything unparsable falls back to the default.
    """
    raw = None
    if settings and settings.get("confidence_floor") is not None:
        raw = settings.get("confidence_floor")
    else:
        raw = os.environ.get("SHIELD_DLP_CONFIDENCE_FLOOR")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_CONFIDENCE_FLOOR
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE_FLOOR
    return min(1.0, max(0.0, value))
