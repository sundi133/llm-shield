"""Guardrail model families.

A *family* is the pairing of a prompt style with a verdict parser. The default
family, ``vai``, is the CSV prompting every guardrail in this repo was written
against. The ``nemo`` family drives
``nvidia/Nemotron-3.5-Content-Safety`` through its native moderation output
instead of fighting its fine-tuning with a CSV instruction.

Why an adapter pack rather than a parallel tree of guardrails
-------------------------------------------------------------
Only the prompt and the parse differ. Thresholds, category filters, chunking,
aggregation, monitor mode and the suppressed-detection reporting are identical
either way, and duplicating 20 guardrail classes to change two things means
every future fix lands twice. Both bugs fixed in #378 and #379 existed in two
files each for exactly that reason.

So an adapter answers two questions — "what do I send" and "what did it say" —
and ``parse()`` returns the SAME dict the guardrail already expects. Nothing
downstream of the parse changes.

Selection is process-wide (``SHIELD_GUARDRAIL_FAMILY``) rather than per tenant
or per guardrail. Both of those would need two models resident on the GPU,
which is the cost this whole design exists to avoid.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from guardrails.nemo.base import NemoAdapter

logger = logging.getLogger("votal.guardrails.nemo")

FAMILY_VAI = "vai"
FAMILY_NEMO = "nemo"
_KNOWN_FAMILIES = (FAMILY_VAI, FAMILY_NEMO)

# Populated by the adapter modules as they land (tasks 3 and 4). Empty here on
# purpose: with no adapters registered, `adapter_for` returns None for every
# guardrail and each one takes its existing vai path unchanged.
_ADAPTERS: dict[str, NemoAdapter] = {}

# One WARN per process for an unusable family value, and one per guardrail that
# has no adapter yet, so a half-finished port is visible without spamming a log
# line onto every request.
_warned: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        logger.warning(message)


def active_family() -> str:
    """Resolve the guardrail family for this process.

    Reads the environment on every call rather than caching. The cost is one
    dict lookup (tens of nanoseconds, against a guard path whose cheapest step
    is a network call to a GPU), and caching would make the setting untestable
    and un-flippable without a restart.

    Anything unrecognised resolves to ``vai``: it is the known-good path, so an
    operator's typo degrades to today's behaviour rather than to an
    unconfigured model.
    """
    raw = os.environ.get("SHIELD_GUARDRAIL_FAMILY", FAMILY_VAI).strip().lower()
    if not raw:
        return FAMILY_VAI
    if raw not in _KNOWN_FAMILIES:
        _warn_once(
            f"family:{raw}",
            f"SHIELD_GUARDRAIL_FAMILY={raw!r} is not one of {_KNOWN_FAMILIES}; "
            f"falling back to {FAMILY_VAI!r}",
        )
        return FAMILY_VAI
    return raw


def adapter_for(guardrail_name: str) -> Optional[NemoAdapter]:
    """The adapter this guardrail should use, or None to take the vai path.

    Returns None whenever the family is ``vai``, which is the default, so the
    dispatch costs one env read and one comparison on the hot path and never
    touches the adapter table at all.
    """
    if active_family() != FAMILY_NEMO:
        return None

    _load_adapters()
    adapter = _ADAPTERS.get(guardrail_name)
    if adapter is None:
        # A guardrail with no adapter yet still has to work. Falling back to
        # the vai prompt against a Nemotron server is worse than the adapter
        # would be, but it is not an outage, and the log line says which
        # guardrail is unported.
        _warn_once(
            f"noadapter:{guardrail_name}",
            f"guardrail {guardrail_name!r} has no {FAMILY_NEMO!r} adapter; "
            "using the vai prompt against the served model",
        )
    return adapter


def register_adapter(guardrail_name: str, adapter: NemoAdapter) -> None:
    """Register an adapter. Called by the adapter modules at import time."""
    _ADAPTERS[guardrail_name] = adapter


def registered_adapters() -> dict[str, NemoAdapter]:
    """Snapshot of the adapter table. For tests and diagnostics."""
    _load_adapters()
    return dict(_ADAPTERS)


_loaded = False


def _load_adapters() -> None:
    """Import the adapter table on first use.

    Deferred rather than imported at module top so the seam costs nothing
    under the default family: a `vai` deployment never imports the adapters,
    the policy text, or the format constants at all.
    """
    global _loaded
    if _loaded:
        return
    _loaded = True
    from guardrails.nemo import prompts  # noqa: F401  (registers on import)


__all__ = [
    "FAMILY_NEMO",
    "FAMILY_VAI",
    "NemoAdapter",
    "active_family",
    "adapter_for",
    "register_adapter",
    "registered_adapters",
]
