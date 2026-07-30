"""Blocking a shadow agent must work for the ids that actually show up.

Shadow-agent discovery records whatever `agent_key` a caller sent, verbatim.
Block/allow then applied the REGISTRATION id rule (alphanumeric, hyphen,
underscore), so any observed agent with an `@` or a `.` — an email-shaped key,
for instance — could be seen in the console and never acted on.

That is backwards for a security control: the ids most likely to be hostile are
exactly the ones that do not look like a well-formed agent name, and an attacker
could pick one deliberately to become unblockable.

`blocked_agents` is a plain list membership test (core/middleware.py:335) — never
a Redis key, never a path — so the strict rule protected nothing there.
"""

import pytest
from fastapi import HTTPException

from api.routes_agents_registry import (_validate_agent_id,
                                        _validate_observed_agent_id)


# ── ids seen in real traffic must be blockable ───────────────────────


@pytest.mark.parametrize("agent_id", [
    "sundi133@gmail.com",       # observed in the live console — the reported bug
    "svc.account.prod",         # dotted service account
    "agent+tag",
])
def test_registration_rule_would_have_rejected_these(agent_id):
    """Pinning the cause: these fail the registration rule, which is why the
    block button returned 400."""
    with pytest.raises(HTTPException):
        _validate_agent_id(agent_id)


def test_plain_uuid_style_ids_were_never_the_problem():
    """Worth separating: `inst-d7f1be2a-...` is alphanumeric+hyphens and always
    passed. Only ids with other characters were unblockable, which is a narrower
    bug than the console made it look."""
    _validate_agent_id("inst-d7f1be2a-e42a-4c3b-a493-9e4f00112233")


@pytest.mark.parametrize("agent_id", [
    "sundi133@gmail.com",
    "inst-d7f1be2a-e42a-4c3b-a493-9e4f00112233",
    "svc.account.prod",
    "agent+tag",
    "Ünicode-agent",
    "shadow-bot-3f6c0d-2",                     # ordinary ones still fine
    "rogue-agent",
])
def test_observed_ids_can_be_blocked(agent_id):
    _validate_observed_agent_id(agent_id)      # must not raise


# ── but genuinely dangerous shapes stay rejected ─────────────────────


@pytest.mark.parametrize("agent_id", [
    "../../etc/passwd",     # path traversal — the original VAPT finding
    "..",
    "a/b",                  # separators
    "a\\b",
    "agent\x00null",        # control characters
    "agent\nnewline",
    "has space",            # whitespace
    "",                     # empty
    "x" * 129,              # over length
])
def test_dangerous_ids_are_still_refused(agent_id):
    with pytest.raises(HTTPException):
        _validate_observed_agent_id(agent_id)


def test_registration_stays_strict():
    """The relaxation is scoped to block/allow. Creating an agent still enforces
    the narrow charset, because that id is authored rather than observed."""
    _validate_agent_id("good-agent_1")
    for bad in ("sundi133@gmail.com", "svc.account.prod", "../x"):
        with pytest.raises(HTTPException):
            _validate_agent_id(bad)


def test_traversal_is_refused_by_both_rules():
    """The VAPT finding this validation exists for must not regress on either
    path."""
    for rule in (_validate_agent_id, _validate_observed_agent_id):
        with pytest.raises(HTTPException):
            rule("../../etc/passwd")


# ── registering a shadow agent ───────────────────────────────────────
#
# `Register` in the console pre-fills the Add Agent form and POSTs to
# /v1/agents/registry, so it hit the same strict rule and failed the same way.
# The relaxation here is narrower than for block/allow, because registering
# CREATES a durable record: an id that fails the strict rule is accepted only if
# this tenant genuinely observed it.

from unittest.mock import patch

from api.routes_agents_registry import _validate_new_agent_id


def _observed(*ids):
    return patch("api.routes_agents_registry.get_redis_data",
                 return_value={"agents": {i: {} for i in ids}})


def test_clean_ids_never_touch_storage():
    """The common path must not pay a lookup: a well-formed id short-circuits."""
    with patch("api.routes_agents_registry.get_redis_data") as g:
        _validate_new_agent_id("my-agent_1", "acme")
    assert g.call_count == 0


def test_observed_shadow_id_can_be_adopted():
    """The reported bug: Register on `sundi133@gmail.com` returned 400."""
    with _observed("sundi133@gmail.com"):
        _validate_new_agent_id("sundi133@gmail.com", "acme")


def test_unobserved_odd_id_is_still_refused():
    """You may adopt what traffic produced; you may not author it. Otherwise the
    relaxation would just be a way around the charset rule."""
    with _observed("someone-else@example.com"):
        with pytest.raises(HTTPException):
            _validate_new_agent_id("attacker@evil.com", "acme")


def test_observed_but_dangerous_is_still_refused():
    """Being observed does not make a traversal payload safe to store."""
    with _observed("../../etc/passwd"):
        with pytest.raises(HTTPException):
            _validate_new_agent_id("../../etc/passwd", "acme")


def test_storage_failure_does_not_widen_what_is_accepted():
    """If the observed list cannot be read, fall back to strict rather than
    letting an unverifiable id through."""
    with patch("api.routes_agents_registry.get_redis_data",
               side_effect=RuntimeError("redis down")):
        with pytest.raises(HTTPException):
            _validate_new_agent_id("sundi133@gmail.com", "acme")


def test_adopted_id_is_stored_byte_identical():
    """It must match the caller, block/allow, and the audit trail. Normalising it
    to fit a charset would register something that governs nothing."""
    original = "sundi133@gmail.com"
    with _observed(original):
        _validate_new_agent_id(original, "acme")   # unchanged, not rewritten
