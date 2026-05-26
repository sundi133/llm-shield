"""`owner_email` is required when creating an agent.

Every agent needs a named human owner for accountability (Agent IDP design).
This is a validator-level test; the full POST flow is covered by integration
tests that need Redis.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from api.routes_agents_registry import (
    _validate_agent_body,
    _validate_owner_email,
)


def test_missing_owner_rejected_on_create():
    with pytest.raises(HTTPException) as exc:
        _validate_agent_body({"tools": []}, require_owner=True)
    assert exc.value.status_code == 400
    assert "owner_email" in exc.value.detail.lower()


def test_blank_owner_rejected_on_create():
    with pytest.raises(HTTPException) as exc:
        _validate_agent_body({"owner_email": "   "}, require_owner=True)
    assert exc.value.status_code == 400


def test_invalid_email_format_rejected():
    with pytest.raises(HTTPException):
        _validate_owner_email("not-an-email", required=True)
    with pytest.raises(HTTPException):
        _validate_owner_email("alice@", required=True)
    with pytest.raises(HTTPException):
        _validate_owner_email("@example.com", required=True)


def test_valid_email_trimmed():
    assert _validate_owner_email("  alice@example.com  ", required=True) == "alice@example.com"


def test_update_does_not_require_owner():
    _validate_agent_body({"tools": []}, require_owner=False)


def test_update_validates_owner_when_present():
    with pytest.raises(HTTPException):
        _validate_agent_body({"owner_email": "bogus"}, require_owner=False)


def test_owner_email_length_capped():
    too_long = ("a" * 250) + "@x.io"
    with pytest.raises(HTTPException):
        _validate_owner_email(too_long, required=True)
