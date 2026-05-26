"""Blueprint record-building tests.

Blueprints are templates that mint concrete agent records into the existing
`agents:{tenant_id}` registry. These tests exercise the pure-Python record
builder; full HTTP flow tests live in the integration suite (needs Redis).
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from api.routes_agent_blueprints import _build_blueprint_record


def test_create_record_requires_owner():
    with pytest.raises(HTTPException):
        _build_blueprint_record({"name": "n", "tools": []})


def test_create_record_normalizes_owner_and_versions_at_1():
    rec = _build_blueprint_record({
        "name": "Doctor Template",
        "tools": ["patient_lookup"],
        "owner_email": "  doc@example.com  ",
    })
    assert rec["owner_email"] == "doc@example.com"
    assert rec["version"] == 1
    assert rec["tools"] == ["patient_lookup"]
    assert "created_at" in rec and "updated_at" in rec


def test_update_record_increments_version_and_keeps_owner():
    base = _build_blueprint_record({
        "name": "Doctor Template",
        "tools": ["patient_lookup"],
        "owner_email": "doc@example.com",
    })
    updated = _build_blueprint_record(
        {"description": "v2", "tools": ["patient_lookup", "diagnosis_update"]},
        existing=base,
    )
    assert updated["version"] == 2
    assert updated["owner_email"] == "doc@example.com"
    assert updated["description"] == "v2"
    assert updated["tools"] == ["patient_lookup", "diagnosis_update"]


def test_update_can_replace_owner():
    base = _build_blueprint_record({
        "name": "n", "tools": [], "owner_email": "first@example.com",
    })
    updated = _build_blueprint_record(
        {"owner_email": "second@example.com"}, existing=base
    )
    assert updated["owner_email"] == "second@example.com"


def test_update_rejects_invalid_owner():
    base = _build_blueprint_record({
        "name": "n", "tools": [], "owner_email": "first@example.com",
    })
    with pytest.raises(HTTPException):
        _build_blueprint_record({"owner_email": "bogus"}, existing=base)
