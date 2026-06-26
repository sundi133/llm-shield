"""Regression tests for QA finding output-003.

The output PII guardrail's date_of_birth regex matched only MM/DD/YYYY, so an
ISO date like "1991-03-14" slipped through on regex-only deployments. It must
also catch the ISO form, while the phone pattern catches +1-415-555-2210.
"""

import asyncio

from guardrails.output.pii_leakage import PIILeakageGuardrail, _BUILTIN_PATTERNS


def _detect(content, pii_types):
    g = PIILeakageGuardrail()
    g._temp_config = {
        "enabled": True,
        "action": "block",
        "settings": {"pii_types": pii_types, "use_presidio": False},
    }
    res = asyncio.run(g.check(content))
    types = set()
    for d in (res.details or {}).get("detections", []):
        types.add(d["type"])
    return res, types


def test_iso_dob_detected():
    res, types = _detect(
        "The employee DOB is 1991-03-14.", ["Date of Birth"]
    )
    assert res.passed is False
    assert "date_of_birth" in types


def test_iso_dob_slash_detected():
    _, types = _detect("born 1991/03/14", ["Date of Birth"])
    assert "date_of_birth" in types


def test_us_dob_still_detected():
    _, types = _detect("DOB 03/14/1991", ["Date of Birth"])
    assert "date_of_birth" in types


def test_us_dob_dash_still_detected():
    _, types = _detect("DOB 03-14-1991", ["Date of Birth"])
    assert "date_of_birth" in types


def test_phone_detected():
    _, types = _detect("call +1-415-555-2210", ["Phone Number"])
    assert "phone_number" in types


def test_dob_and_phone_together_block():
    res, types = _detect(
        "The employee DOB is 1991-03-14 and phone is +1-415-555-2210.",
        ["Date of Birth", "Phone Number"],
    )
    assert res.passed is False
    assert "date_of_birth" in types
    assert "phone_number" in types


def test_non_date_not_misclassified_as_dob():
    """A 4-4-4 numeric string is not a valid date and must not match DOB."""
    pat = _BUILTIN_PATTERNS["date_of_birth"]
    assert pat.search("1234-56-7890") is None
    # Month 13 / day 32 are invalid -> no match
    assert pat.search("1991-13-14") is None
    assert pat.search("1991-03-32") is None
