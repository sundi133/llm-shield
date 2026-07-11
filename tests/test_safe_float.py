"""safe_float: robust parse of LLM/JSON confidence values.

Regression for a live bug — a guard threw
`ValueError: could not convert string to float: ''` when an LLM returned
`"confidence": ""` (present but empty; the `.get(..., 0.5)` default only covers
a MISSING key). safe_float returns the default on any non-numeric value.
"""

import pytest

from guardrails.base import safe_float


@pytest.mark.parametrize("value,expected", [
    ("", 0.5),          # the live bug: present-but-empty
    (None, 0.5),        # missing (.get returns None)
    ("high", 0.5),      # LLM returned a word
    ("  ", 0.5),        # whitespace
    ({}, 0.5),          # wrong type
    ("0.9", 0.9),       # numeric string
    (0.9, 0.9),         # already a float
    (1, 1.0),           # int
    ("0", 0.0),         # zero is a valid value, not the default
])
def test_safe_float(value, expected):
    assert safe_float(value, 0.5) == expected


def test_default_is_configurable():
    assert safe_float("", default=0.0) == 0.0
    assert safe_float("nope") == 0.0  # default default
