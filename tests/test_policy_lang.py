"""The declarative policy language: parse, validate, compile, evaluate (M2 T1)."""
from __future__ import annotations

import random

import pytest

from core.mcp import policy_lang as pl


def _compile(doc):
    return pl.compile_document(pl.parse_document(doc))


# ── parse / validate ────────────────────────────────────────────────────────

def test_yaml_and_json_and_dict_parse_equally():
    y = "default: deny\nrules:\n  - id: r1\n    effect: allow\n    roles: [a]\n    tools: [t1]\n"
    j = '{"default":"deny","rules":[{"id":"r1","effect":"allow","roles":["a"],"tools":["t1"]}]}'
    d = {"default": "deny", "rules": [{"id": "r1", "effect": "allow", "roles": ["a"], "tools": ["t1"]}]}
    assert pl.parse_document(y).model_dump() == pl.parse_document(j).model_dump() == pl.parse_document(d).model_dump()


def test_empty_document_is_default_deny():
    assert pl.parse_document(None).default == "deny"
    assert pl.parse_document("").rules == []


@pytest.mark.parametrize("bad,msg", [
    ("default: sideways\nrules: []", "default"),
    ("rules:\n  - id: r1\n    effect: maybe", "effect"),
    ("rules:\n  - effect: allow", "id"),
    ("- just\n- a\n- list", "mapping"),
    ("default: deny\nextra_key: 1", "extra"),
])
def test_invalid_documents_rejected(bad, msg):
    ok, errors = pl.validate_document(bad)
    assert ok is False
    assert any(msg in e.lower() for e in errors)


def test_duplicate_rule_ids_rejected():
    ok, errors = pl.validate_document(
        {"rules": [{"id": "x", "effect": "allow"}, {"id": "x", "effect": "deny"}]})
    assert ok is False and any("duplicate" in e.lower() for e in errors)


def test_not_yaml_rejected():
    ok, errors = pl.validate_document("default: [unclosed")
    assert ok is False


# ── evaluate ────────────────────────────────────────────────────────────────

def test_default_deny_when_no_rule_matches():
    snap = _compile({"default": "deny", "rules": [
        {"id": "r1", "effect": "allow", "roles": ["analyst"], "tools": ["balance_get"]}]})
    assert pl.evaluate(snap, "analyst", "balance_get")["effect"] == "allow"
    assert pl.evaluate(snap, "analyst", "pay")["effect"] == "deny"      # tool not allowed
    assert pl.evaluate(snap, "guest", "balance_get")["effect"] == "deny"  # role not allowed
    assert pl.evaluate(snap, "guest", "pay")["default_used"] is True


def test_default_allow():
    snap = _compile({"default": "allow", "rules": [
        {"id": "r1", "effect": "deny", "roles": ["*"], "tools": ["pay"]}]})
    assert pl.evaluate(snap, "anyone", "read")["effect"] == "allow"
    assert pl.evaluate(snap, "anyone", "pay")["effect"] == "deny"


def test_first_match_wins():
    snap = _compile({"default": "deny", "rules": [
        {"id": "allow-admin", "effect": "allow", "roles": ["admin"], "tools": ["pay"]},
        {"id": "deny-pay", "effect": "deny", "roles": ["*"], "tools": ["pay"]}]})
    assert pl.evaluate(snap, "admin", "pay")["rule_id"] == "allow-admin"   # earlier rule wins
    assert pl.evaluate(snap, "clerk", "pay")["rule_id"] == "deny-pay"


def test_wildcards():
    snap = _compile({"default": "deny", "rules": [
        {"id": "all", "effect": "allow", "roles": ["*"], "tools": ["*"]}]})
    assert pl.evaluate(snap, "x", "y")["effect"] == "allow"


# ── property: the index matcher agrees with a linear scan ───────────────────

def _linear(doc, role, tool):
    for r in doc["rules"]:
        tool_ok = "*" in r.get("tools", ["*"]) or tool in r.get("tools", ["*"])
        role_ok = "*" in r.get("roles", ["*"]) or role in r.get("roles", ["*"])
        if tool_ok and role_ok:
            return r["effect"]
    return doc.get("default", "deny")


def test_index_matches_linear_scan_property():
    rng = random.Random(1234)
    roles = ["admin", "analyst", "clerk", "*"]
    tools = ["pay", "balance_get", "statement", "kyc_doc", "*"]
    for _ in range(300):
        doc = {"default": rng.choice(["allow", "deny"]),
               "rules": [{"id": f"r{i}", "effect": rng.choice(["allow", "deny"]),
                          "roles": rng.sample(roles, rng.randint(1, 3)),
                          "tools": rng.sample(tools, rng.randint(1, 3))}
                         for i in range(rng.randint(0, 6))]}
        snap = _compile(doc)
        norm = pl.parse_document(doc).model_dump()      # the normalised doc the snapshot came from
        for role in roles[:-1]:
            for tool in tools[:-1]:
                assert pl.evaluate(snap, role, tool)["effect"] == _linear(norm, role, tool)


def test_starter_document_is_allow_all():
    snap = _compile(pl.starter_document())
    assert pl.evaluate(snap, "any", "any")["effect"] == "allow"
