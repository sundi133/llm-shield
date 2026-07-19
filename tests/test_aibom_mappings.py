"""Threat/compliance mappings + risk heuristic (Task 4 of docs/spec-aibom.md).

Pure functions over a generated BOM; deterministic weights are the contract.
"""
import copy

import pytest

from storage import aibom_mappings as m


BOM = {
    "agents": [
        {"agent_id": "billing-agent", "source": "registered",
         "allowed_tools": ["get_invoice"], "recent_tools_used": ["get_invoice"]},
        {"agent_id": "rogue-bot", "source": "shadow",
         "allowed_tools": [], "recent_tools_used": ["scrape"]},
    ],
    "tools": [
        {"name": "get_invoice", "has_policy": True, "disabled": False},
        {"name": "wire_transfer", "has_policy": False, "disabled": False},
        {"name": "old_tool", "has_policy": True, "disabled": True},
    ],
    "mcp_servers": [{"name": "github", "has_credentials": True}],
    "guardrails": [
        {"name": "prompt_injection", "stage": "input", "enabled": True},
        {"name": "pii_detection", "stage": "output", "enabled": False},
        {"name": "my_custom_thing", "stage": "output", "enabled": True},
    ],
    "models": [{"component_id": "gpt-5", "risk_rating": "high"}],
    "prompts": [{"component_id": "sys-1"}],
}


def test_threats_map_present_categories():
    threats = m.build_threats(BOM)
    by_cat = {t["category"]: t for t in threats}
    assert by_cat["agents"]["applies_to"] == ["billing-agent"]
    assert by_cat["shadow_agents"]["applies_to"] == ["rogue-bot"]
    assert "shadow_ai" in by_cat["shadow_agents"]["threat_ids"]
    assert "tool_poisoning" in by_cat["mcp_servers"]["threat_ids"]
    assert "prompt_injection" in by_cat["models"]["threat_ids"]
    assert "knowledge_sources" not in by_cat  # empty category -> no entry


def test_compliance_covers_enabled_guardrails_and_inventory():
    entries = m.build_compliance(BOM)
    inventory = [e for e in entries if e["component"] == "aibom"]
    assert {e["framework"] for e in inventory} == {"NIST AI RMF", "ISO/IEC 42001", "EU AI Act"}

    pi = [e for e in entries if e["component"] == "prompt_injection"]
    assert {(e["framework"], e["control"]) for e in pi} >= {
        ("OWASP LLM Top 10", "LLM01: Prompt Injection")}
    # disabled guardrails evidence nothing
    assert not [e for e in entries if e["component"] == "pii_detection"]
    # unknown guardrails fall back to generic governance controls
    custom = [e for e in entries if e["component"] == "my_custom_thing"]
    assert {e["framework"] for e in custom} == {"NIST AI RMF", "ISO/IEC 42001"}


def test_risk_heuristic_is_deterministic_and_auditable():
    risk = m.build_risk(BOM)
    assert risk == m.build_risk(copy.deepcopy(BOM))  # deterministic
    by_id = {(r["asset_type"], r["asset_id"]): r for r in risk["per_asset"]}

    shadow = by_id[("agent", "rogue-bot")]
    assert shadow["likelihood"] == 3 and shadow["level"] == "medium"
    assert any("shadow agent" in f for f in shadow["factors"])

    registered = by_id[("agent", "billing-agent")]
    assert registered["likelihood"] == 1 and registered["impact"] == 2
    assert registered["level"] == "low"

    ungoverned = by_id[("tool", "wire_transfer")]
    assert ungoverned["likelihood"] == 2 and ungoverned["level"] == "medium"
    assert by_id[("tool", "old_tool")]["level"] == "informational"

    mcp = by_id[("mcp_server", "github")]
    assert mcp["impact"] == 2 and mcp["level"] == "medium"

    assert by_id[("model", "gpt-5")]["level"] == "high"  # declared rating honored
    assert by_id[("prompt", "sys-1")]["level"] == "informational"

    assert risk["overall"] == "high"


def test_drifted_grants_raise_agent_likelihood():
    bom = copy.deepcopy(BOM)
    bom["agents"][0]["recent_tools_used"] = ["get_invoice", "wire_transfer"]
    r = m.build_risk(bom)
    agent = next(a for a in r["per_asset"] if a["asset_id"] == "billing-agent")
    assert agent["likelihood"] == 2
    assert any("outside grants" in f for f in agent["factors"])


def test_empty_bom_is_low_risk():
    risk = m.build_risk({})
    assert risk == {"per_asset": [], "overall": "low"}
    assert m.build_threats({}) == []
    assert [e["component"] for e in m.build_compliance({})] == ["aibom"] * 3
