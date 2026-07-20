"""Static threat, compliance, and risk mappings for the AIBOM (spec §15-§17).

Pure data + pure functions over an already-generated BOM document — no I/O,
no model calls, no Redis. Deterministic by construction so identical BOMs
always yield identical mappings (tests are the contract on the weights).

Threat ids follow the AIBOM v1.0 §15 taxonomy; compliance references cover
OWASP LLM Top 10, NIST AI RMF / 800-53, ISO/IEC 42001 / 27001, SOC 2, and
the EU AI Act at the control-reference level (pointers for an auditor, not
a certification claim).
"""

from __future__ import annotations

# ── §15 Threat mapping: BOM category -> applicable threat ids ─────────────

CATEGORY_THREATS = {
    "agents": ["excessive_agency", "agent_hijacking", "tool_abuse", "credential_theft"],
    "shadow_agents": ["shadow_ai", "excessive_agency", "agent_hijacking", "supply_chain_attack"],
    "tools": ["tool_abuse", "rce", "ssrf", "sensitive_data_disclosure"],
    "mcp_servers": ["supply_chain_attack", "tool_poisoning", "indirect_prompt_injection",
                    "credential_theft"],
    "models": ["prompt_injection", "jailbreak", "model_theft", "hallucination",
               "output_manipulation"],
    "prompts": ["prompt_injection", "prompt_leakage"],
    "knowledge_sources": ["data_poisoning", "indirect_prompt_injection",
                          "sensitive_data_disclosure"],
    "memory": ["memory_poisoning", "sensitive_data_disclosure"],
    "supply_chain": ["supply_chain_attack"],
}

# ── §16 Compliance mapping: guardrail name -> framework control refs ──────

_G = {
    "prompt_injection": [
        ("OWASP LLM Top 10", "LLM01: Prompt Injection"),
        ("NIST AI RMF", "MEASURE 2.7"),
        ("EU AI Act", "Art. 15 (Accuracy & Robustness)"),
    ],
    "jailbreak": [
        ("OWASP LLM Top 10", "LLM01: Prompt Injection"),
        ("NIST AI RMF", "MANAGE 2.4"),
    ],
    "pii_detection": [
        ("OWASP LLM Top 10", "LLM06: Sensitive Information Disclosure"),
        ("ISO/IEC 27001", "A.8.11 (Data Masking)"),
        ("EU AI Act", "Art. 10 (Data Governance)"),
        ("SOC 2", "CC6.7"),
    ],
    "secrets_detection": [
        ("OWASP LLM Top 10", "LLM06: Sensitive Information Disclosure"),
        ("ISO/IEC 27001", "A.8.12 (Data Leakage Prevention)"),
    ],
    "toxicity": [
        ("NIST AI RMF", "MEASURE 2.11"),
        ("EU AI Act", "Art. 9 (Risk Management)"),
    ],
    "tool_allowlist": [
        ("OWASP LLM Top 10", "LLM08: Excessive Agency"),
        ("NIST 800-53", "AC-6 (Least Privilege)"),
        ("ISO/IEC 42001", "B.9.4 (Use of AI Systems)"),
    ],
    "output_moderation": [
        ("OWASP LLM Top 10", "LLM05: Improper Output Handling"),
        ("NIST AI RMF", "MEASURE 2.7"),
    ],
    "memory_access_control": [
        ("OWASP LLM Top 10", "LLM06: Sensitive Information Disclosure"),
        ("NIST 800-53", "AC-3 (Access Enforcement)"),
    ],
}

# Any guardrail not in the curated table still evidences governance controls.
_G_DEFAULT = [
    ("NIST AI RMF", "GOVERN 1.2"),
    ("ISO/IEC 42001", "B.5.2 (AI Policy)"),
]

# Maintaining the BOM itself satisfies inventory/transparency controls.
_BOM_CONTROLS = [
    ("NIST AI RMF", "MAP 1.1 (Context & Inventory)"),
    ("ISO/IEC 42001", "B.4.2 (AI System Inventory)"),
    ("EU AI Act", "Art. 11 (Technical Documentation)"),
]

RISK_LEVELS = ("informational", "low", "medium", "high", "critical")


def build_threats(bom: dict) -> list[dict]:
    """Per-category threat applicability for components present in the BOM."""
    out = []
    agents = bom.get("agents") or []
    registered = sorted(a["agent_id"] for a in agents if a.get("source") == "registered")
    shadow = sorted(a["agent_id"] for a in agents if a.get("source") == "shadow")
    if registered:
        out.append({"category": "agents", "applies_to": registered,
                    "threat_ids": CATEGORY_THREATS["agents"]})
    if shadow:
        out.append({"category": "shadow_agents", "applies_to": shadow,
                    "threat_ids": CATEGORY_THREATS["shadow_agents"]})
    for section, id_field in (("tools", "name"), ("mcp_servers", "name"),
                              ("models", "component_id"), ("prompts", "component_id"),
                              ("knowledge_sources", "component_id"), ("memory", "component_id"),
                              ("supply_chain", "component_id")):
        ids = sorted(str(e.get(id_field)) for e in (bom.get(section) or []) if e.get(id_field))
        if ids:
            out.append({"category": section, "applies_to": ids,
                        "threat_ids": CATEGORY_THREATS[section]})
    return out


def build_compliance(bom: dict) -> list[dict]:
    """Control references evidenced by enabled guardrails + the BOM itself."""
    out = [{"component": "aibom", "component_type": "inventory",
            "framework": fw, "control": ctrl} for fw, ctrl in _BOM_CONTROLS]
    for g in bom.get("guardrails") or []:
        if not g.get("enabled"):
            continue
        name = g.get("name") or ""
        refs = _G.get(name, _G_DEFAULT)
        for fw, ctrl in refs:
            out.append({"component": name, "component_type": "guardrail",
                        "stage": g.get("stage"), "framework": fw, "control": ctrl})
    return out


# ── §17 Risk heuristic (Appendix A-lite: likelihood x impact) ─────────────
#
# Transparent lookups, not ML: every rating echoes its factors so an
# auditor can recompute it by hand.

def _level(score: int) -> str:
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 2:
        return "low"
    return "informational"


def _agent_risk(agent: dict) -> dict:
    factors = []
    if agent.get("source") == "shadow":
        likelihood = 3
        factors.append("shadow agent: observed in traffic, never registered")
    else:
        likelihood = 1
    granted = set(agent.get("allowed_tools") or [])
    used = set(agent.get("recent_tools_used") or [])
    if agent.get("source") == "registered" and used - granted:
        likelihood += 1
        factors.append(f"recent tool use outside grants: {sorted(used - granted)}")
    impact = 1 + (1 if granted else 0) + (1 if len(granted) > 5 else 0)
    if granted:
        factors.append(f"{len(granted)} granted tools")
    score = likelihood * impact
    return {"asset_type": "agent", "asset_id": agent.get("agent_id"),
            "likelihood": likelihood, "impact": impact, "score": score,
            "level": _level(score), "factors": factors}


def _tool_risk(tool: dict) -> dict:
    factors = []
    likelihood = 1
    if not tool.get("has_policy"):
        likelihood = 2
        factors.append("no tool policy configured")
    impact = 2
    score = likelihood * impact
    level = _level(score)
    if tool.get("disabled"):
        level = "informational"
        factors.append("killswitched (disabled)")
    return {"asset_type": "tool", "asset_id": tool.get("name"),
            "likelihood": likelihood, "impact": impact, "score": score,
            "level": level, "factors": factors}


def _mcp_risk(server: dict) -> dict:
    factors = ["external MCP dependency"]
    likelihood = 2
    impact = 2 if server.get("has_credentials") else 1
    if server.get("has_credentials"):
        factors.append("upstream credentials configured")
    score = likelihood * impact
    return {"asset_type": "mcp_server", "asset_id": server.get("name"),
            "likelihood": likelihood, "impact": impact, "score": score,
            "level": _level(score), "factors": factors}


def _declared_risk(asset_type: str, comp: dict) -> dict:
    declared_level = comp.get("risk_rating")
    level = declared_level if declared_level in RISK_LEVELS else "informational"
    factors = ["declared component: no runtime signal"]
    if declared_level:
        factors.append(f"declared risk_rating: {declared_level}")
    return {"asset_type": asset_type, "asset_id": comp.get("component_id"),
            "likelihood": None, "impact": None, "score": None,
            "level": level, "factors": factors}


def build_risk(bom: dict) -> dict:
    per_asset = []
    per_asset += [_agent_risk(a) for a in bom.get("agents") or []]
    per_asset += [_tool_risk(t) for t in bom.get("tools") or []]
    per_asset += [_mcp_risk(s) for s in bom.get("mcp_servers") or []]
    for section, asset_type in (("models", "model"), ("prompts", "prompt"),
                                ("knowledge_sources", "knowledge_source"),
                                ("memory", "memory"), ("supply_chain", "supply_chain")):
        per_asset += [_declared_risk(asset_type, c) for c in bom.get(section) or []]

    actionable = [r["level"] for r in per_asset if r["level"] != "informational"]
    overall = max(actionable, key=RISK_LEVELS.index) if actionable else "low"
    return {"per_asset": per_asset, "overall": overall}
