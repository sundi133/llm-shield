"""Industry policy templates — sensible starting points, not blank pages.

Security teams shouldn't have to author a guardrail policy from an empty
config. Each template is a curated set of input/output guardrails tuned for an
industry, and ships with ``recommended_mode = "monitor"`` so the policy lands
in dry-run first: observe what *would* block, then flip to enforce.

Guardrail names here match the registry (see ``config/default.yaml``).
"""

from __future__ import annotations

from typing import Optional


def _g(enabled=True, action="block", **settings):
    return {"enabled": enabled, "action": action, "settings": settings}


# Each template: metadata + input/output guardrail policy maps.
TEMPLATES: dict[str, dict] = {
    "general": {
        "name": "General Baseline",
        "description": "A safe default for any assistant: block prompt attacks "
                       "and toxicity, watch for PII.",
        "industry": "general",
        "compliance_frameworks": [],
        "recommended_mode": "monitor",
        "input_guardrails": {
            "adversarial_detection": _g(action="block", confidence_threshold=0.7),
            "toxicity": _g(action="block", threshold=0.7),
            "pii_detection": _g(action="warn",
                                entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"],
                                score_threshold=0.7),
        },
        "output_guardrails": {
            "pii_leakage": _g(action="warn", pii_types=["SSN", "Credit Card"], threshold=0.8),
            "hallucinated_links": _g(action="warn"),
        },
    },
    "healthcare": {
        "name": "Healthcare (HIPAA)",
        "description": "PHI-aware policy for clinical and patient-facing agents. "
                       "Blocks PII/PHI leakage and off-topic medical advice.",
        "industry": "healthcare",
        "compliance_frameworks": ["hipaa"],
        "recommended_mode": "monitor",
        "input_guardrails": {
            "adversarial_detection": _g(action="block", confidence_threshold=0.7),
            "toxicity": _g(action="block", threshold=0.7),
            "system_prompt_leak": _g(action="block"),
            "pii_detection": _g(action="block",
                                entities=["US_SSN", "PHONE_NUMBER", "EMAIL_ADDRESS",
                                          "MEDICAL_LICENSE", "PERSON"],
                                score_threshold=0.6),
            "topic_restriction": _g(action="block",
                                    blocked_topics=["weapons", "illegal_activities"]),
        },
        "output_guardrails": {
            "pii_leakage": _g(action="block",
                              pii_types=["SSN", "Medical Record Number", "Credit Card"],
                              threshold=0.7),
            "role_redaction": _g(action="block", pii_clearance_required="confidential"),
            "hallucinated_links": _g(action="block"),
            "bias_detection": _g(action="warn", categories=["Gender", "Racial", "Age"],
                                 threshold=0.6),
        },
    },
    "financial_services": {
        "name": "Financial Services (PCI DSS / SOX)",
        "description": "Cardholder- and account-data-aware policy for banking and "
                       "fintech agents. Blocks card/account leakage and prompt attacks.",
        "industry": "financial_services",
        "compliance_frameworks": ["pci_dss", "sox"],
        "recommended_mode": "monitor",
        "input_guardrails": {
            "adversarial_detection": _g(action="block", confidence_threshold=0.7),
            "system_prompt_leak": _g(action="block"),
            "toxicity": _g(action="warn", threshold=0.7),
            "pii_detection": _g(action="block",
                                entities=["CREDIT_CARD", "US_BANK_NUMBER", "US_SSN",
                                          "IBAN_CODE"],
                                score_threshold=0.6),
        },
        "output_guardrails": {
            "pii_leakage": _g(action="block",
                              pii_types=["Credit Card", "Bank Account", "SSN"],
                              threshold=0.7),
            "hallucinated_links": _g(action="block"),
            "competitor_mention": _g(action="warn"),
            "tone_enforcement": _g(action="warn",
                                   brand_voice_description="Professional, compliant, precise"),
        },
    },
}


def list_templates() -> list[dict]:
    """Return template summaries (no full guardrail bodies) for pickers."""
    return [
        {
            "id": tid,
            "name": t["name"],
            "description": t["description"],
            "industry": t["industry"],
            "compliance_frameworks": t["compliance_frameworks"],
            "recommended_mode": t["recommended_mode"],
            "input_guardrail_count": len(t["input_guardrails"]),
            "output_guardrail_count": len(t["output_guardrails"]),
        }
        for tid, t in TEMPLATES.items()
    ]


def get_template(template_id: str) -> Optional[dict]:
    """Return the full template (including guardrail bodies), or None."""
    return TEMPLATES.get(template_id)
