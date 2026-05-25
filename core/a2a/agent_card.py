"""A2A Agent Card -- discovery metadata for inter-agent communication.

The Agent Card is served at /.well-known/agent.json and describes
what this Shield agent can do and how to authenticate with it.
"""

from __future__ import annotations

import os
from typing import Optional


def build_agent_card(
    *,
    base_url: str,
    tenant_id: str = "",
    agent_id: str = "votal-shield",
) -> dict:
    """Build an A2A Agent Card for this Shield instance.

    Args:
        base_url: The public URL of this Shield instance.
        tenant_id: Optional tenant scope.
        agent_id: Agent identifier.

    Returns:
        A2A Agent Card dict per the A2A spec.
    """
    base = base_url.rstrip("/")
    issuer = os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield"

    return {
        "name": "Votal Shield",
        "description": (
            "AI guardrails agent — checks inputs/outputs against security policies, "
            "enforces RBAC, provides tool authorization, and sanitizes data."
        ),
        "url": f"{base}/a2a",
        "version": "1.0.0",
        "provider": {
            "organization": "Votal",
            "url": "https://votal.ai",
        },
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "authentication": {
            "schemes": [
                {
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "OAuth 2.1 access token (EdDSA/Ed25519)",
                },
                {
                    "scheme": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "Tenant API key",
                },
            ],
            "oauth": {
                "authorization_server": f"{base}/.well-known/oauth-authorization-server",
            },
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id": "check-input",
                "name": "Check Input",
                "description": "Run input guardrails (adversarial detection, toxicity, PII)",
                "tags": ["guardrails", "safety", "input"],
                "examples": ["Check if this message is safe: {message}"],
            },
            {
                "id": "check-output",
                "name": "Check Output",
                "description": "Run output guardrails (PII leakage, bias, tone)",
                "tags": ["guardrails", "safety", "output"],
                "examples": ["Verify this LLM response is safe: {output}"],
            },
            {
                "id": "check-tool",
                "name": "Check Tool Authorization",
                "description": "Verify if a tool call is authorized (RBAC + kill switch)",
                "tags": ["authorization", "rbac", "tools"],
                "examples": ["Can agent X use tool Y?"],
            },
            {
                "id": "sanitize",
                "name": "Sanitize Output",
                "description": "Redact PII and enforce data policies on tool output",
                "tags": ["sanitization", "pii", "data-policy"],
                "examples": ["Sanitize this database result: {output}"],
            },
        ],
    }
