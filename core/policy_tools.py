"""Policy management tools for function calling integration.

Provides OpenAI-compatible tool definitions and implementation functions
for managing data protection policies through natural language.
"""

import json
import os
import requests
from typing import Dict, List, Optional, Any

# Tool definitions for OpenAI-style function calling
POLICY_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "create_data_policy",
            "description": "Create a new data protection policy with custom patterns and role-based access controls",
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier (required for multi-tenant setup)"
                    },
                    "policy_id": {
                        "type": "string",
                        "description": "Unique policy identifier (e.g., 'healthcare_hipaa', 'financial_pii')"
                    },
                    "name": {
                        "type": "string",
                        "description": "Human-readable policy name"
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional policy description"
                    },
                    "patterns": {
                        "type": "array",
                        "description": "Data detection patterns",
                        "items": {
                            "type": "object",
                            "properties": {
                                "regex": {"type": "string", "description": "Regular expression pattern"},
                                "type": {"type": "string", "description": "Data type name (e.g., 'diagnosis', 'ssn', 'salary')"},
                                "sensitivity": {
                                    "type": "string",
                                    "enum": ["low", "medium", "high", "critical"],
                                    "description": "Sensitivity level"
                                },
                                "replacement": {
                                    "type": "string",
                                    "description": "Replacement text for redaction (optional)",
                                    "default": "[REDACTED]"
                                }
                            },
                            "required": ["regex", "type", "sensitivity"]
                        }
                    },
                    "roles": {
                        "type": "object",
                        "description": "Role-based access control mapping",
                        "additionalProperties": {
                            "type": "object",
                            "description": "Role permissions for data types",
                            "additionalProperties": {
                                "type": "string",
                                "enum": ["allow", "redact", "block"],
                                "description": "Action for this role and data type"
                            }
                        }
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether policy is active",
                        "default": True
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Policy priority (lower = higher priority)",
                        "default": 100
                    }
                },
                "required": ["tenant_id", "policy_id", "name", "patterns", "roles"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "update_data_policy",
            "description": "Update an existing data protection policy",
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string"},
                    "policy_id": {"type": "string"},
                    "name": {"type": "string", "description": "Updated policy name"},
                    "description": {"type": "string"},
                    "patterns": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "regex": {"type": "string"},
                                "type": {"type": "string"},
                                "sensitivity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                                "replacement": {"type": "string"}
                            }
                        }
                    },
                    "roles": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "string", "enum": ["allow", "redact", "block"]}
                        }
                    },
                    "enabled": {"type": "boolean"},
                    "priority": {"type": "integer"}
                },
                "required": ["tenant_id", "policy_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_data_policies",
            "description": "List all data protection policies for a tenant",
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string"},
                    "include_deleted": {
                        "type": "boolean",
                        "description": "Include soft-deleted policies",
                        "default": False
                    }
                },
                "required": ["tenant_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "test_data_policy",
            "description": "Test a policy against sample content to see how it would be processed",
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string"},
                    "policy_id": {"type": "string"},
                    "test_content": {
                        "type": "string",
                        "description": "Sample content to test the policy against"
                    },
                    "test_user_role": {
                        "type": "string",
                        "description": "Role to test permissions with"
                    }
                },
                "required": ["tenant_id", "policy_id", "test_content", "test_user_role"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "delete_data_policy",
            "description": "Delete a data protection policy",
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string"},
                    "policy_id": {"type": "string"},
                    "hard_delete": {
                        "type": "boolean",
                        "description": "Permanently delete (true) or soft delete (false)",
                        "default": False
                    }
                },
                "required": ["tenant_id", "policy_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "update_guardrail_config",
            "description": "Update guardrail configuration and settings",
            "parameters": {
                "type": "object",
                "properties": {
                    "guardrail_name": {
                        "type": "string",
                        "description": "Name of guardrail to update (e.g., 'tool_output_sanitization', 'pii_detection')"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Enable or disable the guardrail"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["pass", "warn", "block"],
                        "description": "Action when guardrail is triggered"
                    },
                    "settings": {
                        "type": "object",
                        "description": "Guardrail-specific settings",
                        "properties": {
                            "threshold": {
                                "type": "number",
                                "description": "Detection threshold (0.0-1.0)"
                            },
                            "max_output_length": {
                                "type": "integer",
                                "description": "Maximum output length before truncation"
                            },
                            "redaction_patterns": {
                                "type": "array",
                                "description": "Custom redaction patterns",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "pattern": {"type": "string"},
                                        "replacement": {"type": "string"},
                                        "description": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                },
                "required": ["guardrail_name"]
            }
        }
    }
]


class PolicyToolsClient:
    """Client for executing policy management tool calls."""

    def __init__(self, shield_base_url: str, admin_api_key: str):
        self.base_url = shield_base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {admin_api_key}",
            "Content-Type": "application/json",
            "X-Admin-Key": admin_api_key  # Backup header format
        }

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make HTTP request to Shield API."""
        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def create_data_policy(self, tenant_id: str, policy_id: str, name: str,
                          patterns: List[Dict], roles: Dict[str, Dict[str, str]],
                          description: str = None, enabled: bool = True, priority: int = 100) -> Dict:
        """Create a new data protection policy."""
        payload = {
            "policy_id": policy_id,
            "name": name,
            "patterns": patterns,
            "roles": roles,
            "enabled": enabled,
            "priority": priority
        }

        if description:
            payload["description"] = description

        result = self._request("POST", f"/v1/shield/policies/{tenant_id}", json=payload)

        if "status" in result and result["status"] == "created":
            return {
                "success": True,
                "message": f"Created policy '{policy_id}' for tenant '{tenant_id}'",
                "policy": result.get("policy", {})
            }
        else:
            return {
                "success": False,
                "error": result.get("detail", result.get("error", "Unknown error"))
            }

    def update_data_policy(self, tenant_id: str, policy_id: str, **updates) -> Dict:
        """Update an existing data protection policy."""
        # Filter out None values
        payload = {k: v for k, v in updates.items() if v is not None}

        if not payload:
            return {"success": False, "error": "No updates provided"}

        result = self._request("PUT", f"/v1/shield/policies/{tenant_id}/{policy_id}", json=payload)

        if "status" in result and result["status"] == "updated":
            return {
                "success": True,
                "message": f"Updated policy '{policy_id}' for tenant '{tenant_id}'",
                "policy": result.get("policy", {})
            }
        else:
            return {
                "success": False,
                "error": result.get("detail", result.get("error", "Unknown error"))
            }

    def list_data_policies(self, tenant_id: str, include_deleted: bool = False) -> Dict:
        """List all data protection policies for a tenant."""
        params = {"include_deleted": include_deleted}
        result = self._request("GET", f"/v1/shield/policies/{tenant_id}", params=params)

        if "policies" in result:
            return {
                "success": True,
                "policies": result["policies"],
                "count": result.get("count", len(result["policies"]))
            }
        else:
            return {
                "success": False,
                "error": result.get("detail", result.get("error", "Unknown error"))
            }

    def test_data_policy(self, tenant_id: str, policy_id: str, test_content: str, test_user_role: str) -> Dict:
        """Test a policy against sample content."""
        # First get the policy
        policy_result = self._request("GET", f"/v1/shield/policies/{tenant_id}/{policy_id}")

        if "policy_id" not in policy_result:
            return {
                "success": False,
                "error": f"Policy '{policy_id}' not found"
            }

        # Test the policy
        payload = {
            "tenant_id": tenant_id,
            "policy": policy_result,
            "test_content": test_content,
            "test_user_role": test_user_role
        }

        result = self._request("POST", "/v1/shield/policies/test", json=payload)

        if "result" in result:
            return {
                "success": True,
                "test_result": result["result"],
                "summary": {
                    "action": result["result"]["final_action"],
                    "blocked_items": len(result["result"]["blocked_items"]),
                    "redacted_items": len(result["result"]["redacted_items"])
                }
            }
        else:
            return {
                "success": False,
                "error": result.get("detail", result.get("error", "Unknown error"))
            }

    def delete_data_policy(self, tenant_id: str, policy_id: str, hard_delete: bool = False) -> Dict:
        """Delete a data protection policy."""
        params = {"hard": hard_delete}
        result = self._request("DELETE", f"/v1/shield/policies/{tenant_id}/{policy_id}", params=params)

        if "status" in result and result["status"] == "deleted":
            return {
                "success": True,
                "message": f"{'Permanently' if hard_delete else 'Soft'} deleted policy '{policy_id}'"
            }
        else:
            return {
                "success": False,
                "error": result.get("detail", result.get("error", "Unknown error"))
            }

    def update_guardrail_config(self, guardrail_name: str, enabled: bool = None,
                               action: str = None, settings: Dict = None) -> Dict:
        """Update guardrail configuration."""
        payload = {"guardrails": {guardrail_name: {}}}

        if enabled is not None:
            payload["guardrails"][guardrail_name]["enabled"] = enabled
        if action is not None:
            payload["guardrails"][guardrail_name]["action"] = action
        if settings is not None:
            payload["guardrails"][guardrail_name]["settings"] = settings

        result = self._request("PUT", "/v1/shield/config", json=payload)

        if "status" in result and result["status"] == "updated":
            return {
                "success": True,
                "message": f"Updated guardrail '{guardrail_name}'",
                "updated_guardrails": result.get("updated_guardrails", [])
            }
        else:
            return {
                "success": False,
                "error": result.get("detail", result.get("error", "Unknown error"))
            }


# Global client instance (initialized by environment variables)
_client = None

def get_policy_client() -> Optional[PolicyToolsClient]:
    """Get global policy client instance."""
    global _client
    if _client is None:
        shield_url = os.environ.get("SHIELD_BASE_URL")
        admin_key = os.environ.get("SHIELD_ADMIN_KEY")

        if shield_url and admin_key:
            _client = PolicyToolsClient(shield_url, admin_key)

    return _client


# Tool implementation functions for LiteLLM integration
def create_data_policy(**kwargs) -> Dict[str, Any]:
    """Tool function: Create data protection policy."""
    client = get_policy_client()
    if not client:
        return {"success": False, "error": "Policy client not configured"}

    return client.create_data_policy(**kwargs)


def update_data_policy(**kwargs) -> Dict[str, Any]:
    """Tool function: Update data protection policy."""
    client = get_policy_client()
    if not client:
        return {"success": False, "error": "Policy client not configured"}

    return client.update_data_policy(**kwargs)


def list_data_policies(**kwargs) -> Dict[str, Any]:
    """Tool function: List data protection policies."""
    client = get_policy_client()
    if not client:
        return {"success": False, "error": "Policy client not configured"}

    return client.list_data_policies(**kwargs)


def test_data_policy(**kwargs) -> Dict[str, Any]:
    """Tool function: Test data protection policy."""
    client = get_policy_client()
    if not client:
        return {"success": False, "error": "Policy client not configured"}

    return client.test_data_policy(**kwargs)


def delete_data_policy(**kwargs) -> Dict[str, Any]:
    """Tool function: Delete data protection policy."""
    client = get_policy_client()
    if not client:
        return {"success": False, "error": "Policy client not configured"}

    return client.delete_data_policy(**kwargs)


def update_guardrail_config(**kwargs) -> Dict[str, Any]:
    """Tool function: Update guardrail configuration."""
    client = get_policy_client()
    if not client:
        return {"success": False, "error": "Policy client not configured"}

    return client.update_guardrail_config(**kwargs)


# Export all tool functions for easy importing
__all__ = [
    "POLICY_TOOLS",
    "PolicyToolsClient",
    "create_data_policy",
    "update_data_policy",
    "list_data_policies",
    "test_data_policy",
    "delete_data_policy",
    "update_guardrail_config",
    "get_policy_client"
]