"""
Universal GuardRail System - Industry Agnostic

A generic role-based access control and data protection system that works
across any industry: healthcare, finance, e-commerce, education, etc.

Features:
- Role-based tool authorization
- Data sanitization and protection policies
- Industry-agnostic design
- Configurable for any use case
"""

import requests
import os
from typing import Dict, List, Optional, Any


class GuardRailSystem:
    """
    Universal role-based access control and data protection system
    Works across any industry: healthcare, finance, e-commerce, etc.
    """

    def __init__(self, base_url: str, tenant_api_key: str, runpod_token: str = None):
        self.base_url = base_url
        self.headers = {
            "X-API-Key": tenant_api_key,
            "Content-Type": "application/json"
        }
        if runpod_token:
            self.headers["Authorization"] = f"Bearer {runpod_token}"

        # Optional industry metadata (can be set via factory methods)
        self.industry = None
        self.common_roles = []
        self.sensitive_data_types = []

    def check_tool_authorization(self, agent_id: str, tool_name: str, user_role: str, tool_input: Dict = None) -> Dict:
        """
        Pre-execution authorization check for any industry

        Args:
            agent_id: The AI agent identifier
            tool_name: The tool/function being called
            user_role: The user's role (doctor, admin, customer, etc.)
            tool_input: Optional input parameters for the tool

        Returns:
            Dict with authorization result and details
        """
        try:
            response = requests.post(
                f"{self.base_url}/v1/agents/authorize",
                headers=self.headers,
                json={
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "user_role": user_role,
                    "tool_input": tool_input or {}
                }
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "allowed": False,
                "reason": f"Authorization service error: {str(e)}",
                "error_type": "service_error"
            }

    def apply_data_policies(self, output: str, user_role: str, agent_id: str, tool_name: str, tool_input: Dict = None) -> Dict:
        """
        Post-execution data sanitization and validation for any industry

        Args:
            output: The raw tool output containing potentially sensitive data
            user_role: The user's role for role-based sanitization
            agent_id: The AI agent identifier
            tool_name: The tool that generated this output
            tool_input: Original input parameters for context

        Returns:
            Dict with sanitized output and policy compliance details
        """
        try:
            guardrail_headers = {**self.headers, "X-User-Role": user_role, "X-Agent-ID": agent_id}

            response = requests.post(
                f"{self.base_url}/guardrails/output",
                headers=guardrail_headers,
                json={
                    "output": output,
                    "context": {
                        "tool_name": tool_name,
                        "tool_input": tool_input or {}
                    }
                }
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "safe": False,
                "reason": f"Data policy service error: {str(e)}",
                "error_type": "service_error"
            }

    def execute_protected_tool(self, agent_id: str, tool_name: str, user_role: str, raw_output: str, tool_input: Dict = None) -> Dict:
        """
        Complete tool execution with authorization + data protection
        Universal method for any industry/use case

        Args:
            agent_id: The AI agent identifier
            tool_name: The tool/function being executed
            user_role: The user's role
            raw_output: The raw output from the tool execution
            tool_input: Original input parameters for the tool

        Returns:
            Dict with execution result, sanitized data, and compliance metadata
        """

        # Step 1: Authorization Check
        auth_result = self.check_tool_authorization(agent_id, tool_name, user_role, tool_input)

        if not auth_result.get("allowed"):
            return {
                "success": False,
                "stage": "authorization",
                "error": auth_result.get("reason"),
                "error_type": auth_result.get("error_type", "authorization_denied"),
                "metadata": {
                    "user_role": user_role,
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "allowed_tools": self._extract_allowed_tools(auth_result, user_role)
                }
            }

        # Step 2: Data Protection
        guardrail_result = self.apply_data_policies(raw_output, user_role, agent_id, tool_name, tool_input)

        if guardrail_result.get("safe", True):
            return {
                "success": True,
                "data": guardrail_result.get("sanitized_output", raw_output),
                "original_data": raw_output,
                "data_modified": "sanitized_output" in guardrail_result,
                "metadata": {
                    "user_role": user_role,
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "guardrails_applied": guardrail_result.get("guardrail_results", []),
                    "compliance_actions": self._extract_compliance_actions(guardrail_result)
                }
            }
        else:
            return {
                "success": False,
                "stage": "data_protection",
                "error": guardrail_result.get("reason", "Data policy violation"),
                "action": guardrail_result.get("action", "block"),
                "error_type": guardrail_result.get("error_type", "policy_violation"),
                "metadata": {
                    "violated_policies": guardrail_result.get("guardrail_results", [])
                }
            }

    def get_agent_configuration(self, agent_id: str = None) -> Dict:
        """Get agent configurations for the tenant"""
        try:
            url = f"{self.base_url}/v1/agents/registry"
            if agent_id:
                url += f"/{agent_id}"

            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to get agent configuration: {str(e)}"}

    def get_tool_policies(self, tool_name: str = None) -> Dict:
        """Get tool data policies"""
        try:
            url = f"{self.base_url}/v1/agents/tools/policies"
            if tool_name:
                url += f"/{tool_name}"

            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to get tool policies: {str(e)}"}

    def get_tenant_configuration(self) -> Dict:
        """Get complete tenant configuration"""
        try:
            response = requests.get(f"{self.base_url}/v1/tenant/me", headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to get tenant configuration: {str(e)}"}

    def get_supported_roles(self) -> Dict:
        """Get list of supported user roles"""
        try:
            response = requests.get(f"{self.base_url}/v1/agents/roles", headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to get supported roles: {str(e)}"}

    def _extract_allowed_tools(self, auth_result: Dict, user_role: str) -> List[str]:
        """Extract which tools this role can use"""
        agent_config = auth_result.get("agent_config", {})
        role_permissions = agent_config.get("role_permissions", {})
        return role_permissions.get(user_role, [])

    def _extract_compliance_actions(self, guardrail_result: Dict) -> List[Dict]:
        """Extract what compliance actions were taken"""
        actions = []
        for result in guardrail_result.get("guardrail_results", []):
            if result.get("action") in ["redact", "mask", "block"]:
                actions.append({
                    "guardrail": result.get("guardrail"),
                    "action": result.get("action"),
                    "reason": result.get("message", "")
                })
        return actions


class IndustryConfigurator:
    """Factory for creating industry-specific configurations"""

    @staticmethod
    def healthcare(base_url: str, tenant_api_key: str, runpod_token: str = None) -> GuardRailSystem:
        """Healthcare industry configuration"""
        system = GuardRailSystem(base_url, tenant_api_key, runpod_token)
        system.industry = "healthcare"
        system.common_roles = ["doctor", "nurse", "admin", "patient"]
        system.sensitive_data_types = ["ssn", "phone", "email", "medical_records", "prescription"]
        return system

    @staticmethod
    def finance(base_url: str, tenant_api_key: str, runpod_token: str = None) -> GuardRailSystem:
        """Financial services configuration"""
        system = GuardRailSystem(base_url, tenant_api_key, runpod_token)
        system.industry = "finance"
        system.common_roles = ["advisor", "analyst", "customer_service", "customer", "compliance_officer"]
        system.sensitive_data_types = ["ssn", "account_number", "credit_card", "routing_number", "tax_id"]
        return system

    @staticmethod
    def ecommerce(base_url: str, tenant_api_key: str, runpod_token: str = None) -> GuardRailSystem:
        """E-commerce configuration"""
        system = GuardRailSystem(base_url, tenant_api_key, runpod_token)
        system.industry = "ecommerce"
        system.common_roles = ["admin", "support", "manager", "customer"]
        system.sensitive_data_types = ["credit_card", "address", "phone", "email", "order_history"]
        return system

    @staticmethod
    def education(base_url: str, tenant_api_key: str, runpod_token: str = None) -> GuardRailSystem:
        """Education industry configuration"""
        system = GuardRailSystem(base_url, tenant_api_key, runpod_token)
        system.industry = "education"
        system.common_roles = ["teacher", "admin", "student", "parent"]
        system.sensitive_data_types = ["ssn", "student_id", "grades", "disciplinary_records"]
        return system


# Example usage and testing
def example_usage():
    """Example usage of the universal GuardRail system"""

    # Generic system - works for any industry
    system = GuardRailSystem(
        base_url="https://your-endpoint.ai",
        tenant_api_key="your-tenant-api-key",
        runpod_token=os.getenv("RUNPOD_TOKEN")
    )

    # Industry-specific shortcuts (optional)
    healthcare_system = IndustryConfigurator.healthcare(
        "https://your-endpoint.ai",
        "your-tenant-api-key",
        os.getenv("RUNPOD_TOKEN")
    )

    # Example 1: Check authorization
    auth_result = system.check_tool_authorization(
        agent_id="my-agent",
        tool_name="sensitive_lookup",
        user_role="manager"
    )
    print("Authorization result:", auth_result)

    # Example 2: Execute protected tool
    result = system.execute_protected_tool(
        agent_id="my-agent",
        tool_name="data_lookup",
        user_role="staff",
        raw_output="User: John Doe, SSN: 123-45-6789, Phone: 555-1234",
        tool_input={"user_id": "12345"}
    )

    if result["success"]:
        print(f"✅ Tool executed successfully")
        print(f"📊 Sanitized data: {result['data']}")
        print(f"🔒 Data was modified: {result['data_modified']}")
        print(f"👤 User role: {result['metadata']['user_role']}")
    else:
        print(f"❌ Tool blocked at {result['stage']}: {result['error']}")

        if result["stage"] == "authorization":
            print(f"💡 Allowed tools: {result['metadata']['allowed_tools']}")
        elif result["stage"] == "data_protection":
            print(f"🚨 Policy violations: {result['metadata']['violated_policies']}")


if __name__ == "__main__":
    example_usage()