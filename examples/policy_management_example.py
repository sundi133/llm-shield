"""Example: Policy Management through Function Calling

This demonstrates how customers can manage data protection policies
through natural language using LiteLLM function calling.
"""

import openai
import os
from core.policy_tools import POLICY_TOOLS

# Example 1: Customer Configuration
# =====================================
# Customer sets up LiteLLM with policy management tools

def setup_customer_client():
    """Setup customer's LiteLLM client with policy management tools."""

    # Customer's standard OpenAI setup pointing to LiteLLM proxy
    client = openai.OpenAI(
        base_url="https://your-litellm-proxy.com/v1",
        api_key=os.environ.get("CUSTOMER_API_KEY")
    )

    return client

def customer_natural_language_policy_management():
    """Demonstrate natural language policy management."""

    client = setup_customer_client()

    # Customer request: "I need to create HIPAA-compliant data protection"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{
            "role": "user",
            "content": """
            I need to set up HIPAA-compliant data protection policies for my healthcare tenant.
            Here are the requirements:

            1. Block HIV/AIDS diagnoses for 'nurse' and 'patient' roles, but allow 'doctor' and 'admin'
            2. Redact SSNs for everyone except 'admin' role
            3. Block financial information (salary, billing) for 'patient' role
            4. Allow medical staff to see general medical info but redact mental health details for 'nurse' role

            My tenant ID is 'healthcare-corp-123'. Please create appropriate policies.
            """
        }],
        tools=POLICY_TOOLS,  # Include policy management tools
        tool_choice="auto"
    )

    print("LLM Response:")
    print(response.choices[0].message.content)

    # The LLM will generate function calls like:
    print("\nGenerated Function Calls:")
    for tool_call in response.choices[0].message.tool_calls or []:
        print(f"Function: {tool_call.function.name}")
        print(f"Arguments: {tool_call.function.arguments}")
        print()

# Example 2: Policy Testing and Updates
# =====================================

def test_policy_example():
    """Example of testing policies against sample data."""

    client = setup_customer_client()

    # Customer: "Test my policy against sample patient data"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{
            "role": "user",
            "content": """
            Test my 'hipaa_compliance' policy against this sample patient record:

            "Patient: John Doe, Age: 34, SSN: 123-45-6789, Diagnosis: HIV+,
             Mental Health: Depression, Therapy Sessions: 12, Salary: $85,000"

            Test it for 'nurse' role and 'doctor' role to see the difference.
            Tenant ID: healthcare-corp-123
            """
        }],
        tools=POLICY_TOOLS,
        tool_choice="auto"
    )

    print("Policy Test Results:")
    print(response.choices[0].message.content)

# Example 3: Dynamic Policy Updates
# =====================================

def dynamic_policy_updates():
    """Example of updating policies based on changing requirements."""

    client = setup_customer_client()

    # Customer: "Update our policy due to new regulations"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{
            "role": "user",
            "content": """
            We just received new compliance requirements. Please update our data policies:

            1. Add protection for credit card numbers (block for all roles except 'billing')
            2. Add detection for email addresses (redact for 'contractor' role)
            3. Increase priority of our financial data policy to 50 (higher priority)
            4. Enable our previously created 'hipaa_compliance' policy

            Tenant: healthcare-corp-123
            """
        }],
        tools=POLICY_TOOLS,
        tool_choice="auto"
    )

    print("Policy Update Results:")
    print(response.choices[0].message.content)

# Example 4: Backend Policy Configuration
# =====================================

def backend_policy_setup():
    """Example backend setup for storing policies in Redis."""

    from storage.policy_store import create_policy, get_tenant_policies
    from core.policy_tools import PolicyToolsClient

    # Example: Programmatically create a policy
    tenant_id = "healthcare-corp-123"

    # Healthcare policy configuration
    healthcare_policy = {
        "policy_id": "hipaa_compliance",
        "name": "HIPAA Healthcare Data Protection",
        "description": "Complies with HIPAA regulations for healthcare data",
        "patterns": [
            {
                "regex": r"\b(HIV|AIDS|Cancer|Diabetes)\b",
                "type": "medical_diagnosis",
                "sensitivity": "critical",
                "replacement": "[DIAGNOSIS_REDACTED]"
            },
            {
                "regex": r"\b(therapy|counseling|psychiatric|mental health)\b",
                "type": "mental_health",
                "sensitivity": "high",
                "replacement": "[MENTAL_HEALTH_REDACTED]"
            },
            {
                "regex": r"\b\d{3}-\d{2}-\d{4}\b",
                "type": "ssn",
                "sensitivity": "critical",
                "replacement": "[SSN_REDACTED]"
            },
            {
                "regex": r"\$[\d,]+\.\d{2}",
                "type": "financial",
                "sensitivity": "medium",
                "replacement": "[AMOUNT_REDACTED]"
            }
        ],
        "roles": {
            "patient": {
                "medical_diagnosis": "block",
                "mental_health": "block",
                "ssn": "block",
                "financial": "block"
            },
            "nurse": {
                "medical_diagnosis": "redact",
                "mental_health": "redact",
                "ssn": "block",
                "financial": "redact"
            },
            "doctor": {
                "medical_diagnosis": "allow",
                "mental_health": "allow",
                "ssn": "redact",
                "financial": "redact"
            },
            "admin": {
                "medical_diagnosis": "allow",
                "mental_health": "allow",
                "ssn": "allow",
                "financial": "allow"
            }
        },
        "enabled": True,
        "priority": 10  # High priority
    }

    # Create policy in Redis
    created_policy = create_policy(tenant_id, "hipaa_compliance", healthcare_policy)
    print(f"Created policy: {created_policy['policy_id']}")

    # Verify it's stored
    policies = get_tenant_policies(tenant_id)
    print(f"Tenant policies count: {len(policies)}")

# Example 5: Integration with Existing Guardrails
# ==============================================

def test_guardrail_integration():
    """Test how policies integrate with existing guardrails."""

    from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

    # Example tool output that would trigger policies
    sample_output = """
    Patient Record:
    - Name: Jane Smith
    - SSN: 987-65-4321
    - Diagnosis: HIV+
    - Mental Health: Severe Depression
    - Therapy: Weekly sessions
    - Insurance: $50,000 coverage
    """

    # Test with different role contexts
    test_contexts = [
        {
            "tenant_id": "healthcare-corp-123",
            "user_role": "nurse",
            "tool_name": "patient_lookup"
        },
        {
            "tenant_id": "healthcare-corp-123",
            "user_role": "doctor",
            "tool_name": "patient_lookup"
        },
        {
            "tenant_id": "healthcare-corp-123",
            "user_role": "admin",
            "tool_name": "patient_lookup"
        }
    ]

    guardrail = ToolOutputSanitizationGuardrail()

    for context in test_contexts:
        print(f"\nTesting as role: {context['user_role']}")
        print("=" * 50)

        # This will automatically load tenant policies and apply role-based filtering
        result = guardrail.check(sample_output, context)

        print(f"Action: {result.action}")
        print(f"Passed: {result.passed}")
        print(f"Message: {result.message}")

        if result.details:
            print(f"Sanitized output: {result.details.get('sanitized_output', '')}")
            print(f"Blocked items: {len(result.details.get('blocked_items', []))}")
            print(f"Redacted items: {len(result.details.get('redacted_items', []))}")

# Example 6: Complete End-to-End Flow
# ===================================

def complete_workflow_example():
    """Complete workflow from policy creation to enforcement."""

    print("Step 1: Customer creates policy through natural language")
    print("-" * 60)
    customer_natural_language_policy_management()

    print("\nStep 2: Test policy against sample data")
    print("-" * 60)
    test_policy_example()

    print("\nStep 3: Policy automatically protects tool outputs")
    print("-" * 60)
    test_guardrail_integration()

    print("\nStep 4: Customer updates policies as needed")
    print("-" * 60)
    dynamic_policy_updates()

if __name__ == "__main__":
    # Set required environment variables
    os.environ.setdefault("SHIELD_BASE_URL", "http://localhost:8000")
    os.environ.setdefault("SHIELD_ADMIN_KEY", "your-admin-key")
    os.environ.setdefault("CUSTOMER_API_KEY", "customer-api-key")

    print("LLM Shield - Policy Management Example")
    print("=" * 60)
    print()

    # Run examples
    try:
        print("Setting up backend policies...")
        backend_policy_setup()

        print("\nTesting guardrail integration...")
        test_guardrail_integration()

        print("\nRunning complete workflow...")
        complete_workflow_example()

    except Exception as e:
        print(f"Example failed: {e}")
        print("Make sure LLM Shield server is running and environment variables are set.")

"""
Expected Output:
================

The examples above show:

1. **Customer Experience**:
   - Zero code changes needed
   - Natural language policy management
   - Automatic enforcement

2. **Backend Integration**:
   - Policies stored in Redis
   - Role-based data access control
   - Automatic integration with existing guardrails

3. **Real-time Protection**:
   - Tool outputs automatically filtered
   - Different users see different data
   - Configurable sensitivity levels

4. **Policy Management**:
   - Create, update, delete policies via API
   - Test policies before deployment
   - Audit trail of all changes

Usage:
------
1. Start LLM Shield server
2. Set environment variables
3. Run: python examples/policy_management_example.py

The customer can then use standard OpenAI function calling to manage
their data protection policies through natural language.
"""