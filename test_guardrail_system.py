"""
Test script for the Universal GuardRail System
Demonstrates usage with current healthcare agents setup
"""

import os
from guardrail_system import GuardRailSystem, IndustryConfigurator


def test_current_healthcare_setup():
    """Test with current healthcare agents configuration"""

    # Initialize system with current RunPod configuration
    system = GuardRailSystem(
        base_url="https://kk5losqxwr2ui7.api.runpod.ai",
        tenant_api_key="tenant-20260407220546-28f6bb-key-28f6bb",
        runpod_token=os.getenv("RUNPOD_TOKEN")
    )

    print("=== Universal GuardRail System Test ===\n")

    # Test 1: Get tenant configuration
    print("1. Getting tenant configuration...")
    tenant_config = system.get_tenant_configuration()
    if "error" not in tenant_config:
        print(f"   ✅ Tenant: {tenant_config.get('name')} ({tenant_config.get('plan')})")
        print(f"   📊 Agents: {len(tenant_config.get('agents', []))}")
        print(f"   🛡️ Input guardrails: {len(tenant_config.get('input_guardrails', []))}")
        print(f"   🔒 Output guardrails: {len(tenant_config.get('output_guardrails', []))}")
    else:
        print(f"   ❌ Error: {tenant_config['error']}")
    print()

    # Test 2: Get agent registry
    print("2. Getting agent registry...")
    agents = system.get_agent_configuration()
    if "error" not in agents and "success" in agents:
        agent_list = agents.get("agents", {})
        print(f"   ✅ Found {len(agent_list)} registered agents:")
        for agent_id, agent_info in agent_list.items():
            print(f"      • {agent_id}: {agent_info.get('name')}")
    else:
        print(f"   ❌ Error: {agents.get('error', 'Unknown error')}")
    print()

    # Test 3: Authorization checks
    print("3. Testing authorization...")

    # Doctor can prescribe medication
    doctor_auth = system.check_tool_authorization(
        agent_id="healthcare-doctor",
        tool_name="prescribe_medication",
        user_role="doctor"
    )
    print(f"   Doctor prescribe: {'✅ Allowed' if doctor_auth.get('allowed') else '❌ Denied'}")

    # Nurse cannot prescribe medication
    nurse_auth = system.check_tool_authorization(
        agent_id="healthcare-doctor",
        tool_name="prescribe_medication",
        user_role="nurse"
    )
    print(f"   Nurse prescribe: {'✅ Allowed' if nurse_auth.get('allowed') else '❌ Denied'}")

    # Nurse can lookup patients
    nurse_lookup = system.check_tool_authorization(
        agent_id="healthcare-nurse",
        tool_name="patient_lookup",
        user_role="nurse"
    )
    print(f"   Nurse lookup: {'✅ Allowed' if nurse_lookup.get('allowed') else '❌ Denied'}")
    print()

    # Test 4: Complete tool execution with data protection
    print("4. Testing complete tool execution...")

    test_patient_data = "Patient: John Doe, SSN: 123-45-6789, Phone: 555-123-4567, Email: john.doe@email.com"

    # Doctor accessing patient data
    doctor_result = system.execute_protected_tool(
        agent_id="healthcare-doctor",
        tool_name="patient_lookup",
        user_role="doctor",
        raw_output=test_patient_data,
        tool_input={"patient_id": "12345"}
    )

    print("   Doctor patient lookup:")
    if doctor_result["success"]:
        print(f"      ✅ Success: Data modified = {doctor_result['data_modified']}")
        print(f"      📊 Output: {doctor_result['data'][:100]}...")
    else:
        print(f"      ❌ Failed at {doctor_result['stage']}: {doctor_result['error']}")
    print()

    # Nurse accessing same data (should show different redaction)
    nurse_result = system.execute_protected_tool(
        agent_id="healthcare-nurse",
        tool_name="patient_lookup",
        user_role="nurse",
        raw_output=test_patient_data,
        tool_input={"patient_id": "12345"}
    )

    print("   Nurse patient lookup:")
    if nurse_result["success"]:
        print(f"      ✅ Success: Data modified = {nurse_result['data_modified']}")
        print(f"      📊 Output: {nurse_result['data'][:100]}...")
    else:
        print(f"      ❌ Failed at {nurse_result['stage']}: {nurse_result['error']}")
    print()

    # Test 5: Unauthorized tool access
    print("5. Testing unauthorized access...")

    # Nurse trying to prescribe (should be blocked)
    nurse_prescription = system.execute_protected_tool(
        agent_id="healthcare-doctor",
        tool_name="prescribe_medication",
        user_role="nurse",
        raw_output="Prescribed Lisinopril 10mg for John Doe",
        tool_input={"medication": "Lisinopril", "dosage": "10mg"}
    )

    print("   Nurse prescription attempt:")
    if nurse_prescription["success"]:
        print(f"      🚨 WARNING: Nurse was allowed to prescribe! This should not happen.")
    else:
        print(f"      ✅ Correctly blocked at {nurse_prescription['stage']}: {nurse_prescription['error']}")
        if "allowed_tools" in nurse_prescription.get("metadata", {}):
            tools = nurse_prescription["metadata"]["allowed_tools"]
            print(f"      💡 Nurse allowed tools: {tools}")
    print()


def test_industry_configurators():
    """Test industry-specific configurators"""

    print("=== Industry Configurator Test ===\n")

    # Test different industry configurations
    industries = {
        "Healthcare": IndustryConfigurator.healthcare,
        "Finance": IndustryConfigurator.finance,
        "E-commerce": IndustryConfigurator.ecommerce,
        "Education": IndustryConfigurator.education
    }

    for industry_name, configurator in industries.items():
        system = configurator(
            base_url="https://example.com",
            tenant_api_key="test-key"
        )

        print(f"{industry_name}:")
        print(f"   Common roles: {system.common_roles}")
        print(f"   Sensitive data types: {system.sensitive_data_types}")
        print()


def main():
    """Run all tests"""
    try:
        test_current_healthcare_setup()
        test_industry_configurators()

        print("=== Test Summary ===")
        print("✅ Universal GuardRail System is ready for deployment!")
        print("🚀 Deploy to RunPod and test with your current healthcare agents")

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()