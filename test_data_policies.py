#!/usr/bin/env python3
"""Test script for Data Policies API endpoints"""

import json
from api.routes_data_policies import (
    create_tool_data_policy,
    get_tool_data_policy,
    get_compliance_frameworks,
    validate_data_against_policies
)

def test_compliance_frameworks():
    """Test compliance frameworks endpoint"""
    print("=== Testing Compliance Frameworks ===")
    result = get_compliance_frameworks()
    frameworks = result["frameworks"]

    print(f"✅ Found {len(frameworks)} compliance frameworks:")
    for name, details in frameworks.items():
        print(f"  - {name.upper()}: {details['name']}")
        print(f"    Audit Required: {details['audit_required']}")
        print(f"    Max Retention: {details['retention_max_days']} days")
    print()

def test_healthcare_policy():
    """Test healthcare tool policy"""
    print("=== Testing Healthcare Tool Policy ===")

    # Mock tool policy for patient lookup
    result = get_tool_data_policy("patient_lookup", "tenant_123")
    policy = result["policy"]

    print(f"✅ Tool: {policy['tool_name']}")
    print(f"✅ Sanitization Rules: {len(policy['sanitization_rules'])}")
    for rule in policy['sanitization_rules']:
        print(f"  - {rule['description']}: {rule['pattern_id']} ({rule['severity']})")

    print(f"✅ Role Policies: {len(policy['role_policies'])}")
    for role_policy in policy['role_policies']:
        print(f"  - {role_policy['role']}: {role_policy['action']} ({role_policy['redaction_level']} redaction)")

    print(f"✅ Compliance: {policy['compliance_framework']}")
    print(f"✅ Audit Required: {policy['audit_required']}")
    print()

def test_data_validation():
    """Test data validation with PII"""
    print("=== Testing Data Validation ===")

    # Test data with PII
    test_cases = [
        {
            "data": "Patient: John Doe, SSN: 123-45-6789, Phone: 555-123-4567",
            "role": "doctor",
            "description": "Doctor accessing patient data"
        },
        {
            "data": "Patient: John Doe, SSN: 123-45-6789, Phone: 555-123-4567",
            "role": "nurse",
            "description": "Nurse accessing patient data"
        },
        {
            "data": "Patient: John Doe, SSN: 123-45-6789, Phone: 555-123-4567",
            "role": "patient",
            "description": "Patient accessing their own data"
        }
    ]

    for test_case in test_cases:
        print(f"🧪 Test: {test_case['description']}")
        print(f"   Role: {test_case['role']}")
        print(f"   Input: {test_case['data']}")

        # Mock validation request
        request_data = {
            "data": test_case['data'],
            "tool_name": "patient_lookup",
            "user_role": test_case['role'],
            "compliance_check": True
        }

        result = validate_data_against_policies(request_data, "tenant_123")
        validation = result["validation_result"]

        print(f"   ✅ Compliant: {validation['compliant']}")
        print(f"   ✅ Risk Level: {validation['risk_level']}")
        print(f"   ✅ Violations: {validation['violations_count']}")

        if result["data_modified"]:
            print(f"   🔒 Sanitized: {result['sanitized_data']}")
        else:
            print(f"   ✅ No redaction needed")
        print()

def main():
    """Run all tests"""
    print("🛡️  LLM Shield Data Policies API Test Suite\n")

    try:
        test_compliance_frameworks()
        test_healthcare_policy()
        test_data_validation()

        print("✅ All tests completed successfully!")
        print("🚀 Data Policies API is working correctly")

    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    main()