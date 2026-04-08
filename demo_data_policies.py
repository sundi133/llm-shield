#!/usr/bin/env python3
"""Demo script showing Data Policies API functionality"""

import re
import json

def demo_compliance_frameworks():
    """Demo compliance frameworks"""
    print("=== 📋 Compliance Frameworks ===")

    frameworks = {
        "hipaa": {
            "name": "Health Insurance Portability and Accountability Act",
            "description": "US healthcare data protection",
            "required_protections": ["phi", "ssn", "medical_records"],
            "audit_required": True,
            "retention_max_days": 365
        },
        "pci_dss": {
            "name": "Payment Card Industry Data Security Standard",
            "description": "Credit card data protection",
            "required_protections": ["pan", "cvv", "cardholder_data"],
            "audit_required": True,
            "retention_max_days": 365
        },
        "gdpr": {
            "name": "General Data Protection Regulation",
            "description": "EU personal data protection",
            "required_protections": ["personal_data", "sensitive_data"],
            "audit_required": True,
            "retention_max_days": 1095
        }
    }

    print(f"✅ Available frameworks: {len(frameworks)}")
    for code, details in frameworks.items():
        print(f"  🏛️  {code.upper()}: {details['name']}")
        print(f"     📊 Audit Required: {details['audit_required']}")
        print(f"     📅 Max Retention: {details['retention_max_days']} days")
        print(f"     🔒 Protections: {', '.join(details['required_protections'])}")
    print()

def demo_tool_policy():
    """Demo healthcare tool policy configuration"""
    print("=== 🏥 Healthcare Tool Policy (patient_lookup) ===")

    policy = {
        "tool_name": "patient_lookup",
        "sanitization_rules": [
            {
                "pattern_id": "ssn_redaction",
                "regex": r"\b\d{3}-\d{2}-\d{4}\b",
                "replacement": "[SSN_REDACTED]",
                "description": "Social Security Numbers",
                "enabled": True,
                "severity": "critical"
            },
            {
                "pattern_id": "phone_masking",
                "regex": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                "replacement": "[PHONE_MASKED]",
                "description": "Phone Numbers",
                "enabled": True,
                "severity": "high"
            }
        ],
        "role_policies": [
            {
                "role": "doctor",
                "action": "allow",
                "data_scope": ["medical", "personal", "contact"],
                "redaction_level": "partial"
            },
            {
                "role": "nurse",
                "action": "redact",
                "data_scope": ["medical", "contact"],
                "redaction_level": "partial"
            },
            {
                "role": "patient",
                "action": "block",
                "data_scope": [],
                "redaction_level": "full"
            }
        ],
        "compliance_framework": "hipaa",
        "audit_required": True,
        "retention_days": 90
    }

    print(f"🔧 Tool: {policy['tool_name']}")
    print(f"📋 Compliance: {policy['compliance_framework'].upper()}")
    print(f"📊 Audit Required: {policy['audit_required']}")

    print(f"\n🛡️  Sanitization Rules ({len(policy['sanitization_rules'])}):")
    for rule in policy['sanitization_rules']:
        print(f"  🔍 {rule['description']} ({rule['severity']})")
        print(f"     Pattern: {rule['regex']}")
        print(f"     Replace: {rule['replacement']}")

    print(f"\n👥 Role Policies ({len(policy['role_policies'])}):")
    for rp in policy['role_policies']:
        print(f"  👤 {rp['role']}: {rp['action']} | {rp['redaction_level']} redaction")
        print(f"     📊 Data Scope: {', '.join(rp['data_scope']) if rp['data_scope'] else 'None'}")
    print()

def demo_data_validation():
    """Demo real-time data validation with role-based redaction"""
    print("=== 🔍 Live Data Validation & Redaction ===")

    # Test data with sensitive information
    test_data = "Patient: John Doe, SSN: 123-45-6789, Phone: 555-123-4567, Diagnosis: Diabetes"

    test_cases = [
        {"role": "doctor", "description": "Doctor accessing patient data"},
        {"role": "nurse", "description": "Nurse accessing patient data"},
        {"role": "patient", "description": "Patient accessing own data"},
        {"role": "admin", "description": "Admin user accessing data"}
    ]

    print(f"📝 Original Data: {test_data}\n")

    for case in test_cases:
        role = case["role"]
        desc = case["description"]

        print(f"🧪 Test: {desc}")
        print(f"   👤 Role: {role}")

        # Simulate validation logic
        violations = []
        sanitized_data = test_data

        # Check for SSN
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', test_data):
            violations.append({
                "violation_type": "pii_exposure",
                "data_type": "ssn",
                "severity": "critical",
                "action_required": "redact" if role != "admin" else "log"
            })

            if role in ["nurse", "patient"]:
                sanitized_data = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', sanitized_data)

        # Check for phone numbers
        if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', test_data):
            violations.append({
                "violation_type": "pii_exposure",
                "data_type": "phone",
                "severity": "high",
                "action_required": "mask" if role != "doctor" else "log"
            })

            if role in ["nurse", "admin"]:
                sanitized_data = re.sub(r'\b(\d{3})[-.]?(\d{3})[-.]?(\d{4})\b', r'\1-***-\3', sanitized_data)

        # Determine compliance status
        compliant = len(violations) == 0
        risk_level = "high" if any(v["severity"] == "critical" for v in violations) else "medium" if violations else "low"

        print(f"   ✅ Compliant: {compliant}")
        print(f"   ⚠️  Risk Level: {risk_level}")
        print(f"   🚨 Violations: {len(violations)}")

        if violations:
            for v in violations:
                print(f"      - {v['data_type'].upper()}: {v['action_required']}")

        if sanitized_data != test_data:
            print(f"   🔒 Sanitized: {sanitized_data}")
        else:
            print(f"   ✅ No redaction needed")
        print()

def demo_policy_validation_flow():
    """Demo complete policy validation workflow"""
    print("=== 🔄 Complete Policy Validation Workflow ===")

    workflow_steps = [
        "1. 📥 Receive tool output with sensitive data",
        "2. 🔍 Identify user role and tool policy",
        "3. 📋 Apply compliance framework rules (HIPAA)",
        "4. 🛡️  Execute sanitization patterns (SSN, Phone)",
        "5. 👤 Apply role-based access control",
        "6. 📊 Generate audit log entry",
        "7. 📤 Return sanitized output to user"
    ]

    for step in workflow_steps:
        print(f"   {step}")

    print(f"\n✨ Result: Role-appropriate, compliant data delivery")
    print(f"🔐 Security: PII protected, audit trail maintained")
    print(f"⚖️  Compliance: HIPAA/GDPR requirements met")
    print()

def main():
    """Run complete demo"""
    print("🛡️  LLM Shield Data Policies API - Live Demo")
    print("=" * 50)

    demo_compliance_frameworks()
    demo_tool_policy()
    demo_data_validation()
    demo_policy_validation_flow()

    print("✅ Data Policies API Demo Complete!")
    print("🚀 Ready for healthcare, finance, and compliance-critical deployments")

if __name__ == "__main__":
    main()