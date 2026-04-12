#!/usr/bin/env python3
"""Create the specific tenant configuration for debugging."""

import sys
import os
import json

# Add project root to Python path
sys.path.insert(0, os.path.abspath('.'))

from storage.tenant_store import create_tenant, add_api_key

def create_debug_tenant():
    """Create the tenant that the test scripts expect."""

    tenant_id = "tenant-20260407220546-28f6bb"
    api_key = "tenant-20260407220546-28f6bb-key-28f6bb"

    # Create tenant configuration with the correct structure
    tenant_config = {
        "tenant_id": tenant_id,
        "name": "Debug Healthcare Organization",
        "plan": "enterprise",
        "description": "Debug tenant for healthcare AI agents",
        "industry": "healthcare",
        "compliance_frameworks": ["hipaa"],
        "created_at": "2026-04-07T22:05:46Z",
        "input_guardrails": {
            "tool_allowlist": {
                "enabled": True,
                "action": "block",
                "settings": {
                    "strict_mode": True,
                    "per_agent": {
                        "healthcare-doctor-trainee": ["patient_lookup", "prescription_check", "lab_results"],
                        "healthcare-ai-assistant": ["*"]
                    },
                    "per_role": {
                        "doctor": ["patient_lookup", "prescription_check", "lab_results", "diagnosis_aid"],
                        "admin": ["*"],
                        "nurse": ["patient_lookup", "lab_results"]
                    }
                }
            }
        },
        "output_guardrails": {
            "pii_anonymization": {
                "enabled": True,
                "action": "warn",
                "settings": {}
            }
        },
        "rbac": {
            "agents": {
                "healthcare-doctor-trainee": {
                    "role": "doctor",
                    "permissions": ["read", "write"]
                },
                "healthcare-ai-assistant": {
                    "role": "admin",
                    "permissions": ["read", "write", "admin"]
                }
            }
        },
        "quota": {
            "max_requests_per_minute": 100,
            "max_requests_per_day": 10000,
            "max_tokens_per_day": 1000000
        }
    }

    print(f"🔍 CREATING DEBUG TENANT")
    print("=" * 60)
    print(f"Tenant ID: {tenant_id}")
    print(f"API Key: {api_key}")
    print("=" * 60)

    try:
        # Create the tenant
        print(f"Creating tenant...")
        result = create_tenant(tenant_id, tenant_config, [api_key])
        print(f"✅ Tenant created successfully")

        print(f"\nTenant configuration:")
        print(json.dumps(result, indent=2))

        # Verify the setup
        print(f"\n🔍 VERIFYING SETUP")
        print("-" * 40)

        from storage.tenant_store import resolve_tenant_by_api_key, get_tenant

        # Test API key resolution
        resolved_tenant = resolve_tenant_by_api_key(api_key)
        print(f"API key resolves to: {resolved_tenant}")

        # Test config retrieval
        if resolved_tenant:
            tenant_data = get_tenant(resolved_tenant)
            if tenant_data and "input_guardrails" in tenant_data:
                if "tool_allowlist" in tenant_data["input_guardrails"]:
                    print(f"✅ Tool allowlist config found!")
                    tool_config = tenant_data["input_guardrails"]["tool_allowlist"]
                    print(f"Settings: {json.dumps(tool_config['settings'], indent=2)}")
                else:
                    print(f"❌ No tool_allowlist in input_guardrails")
            else:
                print(f"❌ No input_guardrails in tenant config")

        print(f"\n✅ Setup complete! You can now run your tests.")

        # Also test in the same process to see current state
        print(f"\n🔍 TESTING IN SAME PROCESS")
        print("-" * 40)
        from storage.tenant_store import _fallback_store
        print(f"Fallback store keys in same process: {list(_fallback_store.keys())}")

        return api_key

    except Exception as e:
        print(f"❌ Error creating tenant: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    create_debug_tenant()