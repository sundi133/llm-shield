#!/usr/bin/env python3
"""Create a test tenant with API key for frontend testing."""

import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.abspath('.'))

from storage.tenant_store import create_tenant, add_api_key
import uuid

def create_test_tenant():
    """Create a test tenant with API key."""
    tenant_id = "test-tenant-001"

    # Create tenant configuration
    tenant_config = {
        "name": "Test Healthcare Organization",
        "plan": "enterprise",
        "description": "Test tenant for healthcare AI agents",
        "industry": "healthcare",
        "compliance_frameworks": ["hipaa"],
        "created_at": "2026-04-08T00:00:00Z"
    }

    try:
        # Create the tenant
        print(f"Creating tenant: {tenant_id}")
        result = create_tenant(tenant_id, tenant_config)
        print(f"Tenant created: {result}")

        # Generate API key
        api_key = f"sk-test-{uuid.uuid4().hex[:16]}"

        # Add API key to tenant
        print(f"Adding API key: {api_key}")
        add_api_key(tenant_id, api_key)
        print(f"API key added successfully")

        print("\n✅ Test tenant created successfully!")
        print(f"🔑 Tenant ID: {tenant_id}")
        print(f"🔑 API Key: {api_key}")
        print(f"\nUse this API key in the frontend:")
        print(f"X-API-Key: {api_key}")

        return api_key

    except Exception as e:
        print(f"❌ Error creating tenant: {e}")
        return None

if __name__ == "__main__":
    create_test_tenant()