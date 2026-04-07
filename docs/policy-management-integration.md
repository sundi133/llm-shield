# Policy Management through Function Calling

This guide shows how to integrate LLM Shield's policy management capabilities with your LiteLLM setup, allowing customers to manage data protection policies through natural language.

## Overview

With this integration, customers can:

- **Create data protection policies** through natural language
- **Test policies** against sample content  
- **Update role-based permissions** dynamically
- **Zero code changes** required - uses standard OpenAI function calling

## Customer Setup

### 1. Add Policy Tools to Your Function Calling Setup

```python
import openai
from llm_shield.core.policy_tools import POLICY_TOOLS

# Your existing OpenAI client setup
client = openai.OpenAI(
    base_url="https://your-litellm-proxy.com/v1", 
    api_key="your-api-key"
)

# Include policy tools in your function definitions
ALL_TOOLS = [
    # Your existing tools...
    {
        "type": "function",
        "function": {
            "name": "search_database",
            "description": "Search customer database",
            # ... your tool definition
        }
    },
    
    # Add policy management tools
    *POLICY_TOOLS  # This adds create_data_policy, update_data_policy, etc.
]
```

### 2. Natural Language Policy Management

Customers can now manage policies through conversation:

```python
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{
        "role": "user", 
        "content": """
        I need to create a data protection policy for our healthcare application.
        Requirements:
        - Block HIV/AIDS diagnoses for 'nurse' role
        - Allow 'doctor' role to see all medical data  
        - Redact SSNs for everyone except 'admin'
        - Tenant ID: healthcare-corp
        """
    }],
    tools=ALL_TOOLS,
    tool_choice="auto"
)

# LLM automatically generates appropriate function calls
```

### 3. Real-Time Policy Testing

```python
# Test policies before deploying
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{
        "role": "user",
        "content": """
        Test our healthcare policy against this sample:
        
        "Patient: John Doe, SSN: 123-45-6789, Diagnosis: HIV+"
        
        How would this appear to a 'nurse' vs 'doctor'?
        """
    }],
    tools=ALL_TOOLS
)
```

## Backend Configuration

### 1. Environment Variables

Set these on your LLM Shield server:

```bash
# Required for policy management
SHIELD_BASE_URL=https://your-shield-server.com
SHIELD_ADMIN_KEY=your-admin-key

# Redis for policy storage (existing)
UPSTASH_REDIS_REST_URL=https://your-redis.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-token
```

### 2. LiteLLM Configuration

Update your `config.yaml`:

```yaml
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4
      api_key: os.environ/OPENAI_API_KEY

guardrails:
  # Existing guardrails
  - guardrail_name: "votal-input-guard"
    litellm_params:
      guardrail: votal_guardrail.VotalGuardrail
      mode: "pre_call"
      default_on: true

  - guardrail_name: "votal-output-guard"
    litellm_params:
      guardrail: votal_guardrail.VotalGuardrail
      mode: "post_call"  
      default_on: true
      
  # Enhanced with policy support - no changes needed!
  # Existing guardrails automatically load tenant policies
```

## Policy Structure

### Basic Policy Format

```json
{
  "policy_id": "healthcare_hipaa",
  "name": "HIPAA Healthcare Protection",
  "patterns": [
    {
      "regex": "\\b(HIV|AIDS|Cancer)\\b",
      "type": "medical_diagnosis", 
      "sensitivity": "critical",
      "replacement": "[DIAGNOSIS_REDACTED]"
    },
    {
      "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
      "type": "ssn",
      "sensitivity": "critical", 
      "replacement": "[SSN_REDACTED]"
    }
  ],
  "roles": {
    "nurse": {
      "medical_diagnosis": "redact",
      "ssn": "block"
    },
    "doctor": {
      "medical_diagnosis": "allow",
      "ssn": "redact" 
    },
    "admin": {
      "medical_diagnosis": "allow", 
      "ssn": "allow"
    }
  }
}
```

### Role Actions

| Action | Description | Result |
|--------|-------------|--------|
| `allow` | Show original data | No redaction |
| `redact` | Replace with placeholder | `[SSN_REDACTED]` |
| `block` | Block entire response | Error returned |

## API Endpoints

Your LLM Shield server exposes these endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/shield/policies/{tenant_id}` | GET | List policies |
| `/v1/shield/policies/{tenant_id}` | POST | Create policy |
| `/v1/shield/policies/{tenant_id}/{policy_id}` | PUT | Update policy |
| `/v1/shield/policies/{tenant_id}/{policy_id}` | DELETE | Delete policy |
| `/v1/shield/policies/test` | POST | Test policy |

## Example Workflows

### 1. Healthcare Organization

```python
# Customer conversation
user: "Set up HIPAA compliance for tenant 'hospital-123'"

# LLM generates:
create_data_policy(
    tenant_id="hospital-123",
    policy_id="hipaa_medical",
    name="HIPAA Medical Data Protection",
    patterns=[
        {"regex": "\\b(HIV|AIDS|Cancer)\\b", "type": "diagnosis", "sensitivity": "critical"},
        {"regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "type": "ssn", "sensitivity": "critical"}
    ],
    roles={
        "patient": {"diagnosis": "block", "ssn": "block"},
        "nurse": {"diagnosis": "redact", "ssn": "block"},
        "doctor": {"diagnosis": "allow", "ssn": "redact"}
    }
)
```

### 2. Financial Institution

```python
user: "Create banking data protection - hide account numbers from contractors"

# LLM generates:
create_data_policy(
    tenant_id="bank-456", 
    policy_id="banking_privacy",
    patterns=[
        {"regex": "\\b\\d{10,12}\\b", "type": "account_number", "sensitivity": "high"},
        {"regex": "\\$[\\d,]+\\.\\d{2}", "type": "currency", "sensitivity": "medium"}
    ],
    roles={
        "contractor": {"account_number": "block", "currency": "redact"},
        "employee": {"account_number": "redact", "currency": "allow"},
        "manager": {"account_number": "allow", "currency": "allow"}
    }
)
```

### 3. Policy Updates

```python
user: "Update our policy - nurses can now see general diagnoses but not HIV"

# LLM generates:
update_data_policy(
    tenant_id="hospital-123",
    policy_id="hipaa_medical", 
    patterns=[
        {"regex": "\\b(HIV|AIDS)\\b", "type": "sensitive_diagnosis", "sensitivity": "critical"},
        {"regex": "\\b(diabetes|hypertension|flu)\\b", "type": "general_diagnosis", "sensitivity": "medium"}
    ],
    roles={
        "nurse": {"sensitive_diagnosis": "block", "general_diagnosis": "allow"}
    }
)
```

## Data Flow

```
1. Customer creates policy via natural language
     ↓
2. LLM generates function call (create_data_policy)
     ↓ 
3. Function call executes → API call to Shield
     ↓
4. Policy stored in Redis with tenant isolation
     ↓
5. Tool output guardrail loads policy automatically
     ↓
6. Data filtered based on user role + policy rules
     ↓
7. Customer sees role-appropriate data
```

## Security & Isolation

- **Tenant Isolation**: Each tenant's policies are stored separately
- **Role-Based Access**: Same data, different views per role
- **Redis Storage**: Cached with TTL for performance
- **Audit Trail**: All policy changes logged
- **Real-time Updates**: Changes take effect immediately

## Troubleshooting

### Policy Not Applied

1. Check tenant ID in headers:
   ```python
   headers = {"X-Tenant-ID": "your-tenant", "X-User-Role": "nurse"}
   ```

2. Verify policy enabled:
   ```python
   list_data_policies(tenant_id="your-tenant")
   ```

3. Test policy:
   ```python
   test_data_policy(
       tenant_id="your-tenant",
       policy_id="your-policy", 
       test_content="sample data",
       test_user_role="nurse"
   )
   ```

### Performance Issues

1. **Check Redis Connection**: Policies load from Redis cache
2. **Pattern Complexity**: Complex regex patterns slow execution
3. **Policy Count**: Limit to 10-20 policies per tenant

### Function Calls Not Working

1. **Tool Definitions**: Ensure `POLICY_TOOLS` included in tools list
2. **Environment Variables**: Set `SHIELD_BASE_URL` and `SHIELD_ADMIN_KEY`
3. **API Keys**: Customer needs proper API key with policy management permissions

## Advanced Features

### Custom Replacement Text

```python
patterns=[
    {
        "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
        "type": "ssn",
        "replacement": "[PERSONAL_ID_HIDDEN_PER_POLICY]"  # Custom text
    }
]
```

### Priority-Based Processing

```python
# Higher priority policies process first
create_data_policy(priority=10)  # Processes before priority=100
```

### Bulk Policy Creation

```python
# Create multiple policies at once
response = requests.post(f"{SHIELD_BASE_URL}/v1/shield/policies/{tenant_id}/bulk", 
                        json=[policy1, policy2, policy3])
```

This integration provides enterprise-grade data protection with zero code changes - customers manage sophisticated policies through natural conversation!