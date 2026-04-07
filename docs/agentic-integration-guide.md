# Enhanced Agentic Guardrails Integration Guide

Complete guide for integrating role-based tool authorization and validation into your AI applications.

## Overview

The enhanced `/guardrails/output` endpoint now provides unified validation for:

- **Role-based tool authorization** - Control which users can access specific tools
- **LLM validation** - Use AI to validate tool calls for appropriateness
- **Data sanitization** - Apply tool-specific data protection policies
- **Standard output guardrails** - PII detection, toxicity, bias, etc.

## Quick Start

### 1. Register Your Agent

```bash
curl -X POST "https://your-endpoint.ai/v1/agents/register" \
  -H "X-API-Key: your-tenant-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "customer-support-bot",
    "name": "Customer Support Assistant", 
    "tools": ["ticket_lookup", "customer_info", "refund_process"],
    "role_permissions": {
      "admin": ["ticket_lookup", "customer_info", "refund_process"],
      "support": ["ticket_lookup", "customer_info"],
      "customer": ["ticket_lookup"]
    }
  }'
```

### 2. Configure Tool Policies

```bash
curl -X PUT "https://your-endpoint.ai/v1/agents/tools/policies" \
  -H "X-API-Key: your-tenant-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "policies": {
      "customer_info": {
        "data_sanitization": {
          "redact_ssn": true,
          "mask_phone": true
        },
        "llm_validation": {
          "enabled": true,
          "prompt": "Is accessing customer info appropriate for {user_role}?",
          "confidence_threshold": 0.8
        },
        "role_restrictions": {
          "admin": "allow",
          "support": "allow", 
          "customer": "block"
        }
      }
    }
  }'
```

### 3. Validate Tool Calls

```bash
curl -X POST "https://your-endpoint.ai/guardrails/output" \
  -H "X-API-Key: your-tenant-api-key" \
  -H "X-User-Role: support" \
  -H "X-Agent-ID: customer-support-bot" \
  -H "Content-Type: application/json" \
  -d '{
    "output": "Customer: John Doe, SSN: 123-45-6789, Phone: 555-1234",
    "context": {
      "tool_name": "customer_info",
      "tool_input": {"customer_id": "12345"}
    }
  }'
```

## Integration Patterns

### Pattern 1: Pre-Authorization Check

Check authorization before making tool calls:

```python
import requests

def check_tool_authorization(agent_id, tool_name, user_role):
    response = requests.post(
        f"{base_url}/v1/agents/authorize",
        headers={"X-API-Key": api_key},
        json={
            "agent_id": agent_id,
            "tool_name": tool_name,
            "user_role": user_role
        }
    )
    return response.json()

# Check before calling tool
auth_result = check_tool_authorization("support-bot", "customer_info", "support")
if auth_result["allowed"]:
    # Proceed with tool call
    tool_result = call_customer_info_tool(customer_id)
    # Validate output
    validated = validate_tool_output(tool_result, "customer_info", "support")
else:
    return {"error": auth_result["reason"]}
```

### Pattern 2: Post-Execution Validation

Validate tool outputs after execution:

```python
def validate_tool_output(output, tool_name, user_role, agent_id):
    response = requests.post(
        f"{base_url}/guardrails/output",
        headers={
            "X-API-Key": api_key,
            "X-User-Role": user_role,
            "X-Agent-ID": agent_id
        },
        json={
            "output": output,
            "context": {
                "tool_name": tool_name,
                "tool_input": tool_input  # Original input params
            }
        }
    )
    return response.json()

# After tool execution
tool_result = customer_lookup_tool(customer_id="12345")
validation = validate_tool_output(
    output=tool_result,
    tool_name="customer_lookup", 
    user_role="support",
    agent_id="support-bot"
)

if validation["safe"]:
    return validation["guardrail_results"]  # Sanitized output
else:
    return {"error": "Tool output blocked by policy"}
```

### Pattern 3: Framework Integration

#### LangChain Integration

```python
from langchain.tools import BaseTool
from typing import Dict, Any

class GuardrailProtectedTool(BaseTool):
    def __init__(self, base_tool, agent_id, user_role):
        self.base_tool = base_tool
        self.agent_id = agent_id  
        self.user_role = user_role
        
    def _run(self, **kwargs) -> str:
        # Pre-authorization
        auth_check = check_tool_authorization(
            self.agent_id, self.name, self.user_role
        )
        if not auth_check["allowed"]:
            return f"Access denied: {auth_check['reason']}"
            
        # Execute tool
        result = self.base_tool._run(**kwargs)
        
        # Post-validation
        validation = validate_tool_output(
            result, self.name, self.user_role, self.agent_id
        )
        
        if validation["safe"]:
            # Return sanitized output
            return validation.get("sanitized_output", result)
        else:
            return "Output blocked by content policy"

# Usage
protected_lookup = GuardrailProtectedTool(
    base_tool=customer_lookup_tool,
    agent_id="support-bot",
    user_role="support"
)
```

#### OpenAI Function Calling

```python
import openai

def create_protected_function(func_schema, agent_id, user_role):
    def protected_func(**kwargs):
        # Check authorization
        auth = check_tool_authorization(agent_id, func_schema["name"], user_role)
        if not auth["allowed"]:
            return {"error": auth["reason"]}
            
        # Call original function
        result = original_function(**kwargs)
        
        # Validate output
        validation = validate_tool_output(result, func_schema["name"], user_role, agent_id)
        return validation if validation["safe"] else {"error": "Blocked by policy"}
    
    return protected_func

# Protect your function calls
protected_customer_info = create_protected_function(
    func_schema=customer_info_schema,
    agent_id="support-bot", 
    user_role=current_user.role
)
```

## Role-Based Access Control

### Supported Roles

Common role hierarchy (customize as needed):

```json
{
  "admin": "Full access to all tools",
  "manager": "Management-level tools and data access",
  "member": "Standard user tools and limited data",
  "support": "Customer support tools with PII restrictions", 
  "user": "Basic user tools only",
  "customer": "Self-service tools only",
  "guest": "Public information only"
}
```

### Role Permission Actions

- **`allow`** - Full access to tool and outputs
- **`redact`** - Access granted but sensitive data redacted
- **`block`** - Access completely denied

### Healthcare Example

```json
{
  "role_permissions": {
    "doctor": ["patient_lookup", "diagnosis", "prescribe", "update_records"],
    "nurse": ["patient_lookup", "schedule", "basic_updates"],
    "admin": ["patient_lookup", "schedule", "billing", "reports"],
    "patient": ["schedule", "view_own_records"],
    "guest": []
  }
}
```

## Tool Policy Configuration

### Data Sanitization

```json
{
  "data_sanitization": {
    "redact_ssn": true,
    "mask_phone": true,
    "mask_email": false,
    "patterns": [
      {
        "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
        "replacement": "[SSN_REDACTED]",
        "description": "Social Security Numbers"
      },
      {
        "regex": "\\b[A-Z]{2}\\d{8}\\b", 
        "replacement": "[ID_REDACTED]",
        "description": "Government IDs"
      }
    ]
  }
}
```

### LLM Validation

```json
{
  "llm_validation": {
    "enabled": true,
    "prompt": "Evaluate if this {tool_name} request is appropriate for {user_role}:\\n\\nTool Input: {tool_input}\\nTool Output: {tool_output}\\n\\nConsider: data sensitivity, user permissions, business context.\\nRespond: APPROPRIATE or INAPPROPRIATE with reasoning.",
    "confidence_threshold": 0.75
  }
}
```

### Complete Policy Example

```json
{
  "policies": {
    "patient_lookup": {
      "data_sanitization": {
        "redact_ssn": true,
        "mask_phone": true,
        "patterns": [
          {"regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]"}
        ]
      },
      "llm_validation": {
        "enabled": true,
        "prompt": "Is this patient lookup appropriate for {user_role}? Medical necessity required.",
        "confidence_threshold": 0.8
      },
      "role_restrictions": {
        "doctor": "allow",
        "nurse": "allow", 
        "admin": "allow",
        "patient": "block",
        "guest": "block"
      }
    },
    "billing_info": {
      "role_restrictions": {
        "admin": "allow",
        "billing": "allow",
        "doctor": "redact",
        "nurse": "block",
        "patient": "block"
      }
    }
  }
}
```

## Error Handling

### Authorization Errors

```json
{
  "allowed": false,
  "reason": "Role 'patient' not authorized for tool 'update_records'",
  "agent_config": {...},
  "tool_policy": {...}
}
```

### Validation Errors

```json
{
  "safe": false,
  "action": "block",
  "guardrail_results": [
    {
      "guardrail": "tool_authorization",
      "passed": false,
      "action": "block", 
      "message": "LLM validation failed: Inappropriate access to sensitive data",
      "details": {
        "llm_validation": {
          "confidence": 0.2,
          "is_appropriate": false,
          "reason": "Patient data access without medical justification"
        }
      }
    }
  ]
}
```

## Deployment Checklist

- [ ] Register all agents with proper tool assignments
- [ ] Configure role-based permissions for each tool
- [ ] Set up data sanitization patterns for sensitive tools
- [ ] Enable LLM validation for high-risk operations
- [ ] Test authorization flows for each user role
- [ ] Implement error handling for blocked actions
- [ ] Monitor guardrail metrics and violations
- [ ] Document role permissions for your team

## Monitoring & Analytics

Track these metrics for security and compliance:

- **Authorization failures by role/tool**
- **LLM validation confidence scores**
- **Data redaction frequency**
- **Policy violation patterns**
- **Tool usage by user role**

Query audit logs:
```bash
curl "https://your-endpoint.ai/v1/admin/audit?filter=tool_authorization&hours=24" \
  -H "X-Admin-Key: your-admin-key"
```

## Best Practices

### Security
- Use least-privilege principle for role permissions
- Enable LLM validation for sensitive operations
- Regularly audit tool access patterns
- Monitor for privilege escalation attempts

### Performance  
- Cache authorization results where appropriate
- Use role restrictions before expensive LLM validation
- Batch policy updates during maintenance windows

### Compliance
- Document all role-to-tool mappings
- Log all authorization decisions
- Regular review of data sanitization effectiveness
- Maintain audit trail for compliance reporting

## Support

- **API Documentation**: `/docs` endpoint
- **Integration Examples**: `GET /v1/agents/integration/examples`
- **Test Endpoint**: Run `test_agentic_guardrails.sh` 
- **Issues**: GitHub issues or support contact