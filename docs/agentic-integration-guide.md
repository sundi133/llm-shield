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
from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from typing import Dict, Any
import requests

class GuardrailProtectedTool(BaseTool):
    name: str = "protected_tool"
    description: str = "Tool with built-in guardrails validation"
    
    def __init__(self, base_tool, agent_id, user_role, base_url, api_key):
        super().__init__()
        self.base_tool = base_tool
        self.agent_id = agent_id  
        self.user_role = user_role
        self.base_url = base_url
        self.api_key = api_key
        
    def _run(self, **kwargs) -> str:
        # Pre-authorization check
        auth_response = requests.post(
            f"{self.base_url}/v1/agents/authorize",
            headers={"X-API-Key": self.api_key},
            json={
                "agent_id": self.agent_id,
                "tool_name": self.name,
                "user_role": self.user_role
            }
        )
        
        auth_result = auth_response.json()
        if not auth_result["allowed"]:
            return f"Access denied: {auth_result['reason']}"
            
        # Execute original tool
        try:
            result = self.base_tool._run(**kwargs)
        except Exception as e:
            return f"Tool execution failed: {str(e)}"
        
        # Post-execution validation
        validation_response = requests.post(
            f"{self.base_url}/guardrails/output",
            headers={
                "X-API-Key": self.api_key,
                "X-User-Role": self.user_role,
                "X-Agent-ID": self.agent_id
            },
            json={
                "output": str(result),
                "context": {
                    "tool_name": self.name,
                    "tool_input": kwargs
                }
            }
        )
        
        validation = validation_response.json()
        
        if validation["safe"]:
            # Return sanitized output if available
            return validation.get("sanitized_output", result)
        else:
            return f"Output blocked by policy: {validation.get('reason', 'Unknown')}"

# Complete LangChain Agent with Guardrails
class GuardrailAgent:
    def __init__(self, base_url, api_key, agent_id, user_role):
        self.base_url = base_url
        self.api_key = api_key
        self.agent_id = agent_id
        self.user_role = user_role
        self.tools = []
        
    def add_protected_tool(self, tool_name, tool_func, description):
        """Add a tool with automatic guardrail protection"""
        class ProtectedTool(GuardrailProtectedTool):
            name = tool_name
            description = description
            
            def _run(self, query: str = ""):
                return super()._run(query=query)
                
        protected_tool = ProtectedTool(
            base_tool=tool_func,
            agent_id=self.agent_id,
            user_role=self.user_role,
            base_url=self.base_url,
            api_key=self.api_key
        )
        self.tools.append(protected_tool)
        return protected_tool
    
    def create_agent(self, llm):
        """Create LangChain agent with protected tools"""
        prompt = PromptTemplate.from_template("""
        You are a helpful assistant with access to tools. Use tools when needed.
        
        Available tools: {tools}
        
        Question: {input}
        {agent_scratchpad}
        """)
        
        agent = create_react_agent(llm, self.tools, prompt)
        return AgentExecutor(agent=agent, tools=self.tools, verbose=True)

# Usage Example
from langchain_openai import ChatOpenAI

# Initialize guardrail agent
guardrail_agent = GuardrailAgent(
    base_url="https://your-endpoint.ai",
    api_key="your-tenant-key",
    agent_id="customer-support-agent",
    user_role="support"
)

# Add protected tools
def customer_lookup_func(query):
    # Your actual customer lookup logic
    return f"Customer data for: {query}"

def ticket_creation_func(query):
    # Your ticket creation logic
    return f"Created ticket: {query}"

guardrail_agent.add_protected_tool("customer_lookup", customer_lookup_func, "Look up customer information")
guardrail_agent.add_protected_tool("create_ticket", ticket_creation_func, "Create support ticket")

# Create and run the agent
llm = ChatOpenAI(temperature=0)
agent_executor = guardrail_agent.create_agent(llm)

# Execute with built-in guardrails
result = agent_executor.invoke({"input": "Look up customer John Doe and create a ticket for billing issue"})
```

#### CrewAI Integration

```python
from crewai import Agent, Task, Crew, Tool
from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import requests

class GuardrailToolInput(BaseModel):
    query: str = Field(description="Input query for the tool")

class CrewAIGuardrailTool(BaseTool):
    name: str = "guardrail_protected_tool"
    description: str = "Tool with guardrail protection"
    args_schema: Type[BaseModel] = GuardrailToolInput
    
    def __init__(self, base_url, api_key, agent_id, user_role, actual_tool_func, **kwargs):
        super().__init__(**kwargs)
        self.base_url = base_url
        self.api_key = api_key
        self.agent_id = agent_id
        self.user_role = user_role
        self.actual_tool_func = actual_tool_func
    
    def _run(self, query: str) -> str:
        # Pre-authorization
        auth_response = requests.post(
            f"{self.base_url}/v1/agents/authorize",
            headers={"X-API-Key": self.api_key},
            json={
                "agent_id": self.agent_id,
                "tool_name": self.name,
                "user_role": self.user_role
            }
        )
        
        if not auth_response.json().get("allowed"):
            return f"Access denied: {auth_response.json().get('reason')}"
        
        # Execute tool
        result = self.actual_tool_func(query)
        
        # Post-validation
        validation_response = requests.post(
            f"{self.base_url}/guardrails/output",
            headers={
                "X-API-Key": self.api_key,
                "X-User-Role": self.user_role,
                "X-Agent-ID": self.agent_id
            },
            json={
                "output": str(result),
                "context": {
                    "tool_name": self.name,
                    "tool_input": {"query": query}
                }
            }
        )
        
        validation = validation_response.json()
        if validation["safe"]:
            return validation.get("sanitized_output", result)
        else:
            return f"Output blocked: {validation.get('reason')}"

# CrewAI Integration Example
def create_protected_crew():
    # Define protected tools
    customer_tool = CrewAIGuardrailTool(
        name="customer_lookup",
        description="Look up customer information with role-based access control",
        base_url="https://your-endpoint.ai",
        api_key="your-tenant-key", 
        agent_id="support-crew-agent",
        user_role="support",
        actual_tool_func=lambda query: f"Customer data: {query}"
    )
    
    billing_tool = CrewAIGuardrailTool(
        name="billing_access",
        description="Access billing information (admin/billing roles only)", 
        base_url="https://your-endpoint.ai",
        api_key="your-tenant-key",
        agent_id="support-crew-agent", 
        user_role="support",
        actual_tool_func=lambda query: f"Billing info: {query}"
    )
    
    # Define agents with role-specific access
    support_agent = Agent(
        role='Customer Support Specialist',
        goal='Help customers with their issues while respecting data privacy policies',
        backstory='You are a support agent with access to customer lookup but limited billing access.',
        tools=[customer_tool],  # Only customer lookup for support role
        verbose=True
    )
    
    billing_agent = Agent(
        role='Billing Specialist', 
        goal='Handle billing-related inquiries with full access to financial data',
        backstory='You are a billing specialist with full access to customer and billing information.',
        tools=[customer_tool, billing_tool],  # Full access for billing role
        verbose=True
    )
    
    # Define tasks
    customer_task = Task(
        description='Look up customer information for John Doe and summarize account status',
        agent=support_agent,
        expected_output='Customer account summary with appropriate data masking'
    )
    
    billing_task = Task(
        description='Review billing information for customer John Doe',
        agent=billing_agent,
        expected_output='Billing analysis with sensitive data properly handled'
    )
    
    # Create crew
    crew = Crew(
        agents=[support_agent, billing_agent],
        tasks=[customer_task, billing_task],
        verbose=True
    )
    
    return crew

# Usage
crew = create_protected_crew()
result = crew.kickoff()
```

#### AutoGen Integration

```python
import autogen
from autogen import AssistantAgent, UserProxyAgent
import requests

class GuardrailAssistantAgent(AssistantAgent):
    def __init__(self, base_url, api_key, agent_id, user_role, **kwargs):
        super().__init__(**kwargs)
        self.base_url = base_url
        self.api_key = api_key
        self.agent_id = agent_id
        self.user_role = user_role
    
    def _validate_output(self, output, tool_name=None, tool_input=None):
        """Validate agent output through guardrails"""
        validation_response = requests.post(
            f"{self.base_url}/guardrails/output",
            headers={
                "X-API-Key": self.api_key,
                "X-User-Role": self.user_role,
                "X-Agent-ID": self.agent_id
            },
            json={
                "output": str(output),
                "context": {
                    "tool_name": tool_name or "general_response",
                    "tool_input": tool_input or {}
                }
            }
        )
        
        validation = validation_response.json()
        if validation["safe"]:
            return validation.get("sanitized_output", output)
        else:
            return f"Response blocked by policy: {validation.get('reason')}"

# AutoGen Multi-Agent with Guardrails
def create_autogen_with_guardrails():
    config_list = [{"model": "gpt-4", "api_key": "your-openai-key"}]
    
    # Support agent with limited permissions
    support_agent = GuardrailAssistantAgent(
        name="support_assistant",
        base_url="https://your-endpoint.ai",
        api_key="your-tenant-key",
        agent_id="autogen-support-agent",
        user_role="support",
        llm_config={"config_list": config_list},
        system_message="You are a customer support agent. Help customers but protect sensitive data."
    )
    
    # Admin agent with full permissions  
    admin_agent = GuardrailAssistantAgent(
        name="admin_assistant", 
        base_url="https://your-endpoint.ai",
        api_key="your-tenant-key",
        agent_id="autogen-admin-agent", 
        user_role="admin",
        llm_config={"config_list": config_list},
        system_message="You are an admin with full access to all customer data and systems."
    )
    
    user_proxy = UserProxyAgent(
        name="user_proxy",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=3,
        code_execution_config={"work_dir": "autogen_output"}
    )
    
    return support_agent, admin_agent, user_proxy

# Usage
support_agent, admin_agent, user_proxy = create_autogen_with_guardrails()

# Conversation with guardrail validation
user_proxy.initiate_chat(
    support_agent,
    message="Help customer John Doe with his billing issue - customer ID: 12345"
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

## Production Use Cases

### Healthcare AI Assistant

```python
# Healthcare assistant with doctor/nurse/patient roles
class HealthcareAssistant:
    def __init__(self, user_role, base_url, api_key):
        self.user_role = user_role
        self.base_url = base_url
        self.api_key = api_key
        
        # Role-specific tool access
        self.tools = {
            "doctor": ["patient_lookup", "diagnosis_update", "prescribe_medication", "view_records"],
            "nurse": ["patient_lookup", "update_vitals", "schedule_appointment", "view_basic_records"],
            "admin": ["patient_lookup", "billing_access", "schedule_appointment", "generate_reports"],
            "patient": ["view_own_records", "schedule_appointment", "message_provider"]
        }
    
    def execute_with_guardrails(self, tool_name, **kwargs):
        """Execute any tool with automatic guardrail validation"""
        if tool_name not in self.tools.get(self.user_role, []):
            return {"error": f"Role '{self.user_role}' not authorized for tool '{tool_name}'"}
        
        # Pre-authorization
        auth_response = requests.post(
            f"{self.base_url}/v1/agents/authorize",
            headers={"X-API-Key": self.api_key},
            json={
                "agent_id": "healthcare-assistant",
                "tool_name": tool_name,
                "user_role": self.user_role
            }
        )
        
        if not auth_response.json().get("allowed"):
            return {"error": auth_response.json().get("reason")}
        
        # Execute tool (your implementation)
        result = self._execute_tool(tool_name, **kwargs)
        
        # Post-validation with guardrails
        validation_response = requests.post(
            f"{self.base_url}/guardrails/output",
            headers={
                "X-API-Key": self.api_key,
                "X-User-Role": self.user_role,
                "X-Agent-ID": "healthcare-assistant"
            },
            json={
                "output": str(result),
                "context": {
                    "tool_name": tool_name,
                    "tool_input": kwargs
                }
            }
        )
        
        validation = validation_response.json()
        if validation["safe"]:
            return validation.get("sanitized_output", result)
        else:
            return {"error": f"Output blocked: {validation.get('reason')}"}
    
    def _execute_tool(self, tool_name, **kwargs):
        # Your actual tool implementations
        tools = {
            "patient_lookup": lambda patient_id: f"Patient {patient_id}: John Doe, DOB: 1985-03-15, SSN: 123-45-6789",
            "diagnosis_update": lambda patient_id, diagnosis: f"Updated diagnosis for {patient_id}: {diagnosis}",
            "prescribe_medication": lambda patient_id, medication: f"Prescribed {medication} for patient {patient_id}",
            "view_records": lambda patient_id: f"Medical records for patient {patient_id}",
            "update_vitals": lambda patient_id, vitals: f"Updated vitals for {patient_id}: {vitals}",
            "schedule_appointment": lambda patient_id, date: f"Scheduled appointment for {patient_id} on {date}",
            "view_basic_records": lambda patient_id: f"Basic info for patient {patient_id}",
            "billing_access": lambda patient_id: f"Billing info for patient {patient_id}: $1,234.56",
            "generate_reports": lambda report_type: f"Generated {report_type} report",
            "view_own_records": lambda: "Your medical records",
            "message_provider": lambda message: f"Message sent to provider: {message}"
        }
        return tools.get(tool_name, lambda **kw: "Tool not implemented")(**kwargs)

# Usage Examples
doctor = HealthcareAssistant("doctor", "https://your-endpoint.ai", "your-api-key")
nurse = HealthcareAssistant("nurse", "https://your-endpoint.ai", "your-api-key") 
patient = HealthcareAssistant("patient", "https://your-endpoint.ai", "your-api-key")

# Doctor can access full patient records (with PII redaction based on policy)
doctor_result = doctor.execute_with_guardrails("patient_lookup", patient_id="12345")

# Nurse gets limited access with automatic data sanitization
nurse_result = nurse.execute_with_guardrails("patient_lookup", patient_id="12345") 

# Patient blocked from accessing other patients' data
patient_result = patient.execute_with_guardrails("patient_lookup", patient_id="67890")
```

### Financial Services Agent

```python
class FinancialServicesAgent:
    def __init__(self, user_role, compliance_level="strict"):
        self.user_role = user_role
        self.compliance_level = compliance_level
        
        # Compliance-aware role permissions
        self.role_permissions = {
            "financial_advisor": {
                "tools": ["client_portfolio", "investment_advice", "risk_assessment"],
                "data_access": "client_data_filtered",
                "compliance_level": "high"
            },
            "customer_service": {
                "tools": ["account_inquiry", "transaction_history", "balance_check"],
                "data_access": "limited_pii",
                "compliance_level": "medium"
            },
            "compliance_officer": {
                "tools": ["audit_trail", "risk_report", "regulatory_check"],
                "data_access": "full_audit",
                "compliance_level": "highest"
            },
            "customer": {
                "tools": ["view_balance", "transfer_funds", "statement_download"],
                "data_access": "own_account_only", 
                "compliance_level": "standard"
            }
        }

# LangChain integration with financial compliance
from langchain.agents import create_react_agent
from langchain.tools import Tool

def create_compliant_financial_agent(user_role):
    agent = FinancialServicesAgent(user_role)
    
    # Create tools with built-in compliance
    tools = []
    for tool_name in agent.role_permissions[user_role]["tools"]:
        tool = Tool(
            name=tool_name,
            description=f"Financial tool: {tool_name} (compliance: {agent.compliance_level})",
            func=lambda query, tn=tool_name: agent.execute_with_guardrails(tn, query=query)
        )
        tools.append(tool)
    
    # Create agent with compliance-aware tools
    return create_react_agent(llm=ChatOpenAI(), tools=tools, prompt=prompt_template)
```

### E-commerce Customer Support

```python
# CrewAI implementation for e-commerce support
from crewai import Agent, Task, Crew, Tool

class ECommerceGuardrailTool(BaseTool):
    name = "ecommerce_tool"
    description = "E-commerce tool with customer data protection"
    
    def __init__(self, tool_name, user_role, **kwargs):
        super().__init__(**kwargs)
        self.tool_name = tool_name
        self.user_role = user_role
        
        # E-commerce specific policies
        self.policies = {
            "customer_lookup": {"pii_redaction": True, "roles": ["support", "manager"]},
            "order_management": {"financial_masking": True, "roles": ["support", "manager", "admin"]},
            "refund_processing": {"approval_required": True, "roles": ["manager", "admin"]},
            "inventory_access": {"supplier_data_hidden": True, "roles": ["inventory", "manager"]},
        }
    
    def _run(self, query: str) -> str:
        # Check tool-specific policies
        if self.tool_name not in self.policies:
            return f"Tool {self.tool_name} not recognized"
            
        policy = self.policies[self.tool_name]
        if self.user_role not in policy["roles"]:
            return f"Access denied: {self.user_role} not authorized for {self.tool_name}"
        
        # Execute with guardrails validation
        result = self._execute_tool(query)
        
        # Apply data policies
        if policy.get("pii_redaction"):
            result = self._redact_pii(result)
        if policy.get("financial_masking"):
            result = self._mask_financial_data(result)
            
        return result

def create_ecommerce_support_crew():
    # Support agent with customer-facing tools
    support_agent = Agent(
        role='Customer Support Representative',
        goal='Help customers while protecting their data privacy',
        backstory='Customer support specialist with access to order and account info.',
        tools=[
            ECommerceGuardrailTool("customer_lookup", "support"),
            ECommerceGuardrailTool("order_management", "support")
        ]
    )
    
    # Manager agent with elevated permissions
    manager_agent = Agent(
        role='Support Manager', 
        goal='Handle escalated issues and approvals',
        backstory='Support manager with approval authority for refunds.',
        tools=[
            ECommerceGuardrailTool("customer_lookup", "manager"),
            ECommerceGuardrailTool("order_management", "manager"),
            ECommerceGuardrailTool("refund_processing", "manager")
        ]
    )
    
    return Crew(agents=[support_agent, manager_agent], tasks=[], verbose=True)
```

## Multi-Framework Deployment Pattern

```python
# Universal guardrail wrapper for any framework
class UniversalGuardrailWrapper:
    def __init__(self, base_url, api_key, agent_id, default_user_role="user"):
        self.base_url = base_url
        self.api_key = api_key  
        self.agent_id = agent_id
        self.default_user_role = default_user_role
        
    def wrap_langchain_tool(self, tool, user_role=None):
        """Wrap any LangChain tool with guardrails"""
        role = user_role or self.default_user_role
        return GuardrailProtectedTool(tool, self.agent_id, role, self.base_url, self.api_key)
        
    def wrap_crewai_tool(self, tool_func, tool_name, user_role=None):
        """Wrap any CrewAI tool function with guardrails"""
        role = user_role or self.default_user_role
        return CrewAIGuardrailTool(
            name=tool_name,
            base_url=self.base_url,
            api_key=self.api_key,
            agent_id=self.agent_id,
            user_role=role,
            actual_tool_func=tool_func
        )
        
    def wrap_openai_function(self, func_schema, func_impl, user_role=None):
        """Wrap OpenAI function calling with guardrails"""
        role = user_role or self.default_user_role
        
        def protected_func(**kwargs):
            # Pre-authorization
            if not self._check_authorization(func_schema["name"], role):
                return {"error": "Access denied"}
                
            # Execute function
            result = func_impl(**kwargs)
            
            # Post-validation
            return self._validate_output(result, func_schema["name"], role)
            
        return protected_func
    
    def _check_authorization(self, tool_name, user_role):
        response = requests.post(
            f"{self.base_url}/v1/agents/authorize",
            headers={"X-API-Key": self.api_key},
            json={"agent_id": self.agent_id, "tool_name": tool_name, "user_role": user_role}
        )
        return response.json().get("allowed", False)
        
    def _validate_output(self, output, tool_name, user_role):
        response = requests.post(
            f"{self.base_url}/guardrails/output",
            headers={
                "X-API-Key": self.api_key,
                "X-User-Role": user_role,
                "X-Agent-ID": self.agent_id
            },
            json={
                "output": str(output),
                "context": {"tool_name": tool_name}
            }
        )
        
        validation = response.json()
        if validation["safe"]:
            return validation.get("sanitized_output", output)
        else:
            return {"error": f"Blocked: {validation.get('reason')}"}

# Usage: Works with any framework
wrapper = UniversalGuardrailWrapper(
    base_url="https://your-endpoint.ai",
    api_key="your-api-key",
    agent_id="universal-assistant"
)

# Protect LangChain tools
protected_langchain_tool = wrapper.wrap_langchain_tool(existing_langchain_tool, "manager")

# Protect CrewAI tools  
protected_crewai_tool = wrapper.wrap_crewai_tool(my_tool_func, "data_access", "analyst")

# Protect OpenAI functions
protected_openai_func = wrapper.wrap_openai_function(schema, implementation, "admin")
```

## Best Practices

### Security
- Use least-privilege principle for role permissions
- Enable LLM validation for sensitive operations  
- Regularly audit tool access patterns
- Monitor for privilege escalation attempts
- Implement defense-in-depth with multiple validation layers

### Performance  
- Cache authorization results where appropriate
- Use role restrictions before expensive LLM validation
- Batch policy updates during maintenance windows
- Implement circuit breakers for external validation calls

### Compliance
- Document all role-to-tool mappings
- Log all authorization decisions  
- Regular review of data sanitization effectiveness
- Maintain audit trail for compliance reporting
- Test compliance scenarios with automated suites

### Development
- Start with restrictive permissions and gradually open access
- Use environment-specific API keys (dev/staging/prod)
- Implement comprehensive testing for all user roles
- Version control your agent and tool configurations
- Monitor false positive rates and adjust thresholds accordingly

## Support

- **API Documentation**: `/docs` endpoint
- **Integration Examples**: `GET /v1/agents/integration/examples`
- **Test Endpoint**: Run `test_agentic_guardrails.sh` 
- **Issues**: GitHub issues or support contact