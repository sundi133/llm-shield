# Enterprise Role-Based Access Control Configuration

## Overview

The LLM Shield system provides fully generic, tenant-specific role-based access control that adapts to any organization's structure and data policies.

## How It Works

### 1. **Automatic Detection**
- Role-based guardrails auto-activate when `user_role` and `tenant_id` are present
- No manual configuration required for basic protection
- Works across all endpoints: `/chat/completions`, `/chat/agent`, `/guardrails/*`

### 2. **Tenant-Specific Policies**
Each organization defines their own:
- **Role names** (sales_rep, hr_manager, contractor, etc.)
- **Tool access** (customer_lookup, payroll, inventory, etc.)  
- **Data scopes** (financial, personal, confidential, etc.)
- **Actions** (allow, redact, block)

## Configuration Format

### Role Policy Structure
```json
{
  "tool_name": {
    "role_policies": [
      {
        "role": "your_role_name",
        "action": "allow|redact|block",
        "data_scope": ["data_type1", "data_type2"],
        "redaction_level": "none|partial|full",
        "input_rules": ["what this role can request"],
        "output_rules": ["what this role can see"]
      }
    ]
  }
}
```

### Example: Financial Services Firm
```json
{
  "client_portfolio": {
    "role_policies": [
      {
        "role": "portfolio_manager",
        "action": "allow",
        "data_scope": ["client_holdings", "performance_data", "risk_metrics"],
        "input_rules": [
          "Can request complete portfolio analysis",
          "Can access client investment history",
          "Can request performance attribution reports"
        ],
        "output_rules": [
          "Show detailed holdings and allocations",
          "Show performance vs benchmarks",
          "Include risk metrics and exposures"
        ]
      },
      {
        "role": "client_advisor",
        "action": "redact", 
        "data_scope": ["client_holdings"],
        "input_rules": [
          "Can request client portfolio summaries",
          "Cannot access detailed cost basis information",
          "Cannot request internal performance metrics"
        ],
        "output_rules": [
          "Show portfolio allocation summaries",
          "Redact specific position sizes and costs",
          "Hide internal benchmarking data"
        ]
      },
      {
        "role": "compliance_officer",
        "action": "allow",
        "data_scope": ["all"],
        "input_rules": ["Can access any client data for compliance monitoring"],
        "output_rules": ["Full access to all portfolio information"]
      }
    ]
  }
}
```

### Example: Manufacturing Company
```json
{
  "production_data": {
    "role_policies": [
      {
        "role": "plant_manager",
        "action": "allow",
        "data_scope": ["production_metrics", "quality_data", "cost_data"]
      },
      {
        "role": "line_supervisor", 
        "action": "redact",
        "data_scope": ["production_metrics"],
        "output_rules": [
          "Show production volumes and schedules",
          "Redact cost and margin information",
          "Hide supplier pricing data"
        ]
      },
      {
        "role": "quality_inspector",
        "action": "allow", 
        "data_scope": ["quality_data"],
        "input_rules": [
          "Can request quality metrics and defect reports",
          "Cannot access production costs or volumes"
        ]
      }
    ]
  }
}
```

## Setup Process

### 1. **Define Your Roles**
Identify organizational roles that need different data access levels:
```bash
# Examples across industries:
Healthcare: doctor, nurse, admin, patient
Finance: advisor, analyst, compliance, client  
Retail: manager, associate, contractor, customer
Tech: engineer, pm, security, intern
```

### 2. **Define Your Tools**
List the AI tools/functions your organization uses:
```bash
# Examples:
customer_lookup, inventory_check, payroll_query,
financial_analysis, document_search, reporting
```

### 3. **Configure Data Policies**
Use the API to set tenant-specific policies:
```bash
curl -X POST "/v1/data-policies/tools/{tool_name}/policy" \
  -H "X-API-Key: your-tenant-key" \
  -d @your_role_config.json
```

### 4. **Test Access Control**
Verify role-based behavior:
```bash
# Test different roles
curl -X POST "/v1/shield/chat/agent" \
  -H "X-User-Role: sales_rep" \
  -d '{"messages": [{"role": "user", "content": "Show customer financial data"}]}'
  
# Should get different responses for different roles
curl -X POST "/v1/shield/chat/agent" \
  -H "X-User-Role: finance_manager" \
  -d '{"messages": [{"role": "user", "content": "Show customer financial data"}]}'
```

## Features

### ✅ **Fully Generic**
- Any role names
- Any tool names  
- Any data types
- Any industry

### ✅ **Automatic Protection**
- Input validation (prevents privilege escalation)
- Output sanitization (prevents information leakage)
- Tool authorization (per existing data policies)

### ✅ **Enterprise-Ready**
- Tenant isolation
- Audit logging
- Performance optimized
- Redis-backed configuration

### ✅ **No Code Changes Required**
- Auto-detects role context
- Works with existing endpoints
- Backwards compatible

## Security Model

```
User Request → Role Validation → Tool Access Check → Response Sanitization
     ↓              ↓                    ↓                   ↓
   "sales_rep"   Can request        Tool allows         Redact sensitive  
   makes          customer data?     sales_rep?          data for role
   request             ↓                    ↓                   ↓
                 Input Guardrail    Data Policies    Output Guardrail
                  (Generic LLM)     (Tool-specific)   (Generic LLM)
```

## Best Practices

### 1. **Principle of Least Privilege**
- Start with restrictive policies
- Grant minimum access needed
- Regularly review and audit

### 2. **Clear Role Definitions**
- Document role responsibilities
- Avoid overlapping permissions
- Use meaningful role names

### 3. **Comprehensive Testing**
- Test all role + tool combinations
- Verify edge cases and boundary conditions
- Monitor for policy violations

### 4. **Regular Updates**
- Update policies as organization changes
- Remove inactive roles
- Add new tools and data types

The system scales to any organizational complexity while maintaining security and compliance.