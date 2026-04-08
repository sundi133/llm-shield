# 🖥️ LLM Shield Admin Portal - Complete Guide

## **📊 Overview**

The Enhanced Admin Portal provides a comprehensive web interface for managing all LLM Shield policies, agents, and guardrails. **All policies can be viewed, configured, and tested** through this modern, responsive interface.

## **🎯 Key Features**

### **✅ What's Included:**

#### **1. Dashboard & Overview**
- Real-time system metrics
- Tenant configuration summary  
- Active agents count
- Tool policies overview
- System health status

#### **2. Agent Management**
- **View all registered agents** with tools and permissions
- **Create new agents** with role-based tool access
- **Edit agent configurations** and role permissions
- **Delete agents** with confirmation
- **Agent registry** with searchable table

#### **3. Tool Policy Management**
- **Data sanitization rules** (PII redaction patterns)
- **Role-based restrictions** (allow/redact/block per role)
- **LLM validation settings** (confidence thresholds)
- **Custom regex patterns** for sensitive data detection
- **Policy templates** for common use cases

#### **4. Guardrails Configuration**
- **Input guardrails** (topic restriction, safety, PII detection)
- **Output guardrails** (PII leakage, bias, tone, competitors)
- **Live testing interface** with role simulation
- **Guardrail results visualization**
- **Real-time policy testing**

#### **5. Role & Permissions**
- **Role hierarchy management**
- **Tool access matrix** (role × tool permissions)
- **Permission templates** (healthcare, finance, etc.)
- **Role-based data access** visualization

#### **6. Monitoring & Analytics**
- **Audit logs** with filtering
- **Usage analytics** and trends
- **Policy violation alerts**
- **Performance metrics**
- **Compliance reporting**

## **🚀 Quick Start**

### **1. Access the Portal**
```bash
# Open in browser
https://your-llm-shield-domain.com/static/enhanced-admin-portal.html
```

### **2. Authentication**
- Enter your **API Key** (tenant-specific)
- Enter your **RunPod Token** (if using RunPod)
- Credentials are stored securely in browser localStorage

### **3. Navigation Sections**

#### **📊 Overview**
- **Dashboard**: System metrics and health
- **Tenants**: Multi-tenant management

#### **🤖 Agent Management**  
- **Agents Registry**: View/edit all agents
- **Create Agent**: Register new AI agents
- **Roles & Permissions**: Manage role hierarchy

#### **🛡️ Data Protection**
- **Tool Policies**: Configure data sanitization
- **Data Sanitization**: PII detection patterns
- **LLM Validation**: AI-powered policy validation

#### **🔒 Guardrails**
- **Input Guardrails**: Pre-processing filters
- **Output Guardrails**: Post-processing protection
- **Test Guardrails**: Live testing interface

#### **📊 Monitoring**
- **Audit Log**: Track all policy changes
- **Analytics**: Usage trends and metrics
- **Alerts**: Real-time violation notifications

## **🏥 Healthcare Use Case Example**

### **Complete Healthcare Setup via Portal:**

#### **1. Register Healthcare Agents**
```javascript
// Via Portal: Agents Registry → + New Agent
{
  "agent_id": "healthcare-doctor",
  "name": "Doctor AI Assistant",
  "tools": ["patient_lookup", "prescribe_medication", "view_records"],
  "role_permissions": {
    "doctor": ["patient_lookup", "prescribe_medication", "view_records"],
    "nurse": ["patient_lookup"],
    "patient": []
  }
}
```

#### **2. Configure Data Policies**
```javascript
// Via Portal: Tool Policies → patient_lookup
{
  "data_sanitization": {
    "patterns": [
      {"regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]"},
      {"regex": "\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b", "replacement": "[PHONE_REDACTED]"}
    ]
  },
  "role_restrictions": {
    "doctor": "allow",
    "nurse": "redact", 
    "patient": "block"
  }
}
```

#### **3. Test Live Protection**
```javascript
// Via Portal: Test Guardrails
Input: "Patient: John Doe, SSN: 123-45-6789, Phone: 555-1234"
Role: "nurse"
Agent: "healthcare-nurse"

Expected Output: "Patient: John Doe, SSN: [SSN_REDACTED], Phone: [PHONE_REDACTED]"
```

## **🔧 API Integration**

The portal integrates with **all LLM Shield APIs**:

### **Core APIs Used:**
- `GET /v1/tenant/me` - Tenant configuration
- `GET /v1/agents/registry` - Agent management
- `GET/PUT /v1/agents/tools/policies` - Tool policies
- `POST /v1/agents/authorize` - Authorization testing
- `POST /guardrails/output` - Live guardrail testing

### **Authentication Headers:**
```javascript
{
  'Authorization': 'Bearer YOUR_RUNPOD_TOKEN',
  'X-API-Key': 'YOUR_TENANT_API_KEY',
  'X-User-Role': 'doctor|nurse|admin|patient',  // For testing
  'X-Agent-ID': 'healthcare-doctor'             // For context
}
```

## **📱 Responsive Design**

- **Modern dark theme** with professional styling
- **Responsive layout** works on desktop/tablet/mobile
- **Interactive components** with real-time updates
- **Syntax highlighting** for JSON configuration
- **Toast notifications** for actions and errors

## **🔐 Security Features**

### **Secure Credential Management:**
- Credentials stored in browser localStorage (not hardcoded)
- Secure API key entry with masking
- Session-based authentication
- HTTPS-only communication

### **Role-Based UI:**
- Interface adapts to user permissions
- Sensitive actions require confirmation
- Audit trail for all administrative actions
- Read-only mode for restricted users

## **🎨 Customization**

### **Theme Customization:**
```css
:root {
  --bg: #0a0a0f;          /* Main background */
  --accent: #6366f1;       /* Primary accent color */
  --success: #10b981;      /* Success indicators */
  --danger: #ef4444;       /* Error/warning indicators */
}
```

### **Adding New Sections:**
1. Add navigation item in sidebar
2. Create corresponding section div
3. Implement `loadSectionData()` handler
4. Add API integration functions

## **🚀 Production Deployment**

### **1. Environment Setup**
```bash
# No hardcoded credentials in code
# Users enter credentials via secure prompts
# Credentials stored in browser localStorage only
```

### **2. HTTPS Deployment**
- Deploy over HTTPS for security
- Configure proper CORS headers
- Set up reverse proxy if needed

### **3. Access Control**
```javascript
// Optional: Add authentication layer
if (!isAuthenticated()) {
  redirectToLogin();
}
```

## **🔄 API Reference Summary**

| Feature | Endpoint | Description |
|---------|----------|-------------|
| **Tenant Config** | `GET /v1/tenant/me` | Current tenant settings |
| **Agent Registry** | `GET /v1/agents/registry` | All registered agents |
| **Create Agent** | `POST /v1/agents/register` | Register new agent |
| **Tool Policies** | `GET/PUT /v1/agents/tools/policies` | Data protection rules |
| **Authorization** | `POST /v1/agents/authorize` | Check tool permissions |
| **Test Guardrails** | `POST /guardrails/output` | Live policy testing |
| **Supported Roles** | `GET /v1/agents/roles` | Available user roles |
| **Usage Stats** | `GET /v1/tenant/me/usage` | Quota and usage data |

## **📈 Next Steps**

### **Immediate Enhancements:**
1. **Modal dialogs** for create/edit operations
2. **Drag-and-drop** policy configuration
3. **Bulk operations** for agent management
4. **Export/import** policy configurations
5. **Real-time notifications** for policy violations

### **Advanced Features:**
1. **Multi-tenant dashboard** for service providers
2. **Policy versioning** and rollback
3. **A/B testing** for guardrail configurations
4. **Machine learning** policy recommendations
5. **Integration** with external identity providers

The Enhanced Admin Portal provides **complete visibility and control** over your LLM Shield deployment! 🎯✨