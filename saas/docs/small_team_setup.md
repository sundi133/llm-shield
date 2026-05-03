# DevGuard for Small Teams - 5-Minute Setup

**Turn your team's AI usage safe with role-based guardrails**

## 🚀 Quick Start

### 1. Create Your Team (30 seconds)

```bash
# Create team and get API key
curl -X POST "https://shield.votal.ai/v1/saas/teams/create" \
  -H "Content-Type: application/json" \
  -d '{
    "team_name": "Your Startup Name",
    "admin_email": "you@yourcompany.com",
    "plan": "free"
  }'
```

**Response:**
```json
{
  "team_id": "team_abc123",
  "api_key": "dg_team_abc123_xyz789",
  "message": "Team created successfully"
}
```

**Save your API key!** `dg_team_abc123_xyz789`

### 2. Set Up Role-Based Policies (2 minutes)

Choose your team template:

#### 🏢 **Startup Template** (2-10 people)
```bash
export API_KEY="dg_team_abc123_xyz789"  # Your API key

curl -X POST "https://shield.votal.ai/v1/data-policies/tools/general_ai/policy" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "role_policies": [
      {
        "role": "founder",
        "action": "allow",
        "data_scope": ["all"],
        "input_rules": ["Can ask anything related to business and code"],
        "output_rules": ["Full access to AI capabilities"]
      },
      {
        "role": "senior_dev", 
        "action": "allow",
        "data_scope": ["code", "architecture", "debugging"],
        "input_rules": [
          "Can request complex code generation",
          "Can ask for architecture advice",
          "Can access debugging help"
        ],
        "output_rules": ["Show technical details and best practices"]
      },
      {
        "role": "junior_dev",
        "action": "redact", 
        "data_scope": ["code", "learning"],
        "redaction_level": "partial",
        "input_rules": [
          "Can ask for code explanations",
          "Can request learning resources", 
          "Cannot request complex architecture decisions"
        ],
        "output_rules": [
          "Provide educational explanations",
          "Hide advanced optimization details",
          "Focus on learning and understanding"
        ]
      },
      {
        "role": "intern",
        "action": "redact",
        "data_scope": ["learning"],
        "redaction_level": "full", 
        "input_rules": [
          "Can only ask basic programming questions",
          "Cannot access proprietary code patterns",
          "Limited to educational content"
        ],
        "output_rules": [
          "Provide beginner-friendly explanations",
          "Block complex technical details",
          "Focus on fundamentals"
        ]
      }
    ]
  }'
```

#### 🏗️ **Agency Template** (Client work)
```bash
curl -X POST "https://shield.votal.ai/v1/data-policies/tools/general_ai/policy" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "role_policies": [
      {
        "role": "project_manager",
        "action": "allow",
        "data_scope": ["project_planning", "communication"],
        "input_rules": [
          "Can ask for project planning help",
          "Can request client communication assistance",
          "Cannot access technical implementation details"
        ]
      },
      {
        "role": "lead_developer",
        "action": "allow", 
        "data_scope": ["all_technical"],
        "input_rules": ["Full technical access for project delivery"]
      },
      {
        "role": "contractor",
        "action": "block",
        "data_scope": ["specific_project_only"],
        "input_rules": [
          "Cannot access other client projects",
          "Cannot request proprietary code patterns", 
          "Limited to assigned project scope"
        ],
        "output_rules": [
          "Block cross-project information",
          "Hide agency proprietary methods",
          "Only show project-specific guidance"
        ]
      }
    ]
  }'
```

### 3. Add Team Members (30 seconds each)

```bash
# Add team members with roles
curl -X POST "https://shield.votal.ai/v1/saas/teams/$TEAM_ID/members" \
  -H "X-API-Key: $API_KEY" \
  -d "email=alice@company.com&role=senior_dev"

curl -X POST "https://shield.votal.ai/v1/saas/teams/$TEAM_ID/members" \
  -H "X-API-Key: $API_KEY" \  
  -d "email=bob@company.com&role=junior_dev"
```

### 4. Team Members Start Using AI (1 minute)

Share these instructions with your team:

#### **For Python Developers:**
```bash
pip install requests  # or openai

export DEVGUARD_API_KEY="dg_team_abc123_xyz789"
export DEVGUARD_USER_ROLE="senior_dev"  # or junior_dev, intern, etc.
```

```python
import requests

def safe_ai_chat(message, role="developer"):
    response = requests.post(
        "https://shield.votal.ai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.getenv('DEVGUARD_API_KEY')}",
            "X-User-Role": role,
            "Content-Type": "application/json"
        },
        json={
            "messages": [{"role": "user", "content": message}],
            "model": "gpt-4"
        }
    )
    return response.json()

# Usage
result = safe_ai_chat("Help me debug this Python code", role="senior_dev")
print(result['choices'][0]['message']['content'])
```

#### **For JavaScript Developers:**
```javascript
const DEVGUARD_API_KEY = "dg_team_abc123_xyz789";
const USER_ROLE = "senior_dev";

async function safeAIChat(message) {
  const response = await fetch("https://shield.votal.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${DEVGUARD_API_KEY}`,
      "X-User-Role": USER_ROLE,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      messages: [{role: "user", content: message}],
      model: "gpt-4"
    })
  });
  
  return response.json();
}

// Usage
safeAIChat("Help me with this React component").then(console.log);
```

## 🛡️ **What You Get Automatically**

### ✅ **Role-Based Protection**
- **Founders/Admins**: Full AI access
- **Senior Devs**: Technical depth, architecture advice
- **Junior Devs**: Learning-focused, simplified explanations  
- **Interns**: Basic concepts only, heavy guardrails

### ✅ **Built-in Safety**
- **No credential leaks**: API keys, passwords blocked automatically
- **No malicious code**: Harmful code generation prevented
- **Content filtering**: Inappropriate content blocked
- **Usage tracking**: Monitor team AI usage

### ✅ **Team Management**
- **Usage limits**: Free tier 1K requests/month
- **Member management**: Add/remove team members
- **Role assignment**: Change roles anytime
- **Audit logs**: See who asked what

## 🎯 **Role Examples**

### **Senior Developer Request:**
```
User: "Design a microservices architecture for our e-commerce platform"
AI: [Detailed technical response with architecture patterns, trade-offs, specific technologies]
```

### **Junior Developer Same Request:**
```
User: "Design a microservices architecture for our e-commerce platform"  
AI: [Simplified explanation focusing on learning concepts, with references to study materials]
```

### **Intern Same Request:**
```
User: "Design a microservices architecture for our e-commerce platform"
AI: "This is an advanced topic. Let me explain the basics of web applications first..."
```

## 💰 **Pricing**
- **Free**: 5 team members, 1K AI requests/month
- **Pro**: 20 members, 10K requests/month, custom roles ($29/month)
- **Enterprise**: Unlimited, advanced features ($99/month)

## 🔧 **Advanced Setup**

### Custom Guardrails (Pro+)
```bash
# Add custom rules for your domain
curl -X POST "https://shield.votal.ai/v1/data-policies/tools/custom_domain/policy" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "role_policies": [{
      "role": "contractor",
      "action": "block",
      "input_rules": ["Cannot ask about client_name_here", "Cannot access financial data"]
    }]
  }'
```

### Integration with Existing Tools
```bash
# Use with Cursor, VS Code, or any AI tool
export OPENAI_API_BASE="https://shield.votal.ai/v1"
export OPENAI_API_KEY="$DEVGUARD_API_KEY" 
```

## 📞 **Support**
- 📧 **Email**: support@votal.ai  
- 💬 **Discord**: Quick community help
- 📖 **Docs**: Full API documentation

**Setup time: 5 minutes. Team safety: Forever.**