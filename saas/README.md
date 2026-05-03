# 🛡️ DevGuard for Small Dev Teams

**Add role-based AI guardrails to your team in 30 seconds**

Stop worrying about AI mishaps. Get enterprise-grade AI safety without enterprise complexity.

![DevGuard Demo](https://img.shields.io/badge/Setup%20Time-30%20seconds-green)
![Price](https://img.shields.io/badge/Price-$29%2Fmonth-blue)
![Team Size](https://img.shields.io/badge/Team%20Size-2--20%20people-orange)

## 🎯 Quick Start

### ⚡ 30-Second Setup

```bash
# 1. Create your team
curl -X POST "https://shield.votal.ai/v1/saas/teams/create" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "Your Team", "admin_email": "you@company.com", "plan": "free"}'

# 2. Use the API key in your code
export DEVGUARD_API_KEY="dg_team_abc_xyz"  # From step 1 response
export DEVGUARD_USER_ROLE="senior_dev"     # Your role

# 3. Replace OpenAI calls
python -c "
import requests, os
response = requests.post('https://shield.votal.ai/v1/chat/completions',
  headers={'Authorization': f'Bearer {os.getenv(\"DEVGUARD_API_KEY\")}', 'X-User-Role': os.getenv('DEVGUARD_USER_ROLE')},
  json={'messages': [{'role': 'user', 'content': 'Help me code!'}]}
)
print(response.json()['choices'][0]['message']['content'])
"
```

**Done!** Your AI now has role-based guardrails. ✅

## 🚀 Integration Options

### 🎯 **Choose Your Integration**

| Integration | Setup Time | Best For |
|-------------|------------|----------|
| [**🔥 Cursor**](integrations/cursor/) | 30 seconds | AI code editor users |
| [**🐍 Python SDK**](sdk/python/) | 1 minute | Python developers |
| [**🌐 Direct API**](#direct-api) | 30 seconds | Any language |
| [**🛠️ Team Script**](scripts/) | 2 minutes | Full team setup |

### **Popular Integrations:**

<details>
<summary><strong>🔥 Cursor (Most Popular)</strong></summary>

**Add to Cursor settings.json:**
```json
{
  "cursor.apiKey": "dg_team_abc_xyz",
  "cursor.apiBase": "https://shield.votal.ai/v1", 
  "cursor.headers": {"X-User-Role": "senior_dev"}
}
```

**Or use our automated setup:**
```bash
curl -fsSL https://shield.votal.ai/setup-cursor.sh | bash
```

[📖 Full Cursor Setup Guide →](integrations/cursor/)
</details>

<details>
<summary><strong>🐍 Python SDK</strong></summary>

```bash
pip install devguard
```

```python
from devguard import DevGuard

client = DevGuard(
  api_key="dg_team_abc_xyz",
  user_role="senior_dev"
)

# Same interface as OpenAI
response = client.chat.completions.create(
  messages=[{"role": "user", "content": "Help me code"}]
)
```

[📖 Full Python SDK Guide →](sdk/python/)
</details>

<details>
<summary><strong>🌐 Direct API</strong></summary>

**Works with any language:**

```javascript
// JavaScript
const response = await fetch("https://shield.votal.ai/v1/chat/completions", {
  method: "POST",
  headers: {
    "Authorization": "Bearer dg_team_abc_xyz",
    "X-User-Role": "senior_dev"
  },
  body: JSON.stringify({
    messages: [{role: "user", content: "Help me code"}]
  })
});
```

```bash
# curl
curl -X POST "https://shield.votal.ai/v1/chat/completions" \
  -H "Authorization: Bearer dg_team_abc_xyz" \
  -H "X-User-Role: senior_dev" \
  -d '{"messages": [{"role": "user", "content": "Help me code"}]}'
```
</details>

## 🎭 Role-Based AI Experience

### **Same Question, Different Responses:**

**Question: "Design a microservices architecture"**

| Role | Response Style | Example |
|------|---------------|---------|
| **👑 Founder** | Business + Technical | "Consider team size, costs, and complexity. Here's a phased approach..." |
| **👨‍💻 Senior Dev** | Full Technical Depth | "Use API Gateway pattern with service mesh. Here's the implementation..." |
| **👩‍💻 Junior Dev** | Learning-Focused | "Let's break this down step-by-step. First, understand monoliths vs microservices..." |
| **🎓 Intern** | Fundamentals | "That's advanced! Let's start with basic web applications. A microservice is..." |

## 🛡️ Built-in Safety Features

### ✅ **Automatic Protection:**
- **Credential Detection**: Blocks API keys, passwords, secrets
- **Malicious Code**: Prevents harmful code generation  
- **Role Enforcement**: Appropriate responses for experience level
- **Usage Monitoring**: Track and limit AI usage per team

### ✅ **Team Management:**
- **Role Assignment**: founder, senior_dev, junior_dev, intern
- **Usage Tracking**: Monitor requests per team member
- **Audit Logs**: See who asked what, when
- **Access Control**: Project-specific permissions

## 📊 Team Templates

### **🏢 Startup (2-10 people)**
```bash
# Setup startup roles
curl -X POST "https://shield.votal.ai/v1/data-policies/tools/general_ai/policy" \
  -H "X-API-Key: $DEVGUARD_API_KEY" \
  -d @examples/startup_template.json
```
**Roles**: founder, senior_dev, junior_dev, intern

### **🏗️ Agency (5-25 people)**  
```bash
# Setup agency roles
curl -X POST "https://shield.votal.ai/v1/data-policies/tools/general_ai/policy" \
  -H "X-API-Key: $DEVGUARD_API_KEY" \
  -d @examples/agency_template.json
```
**Roles**: project_manager, lead_developer, contractor

### **🎓 Bootcamp (20-100 people)**
**Roles**: instructor, teaching_assistant, student

[📁 See all templates →](examples/)

## 🧪 Test It Works

### **Test 1: Basic Functionality**
```bash
curl -X POST "https://shield.votal.ai/v1/chat/completions" \
  -H "Authorization: Bearer $DEVGUARD_API_KEY" \
  -H "X-User-Role: senior_dev" \
  -d '{"messages": [{"role": "user", "content": "Hello!"}]}'
```

### **Test 2: Safety Check**
```bash
curl -X POST "https://shield.votal.ai/v1/chat/completions" \
  -H "Authorization: Bearer $DEVGUARD_API_KEY" \
  -H "X-User-Role: senior_dev" \
  -d '{"messages": [{"role": "user", "content": "My password is 123456"}]}'
```
**Expected**: ❌ Blocked by credential detection

### **Test 3: Role Differences**
Ask the same question with different roles and see different responses:
- `X-User-Role: senior_dev` → Technical depth
- `X-User-Role: junior_dev` → Learning focus  
- `X-User-Role: intern` → Fundamentals only

## 📁 Repository Structure

```
saas/
├── README.md                    # 👈 You are here
├── api/                        # SaaS API routes  
│   ├── routes_teams.py         # Team management
│   └── routes_chat.py          # OpenAI-compatible chat
├── sdk/
│   └── python/                 # Python SDK
├── integrations/
│   ├── cursor/                 # Cursor setup & extension
│   └── vscode/                 # VS Code integration
├── examples/                   # Role configuration templates
│   ├── startup_template.json
│   ├── agency_template.json  
│   └── healthcare_config.json
├── scripts/                    # Setup automation
│   ├── team_setup_wizard.py   # Interactive setup
│   └── deploy_test.py          # Deployment testing
└── docs/                       # Detailed documentation
    ├── small_team_setup.md     # Step-by-step guide
    └── one_liner_setup.md      # Quick reference
```

## 💰 Pricing

| Plan | Team Size | Requests/Month | Price | Best For |
|------|-----------|----------------|-------|----------|
| **Free** | 5 members | 1,000 | $0 | Getting started |
| **Pro** | 20 members | 10,000 | $29/month | Growing teams |
| **Enterprise** | Unlimited | Unlimited | $99/month | Scale-ups |

**vs. Enterprise Solutions**: 300x less expensive ($10,000+/year → $29/month)

## 🎯 Use Cases

### **👥 Development Teams**
- **Problem**: Junior devs get overwhelmed by advanced AI responses
- **Solution**: Learning-focused responses appropriate to experience level
- **Result**: Faster learning, better code quality

### **🏢 Agencies** 
- **Problem**: Contractors working on different client projects
- **Solution**: Project-isolated AI access with audit trails
- **Result**: Client confidentiality + productive AI usage

### **🎓 Bootcamps**
- **Problem**: Students at different learning stages
- **Solution**: Progressive AI complexity based on skill level  
- **Result**: Optimal learning progression

### **🚀 Startups**
- **Problem**: Mixed experience levels, need AI safety
- **Solution**: Role-based access with automatic safety
- **Result**: Productive + safe AI usage across the team

## 📞 Support & Community

- 📧 **Email**: support@votal.ai
- 💬 **Discord**: [DevGuard Community](https://discord.gg/devguard)
- 📖 **Docs**: https://shield.votal.ai/docs  
- 🐛 **Issues**: GitHub Issues
- 📱 **Twitter**: [@devguard_ai](https://twitter.com/devguard_ai)

## 🚀 Quick Links

| What You Want | Where To Go |
|---------------|-------------|
| **🔥 Setup Cursor in 30 seconds** | [integrations/cursor/](integrations/cursor/) |
| **🐍 Python SDK** | [sdk/python/](sdk/python/) |  
| **👥 Full team setup** | [scripts/team_setup_wizard.py](scripts/team_setup_wizard.py) |
| **📋 Copy-paste configs** | [docs/one_liner_setup.md](docs/one_liner_setup.md) |
| **🎯 Role templates** | [examples/](examples/) |
| **🧪 Test deployment** | [scripts/deploy_test.py](scripts/deploy_test.py) |

## 🏆 Why DevGuard?

| Feature | DevGuard | Enterprise Tools | Raw ChatGPT |
|---------|----------|------------------|-------------|
| **Setup Time** | 30 seconds | 3+ months | N/A |
| **Price** | $29/month | $10,000+/year | Per-user |
| **Role-Based AI** | ✅ Built-in | ✅ Complex setup | ❌ None |
| **Team Management** | ✅ Simple | ❌ Requires IT | ❌ Individual |
| **Safety Guardrails** | ✅ Automatic | ✅ Manual config | ❌ None |
| **Learning Optimization** | ✅ Role-appropriate | ❌ One-size-fits-all | ❌ Generic |

---

**Ready to make your team's AI usage safe and productive?**

[🚀 **Start Free Trial**](https://shield.votal.ai/signup) • [📖 **View Full Docs**](docs/) • [💬 **Join Community**](https://discord.gg/devguard)