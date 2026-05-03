# DevGuard One-Liner Setup for Small Teams

## 🚀 Super Quick Start (30 seconds)

### Copy-Paste Team Setup:

```bash
curl -s https://raw.githubusercontent.com/your-repo/devguard-setup/main/quick_setup.sh | bash -s "Your Team Name" "admin@yourcompany.com"
```

### Manual Quick Setup:

```bash
# 1. Create team (replace with your info)
TEAM_RESPONSE=$(curl -s -X POST "https://shield.votal.ai/v1/saas/teams/create" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "Your Team", "admin_email": "you@company.com", "plan": "free"}')

# 2. Extract API key
API_KEY=$(echo $TEAM_RESPONSE | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
echo "Your API Key: $API_KEY"

# 3. Set up startup roles
curl -s -X POST "https://shield.votal.ai/v1/data-policies/tools/general_ai/policy" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "role_policies": [
      {
        "role": "founder", 
        "action": "allow",
        "data_scope": ["all"]
      },
      {
        "role": "senior_dev",
        "action": "allow", 
        "data_scope": ["code", "architecture"]
      },
      {
        "role": "junior_dev",
        "action": "redact",
        "data_scope": ["code", "learning"],
        "output_rules": ["Provide educational explanations", "Simplify complex concepts"]
      },
      {
        "role": "intern", 
        "action": "redact",
        "data_scope": ["learning"],
        "output_rules": ["Beginner-friendly explanations only", "Focus on fundamentals"]
      }
    ]
  }'

# 4. Save config for your team
echo "export DEVGUARD_API_KEY=\"$API_KEY\"" > .devguard_config
echo "export DEVGUARD_USER_ROLE=\"senior_dev\"  # Change to your role" >> .devguard_config
echo ""
echo "✅ Setup complete! Run: source .devguard_config"
echo "📖 Test with: curl -X POST https://shield.votal.ai/v1/chat/completions -H \"Authorization: Bearer $API_KEY\" -H \"X-User-Role: senior_dev\" -d '{\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'"
```

## 📋 Team Member Instructions

Share this with each team member:

### For Developers:

```bash
# 1. Get your team's API key from admin
export DEVGUARD_API_KEY="dg_team_abc_xyz789"

# 2. Set your role  
export DEVGUARD_USER_ROLE="senior_dev"  # or junior_dev, intern, founder

# 3. Test AI chat with guardrails
python -c "
import requests, os
response = requests.post(
    'https://shield.votal.ai/v1/chat/completions',
    headers={
        'Authorization': f'Bearer {os.getenv(\"DEVGUARD_API_KEY\")}',
        'X-User-Role': os.getenv('DEVGUARD_USER_ROLE'),
        'Content-Type': 'application/json'
    },
    json={'messages': [{'role': 'user', 'content': 'Help me write a Python function'}]}
)
print('AI Response:', response.json()['choices'][0]['message']['content'])
print('Safety Status:', response.json()['devguard']['safe'])
"
```

### Environment File (.env):

```bash
# .env file for your project
DEVGUARD_API_KEY=dg_team_abc_xyz789
DEVGUARD_USER_ROLE=senior_dev
DEVGUARD_BASE_URL=https://shield.votal.ai
```

## 🎯 Role Examples

### What Each Role Can Do:

| Request | Founder | Senior Dev | Junior Dev | Intern |
|---------|---------|-----------|------------|--------|
| "Design our API architecture" | ✅ Full details | ✅ Technical depth | ⚠️ Simplified version | ❌ Too advanced |
| "Debug this Python code" | ✅ Yes | ✅ Yes | ✅ With explanations | ✅ Basic help only |
| "Optimize our database queries" | ✅ Yes | ✅ Yes | ⚠️ Educational focus | ❌ Blocked |
| "What is a variable?" | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Perfect for learning |

## 📊 Usage Monitoring

```bash
# Check team usage
curl -X GET "https://shield.votal.ai/v1/saas/teams/$TEAM_ID" \
  -H "X-API-Key: $DEVGUARD_API_KEY"

# Response shows:
# {
#   "current_usage": 45,
#   "usage_limit": 1000,
#   "plan": "free",
#   "members": [...]
# }
```

## 🔧 Integration Examples

### With Existing OpenAI Code:

```python
# Before DevGuard
import openai
client = openai.OpenAI(api_key="sk-...")

# After DevGuard (minimal change!)
import requests
import os

def openai_compatible_chat(**kwargs):
    response = requests.post(
        "https://shield.votal.ai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.getenv('DEVGUARD_API_KEY')}",
            "X-User-Role": os.getenv('DEVGUARD_USER_ROLE', 'developer')",
            "Content-Type": "application/json"
        },
        json=kwargs
    )
    return response.json()

# Use exactly like OpenAI
result = openai_compatible_chat(
    messages=[{"role": "user", "content": "Help me code"}],
    model="gpt-4"
)
```

### With LangChain:

```python
from langchain_community.llms import OpenAI

# Point LangChain to DevGuard
llm = OpenAI(
    openai_api_base="https://shield.votal.ai/v1",
    openai_api_key=os.getenv('DEVGUARD_API_KEY'),
    headers={"X-User-Role": os.getenv('DEVGUARD_USER_ROLE')}
)
```

### With Cursor/VS Code:

```json
// settings.json
{
  "cursor.ai.provider": "openai",
  "cursor.ai.baseUrl": "https://shield.votal.ai/v1", 
  "cursor.ai.apiKey": "dg_team_abc_xyz789",
  "cursor.ai.headers": {
    "X-User-Role": "senior_dev"
  }
}
```

## 💰 Pricing

- **Free**: 5 members, 1K requests/month
- **Pro**: 20 members, 10K requests/month ($29/month)  
- **Enterprise**: Unlimited everything ($99/month)

## 📞 Questions?

- 📧 Email: support@votal.ai
- 💬 Quick help: Your team admin  
- 📖 Full docs: https://shield.votal.ai/docs

**Total setup time: 30 seconds. Team AI safety: Forever.** 🛡️