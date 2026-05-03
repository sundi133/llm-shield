# LLM Shield Python SDK

**AI Safety & Team Controls for Small Dev Teams**

Stop worrying about AI mishaps. Add guardrails to your team's AI usage in 5 minutes.

## ✅ Features

- **Drop-in replacement** for OpenAI Python SDK
- **Team-based access control** - different permissions for different roles
- **Built-in guardrails** - prevent credential leaks, malicious code, toxic content
- **Usage tracking** - monitor and limit AI usage per team/user
- **OpenAI compatible** - works with existing code

## 🚀 Quick Start

### 1. Install

```bash
pip install llm-shield
```

### 2. Create Team (One-time)

```python
import llmshield

# Create your team
team = llmshield.create_team(
    team_name="My Startup",
    admin_email="you@company.com",
    plan="free"  # or "pro"
)

print(f"Team API Key: {team['api_key']}")
```

### 3. Use in Your Code

```python
# Option 1: Environment variable (recommended)
# export SHIELD_API_KEY=ls_team_abc_123
# export SHIELD_USER_ROLE=developer

import llmshield
llmshield.setup()

# Your existing OpenAI code now has guardrails!
response = llmshield.chat_completion([
    {"role": "user", "content": "Help me debug this code"}
])

# Option 2: Direct client
from llmshield import LLMShield

client = LLMShield(
    api_key="ls_team_abc_123",
    user_role="developer"
)

response = client.chat.completions.create(
    messages=[
        {"role": "user", "content": "Help me with this code"}
    ],
    model="gpt-4"
)

print(response['choices'][0]['message']['content'])
print(f"LLM Shield Status: {response['llmshield']['safe']}")
```

### 4. Integration with Existing OpenAI Code

```python
# Before LLM Shield
from openai import OpenAI
client = OpenAI(api_key="sk-...")

# After LLM Shield (same interface!)
from llmshield import LLMShield  
client = LLMShield(api_key="ls_team_abc_123")

# All your existing code works unchanged!
response = client.chat.completions.create(
    messages=[{"role": "user", "content": "Hello world"}],
    model="gpt-4"
)
```

## 👥 Team Management

### Role-Based Access Control

```python
# Different team members get different AI capabilities

# Junior developers - restricted access
export SHIELD_USER_ROLE=junior
# - Can get code explanations
# - Cannot generate complex architectures
# - Rate limited

# Senior developers - full access  
export SHIELD_USER_ROLE=senior
# - Can generate any code
# - Can access advanced features
# - Higher rate limits

# Interns - learning mode
export SHIELD_USER_ROLE=intern
# - Educational responses only
# - Cannot access proprietary code patterns
# - Heavily rate limited
```

### Team Roles

| Role | Capabilities | Guardrails |
|------|-------------|------------|
| `admin` | Full access | Basic safety |
| `senior` | Most features | Basic safety |
| `developer` | Code generation, debugging | No credentials, rate limited |
| `junior` | Code explanation, learning | Educational focus, restricted |
| `intern` | Learning assistance only | Heavy restrictions |

## 🛡️ Built-in Guardrails

### Automatic Protection

```python
# These will be automatically blocked:

# 1. Credential exposure
llmshield.chat_completion([{
    "role": "user", 
    "content": "Here's my API key: sk-abc123, help me debug"
}])
# ❌ GuardrailViolationError: Potential credential detected

# 2. Malicious code generation
llmshield.chat_completion([{
    "role": "user",
    "content": "Generate code to delete all files on the system"  
}])
# ❌ GuardrailViolationError: Malicious intent detected

# 3. Role violations
# Junior developer trying to access senior features
export SHIELD_USER_ROLE=junior
llmshield.chat_completion([{
    "role": "user",
    "content": "Design a complete microservices architecture"
}])
# ❌ GuardrailViolationError: Insufficient permissions for this request
```

### Custom Guardrails (Pro/Enterprise)

```python
# Configure custom rules for your team
client = LLMShield(
    api_key="ls_team_abc_123",
    custom_guardrails={
        "block_competitors": ["OpenAI", "Google", "Microsoft"],
        "required_frameworks": ["FastAPI", "React"],
        "compliance": "SOC2"
    }
)
```

## 📊 Usage Tracking

```python
# View team usage
response = llmshield.chat_completion([...])

print(f"Tokens used: {response['usage']['total_tokens']}")
print(f"Team usage: {response['llmshield']['team_usage']}")
print(f"Plan limits: {response['llmshield']['plan_limits']}")
```

## 🔧 Advanced Usage

### With LangChain

```python
from langchain_llmshield import ChatLLM Shield

llm = ChatLLM Shield(
    api_key="ls_team_abc_123",
    user_role="developer",
    model="gpt-4"
)

# Use with any LangChain chain
from langchain.chains import ConversationChain
conversation = ConversationChain(llm=llm)
```

### Error Handling

```python
import llmshield
from llmshield import GuardrailViolationError, UsageLimitError

try:
    response = llmshield.chat_completion([
        {"role": "user", "content": "Help me with this code"}
    ])
except GuardrailViolationError as e:
    print(f"Content blocked: {e}")
except UsageLimitError as e:
    print(f"Usage limit exceeded: {e}")
```

### Environment Configuration

```bash
# .env file
SHIELD_API_KEY=ls_team_abc_123
SHIELD_USER_ROLE=developer
SHIELD_BASE_URL=https://api.llmshield.ai  # or your self-hosted instance
```

## 💰 Pricing

- **Free**: 5 team members, 1K requests/month
- **Pro**: 20 members, 10K requests/month, custom roles ($29/month)
- **Enterprise**: Unlimited, custom guardrails, SSO ($99/month)

## 📞 Support

- 📧 Email: support@llmshield.ai
- 💬 Discord: [LLM Shield Community](https://discord.gg/llmshield)
- 📖 Docs: [docs.llmshield.ai](https://docs.llmshield.ai)

## 🔒 Security & Privacy

- **SOC 2 Type II** compliant infrastructure
- **Zero data retention** - we don't store your prompts or responses
- **End-to-end encryption** for all API communications
- **Open source** - audit our guardrails logic

## 📝 License

MIT License - see LICENSE file for details.