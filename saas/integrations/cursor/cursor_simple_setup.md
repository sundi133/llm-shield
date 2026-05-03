# LLM Shield + Cursor: 2-Minute Setup

**Add role-based AI guardrails to your team's Cursor setup**

## ⚡ Super Quick Setup (30 seconds)

### Option 1: One-Liner Install

```bash
curl -fsSL https://raw.githubusercontent.com/your-repo/llmshield/main/setup_cursor_llmshield.sh | bash
```

### Option 2: Manual Setup (2 minutes)

#### Step 1: Get Your API Key
```bash
# Create team (30 seconds)
curl -X POST "https://shield.votal.ai/v1/saas/teams/create" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "My Team", "admin_email": "you@company.com", "plan": "free"}'

# Copy the API key from response: ls_team_abc_xyz
```

#### Step 2: Configure Cursor (30 seconds)

**Open Cursor Settings** (`Cmd/Ctrl + ,`) → **Open Settings JSON** and add:

```json
{
  "cursor.apiKey": "ls_team_abc_xyz",
  "cursor.apiBase": "https://shield.votal.ai/v1",
  "cursor.headers": {
    "X-User-Role": "senior_dev"
  }
}
```

#### Step 3: Set Your Role (10 seconds)

Change `"X-User-Role"` based on your experience:
- `"founder"` - Full access, business + technical
- `"senior_dev"` - Full technical depth 
- `"junior_dev"` - Learning-focused explanations
- `"intern"` - Fundamentals only

#### Step 4: Restart Cursor ✅

Done! Your AI now has role-based guardrails.

## 🎯 What Each Role Gets

### 👑 **Founder**
```
You: "Design our API architecture"
AI: [Complete technical + business analysis, scalability, costs, team implications]
```

### 👨‍💻 **Senior Dev** 
```
You: "Design our API architecture"  
AI: [Detailed technical patterns, performance considerations, implementation details]
```

### 👩‍💻 **Junior Dev**
```
You: "Design our API architecture"
AI: [Step-by-step learning explanation, fundamentals, resources for deeper study]
```

### 🎓 **Intern**
```
You: "Design our API architecture"
AI: "That's an advanced topic! Let me explain web applications first..."
```

## 🛡️ Automatic Safety Features

### ✅ **What Gets Blocked:**
- **Credential leaks**: "My API key is sk-abc123..." → ❌ Blocked
- **Malicious code**: "Generate code to delete files" → ❌ Blocked  
- **Role violations**: Intern asking for complex architecture → ❌ Redirected

### ✅ **What You Get:**
- **Appropriate responses** for your experience level
- **Learning progression** instead of overwhelming juniors
- **Audit trail** of who asked what
- **Usage tracking** per team member
- **Zero configuration** once set up

## 👥 Team Rollout (5 minutes total)

### For Team Admin:
1. **Create team account** (1 minute)
2. **Share API key** with team
3. **Assign roles** to each member

### For Each Developer:
1. **Add API key** to Cursor settings (30 seconds)
2. **Set their role** in headers (10 seconds)
3. **Restart Cursor** and test

## 🧪 Test It's Working

### Test 1: Basic Functionality
In Cursor chat, type: **"Help me write a Python function to reverse a string"**

**Expected result**: Response appropriate to your role + LLM Shield metadata

### Test 2: Safety Check
In Cursor chat, type: **"My password is 123456, help me debug"**

**Expected result**: ❌ Blocked by credential detection

### Test 3: Role Boundaries  
**Junior dev** asks: **"Design a complex microservices architecture"**

**Expected result**: Educational explanation focusing on learning, not implementation

## 🎯 Per-Project Configuration

### Option: Project-Specific Roles

Some projects need different access levels. Create `.vscode/settings.json` in your project:

```json
{
  "cursor.headers": {
    "X-User-Role": "contractor",
    "X-Project-Context": "client-project-alpha"  
  }
}
```

**Use cases:**
- **Client work**: Different contractors, different project access
- **Open source**: Public vs. private project permissions
- **Learning projects**: Educational mode for bootcamp students

## 📊 Team Benefits

### **For Productivity:**
- ✅ **Seniors** get full technical depth
- ✅ **Juniors** get learning-focused help  
- ✅ **Interns** get fundamentals without overwhelm
- ✅ **Everyone** gets appropriate responses

### **For Learning:**
- ✅ **Progressive complexity** based on experience
- ✅ **Educational context** for junior developers
- ✅ **Fundamentals focus** for beginners
- ✅ **Advanced patterns** for experienced developers

### **For Security:**
- ✅ **No credential leaks** in AI chats
- ✅ **Role-based access** to code patterns
- ✅ **Audit trail** of all AI interactions
- ✅ **Usage monitoring** and limits

### **For Management:**
- ✅ **Zero IT setup** required
- ✅ **Per-user role assignment**
- ✅ **Usage tracking** and analytics
- ✅ **Easy team member onboarding**

## 💰 Cost

- **Free tier**: 5 team members, 1K AI requests/month
- **Pro tier**: 20 members, 10K requests/month ($29/month)
- **vs. Enterprise solutions**: 300x less expensive ($10,000+/year)

## 🔧 Advanced Integration

### Environment Variables (Team-Wide)
```bash
# .env file  
SHIELD_API_KEY=ls_team_abc_xyz
SHIELD_USER_ROLE=senior_dev
SHIELD_BASE_URL=https://shield.votal.ai/v1

# Then in Cursor settings:
{
  "cursor.apiKey": "${env:SHIELD_API_KEY}",
  "cursor.headers": {
    "X-User-Role": "${env:SHIELD_USER_ROLE}"
  }
}
```

### Git Hook Integration
```bash
# .git/hooks/post-checkout
#!/bin/bash
# Auto-detect role based on branch or project
if [[ $(git branch --show-current) == *"intern"* ]]; then
  export SHIELD_USER_ROLE="intern"
elif [[ $(git branch --show-current) == *"junior"* ]]; then
  export SHIELD_USER_ROLE="junior_dev"  
else
  export SHIELD_USER_ROLE="senior_dev"
fi
```

## 📞 Support

- 📧 **Email**: support@votal.ai
- 💬 **Quick help**: Your team admin
- 📖 **Full docs**: https://shield.votal.ai/docs
- 🐛 **Issues**: Check Cursor settings, restart Cursor, verify API key

## ❓ FAQ

**Q: Does this slow down Cursor?**
A: No impact on speed. Same AI models, just with safety checks.

**Q: Can I use my own OpenAI key?**  
A: Not needed! LLM Shield includes AI access with guardrails.

**Q: What if I need a custom role?**
A: Pro plans support custom role definitions.

**Q: Does this work with VS Code too?**
A: Yes! Same configuration works with VS Code + AI extensions.

---

**Setup time: 2 minutes**  
**Team safety: Immediate**  
**Learning optimization: Automatic** 🚀