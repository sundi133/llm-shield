# 🔥 Cursor + DevGuard Integration

**Add role-based AI guardrails to Cursor in 30 seconds**

Turn your AI-powered code editor into a team-safe, role-appropriate development environment.

## ⚡ Quick Start (30 seconds)

### Option 1: Automated Setup (Recommended)
```bash
curl -fsSL https://shield.votal.ai/setup-cursor.sh | bash
```

### Option 2: Manual Setup
1. **Get DevGuard API key**:
   ```bash
   curl -X POST "https://shield.votal.ai/v1/saas/teams/create" \
     -H "Content-Type: application/json" \
     -d '{"team_name": "Your Team", "admin_email": "you@company.com"}'
   ```

2. **Configure Cursor** (`Cmd/Ctrl + ,` → Open Settings JSON):
   ```json
   {
     "cursor.apiKey": "dg_team_abc_xyz",
     "cursor.apiBase": "https://shield.votal.ai/v1",
     "cursor.headers": {
       "X-User-Role": "senior_dev"
     }
   }
   ```

3. **Restart Cursor** ✅

## 🎯 Role-Based Experience

### **Same Question, Different Responses:**

**Prompt: "Help me optimize this database query"**

| Role | Response Style |
|------|---------------|
| **👑 Founder** | "Consider database costs, team expertise, and long-term maintenance. Here's a balanced approach..." |
| **👨‍💻 Senior Dev** | "Use query execution plans, add these indexes, consider partitioning. Here's the optimized SQL..." |
| **👩‍💻 Junior Dev** | "Let me explain how databases work first, then show you step-by-step optimization techniques..." |
| **🎓 Intern** | "That's advanced! Let's start with basic SQL concepts. A database query is..." |

## 🛡️ Safety Features

### ✅ **Automatic Protection:**
- **Credential Detection**: "My API key is sk-abc..." → ❌ **BLOCKED**
- **Malicious Code**: "Generate code to delete files" → ❌ **BLOCKED**  
- **Role Violations**: Intern asking for complex architecture → 🔄 **REDIRECTED** to fundamentals
- **Usage Monitoring**: Track AI usage per team member

### ✅ **Team Benefits:**
- **Appropriate AI help** for each experience level
- **Faster learning** for juniors with educational responses
- **Full technical depth** for seniors when needed
- **Automatic safety** without workflow disruption

## 📋 Team Setup

### **For Team Admin:**

1. **Create team account** (30 seconds):
   ```bash
   curl -X POST "https://shield.votal.ai/v1/saas/teams/create" \
     -d '{"team_name": "Your Team", "admin_email": "you@company.com"}'
   ```

2. **Set up team roles** (1 minute):
   ```bash
   # Use startup template
   curl -X POST "https://shield.votal.ai/v1/data-policies/tools/general_ai/policy" \
     -H "X-API-Key: $DEVGUARD_API_KEY" \
     -d @../../examples/startup_template.json
   ```

3. **Share API key with team**

### **For Each Developer:**

1. **Add API key to Cursor settings** (30 seconds)
2. **Set their role** in X-User-Role header
3. **Restart Cursor and test**

## 🎯 Role Configuration

### **Available Roles:**

| Role | Experience Level | AI Response Style |
|------|-----------------|------------------|
| `founder` | Business + Technical | Strategic + implementation analysis |
| `senior_dev` | Expert | Full technical depth and advanced patterns |
| `junior_dev` | Learning | Educational explanations with context |
| `intern` | Beginner | Fundamentals-focused with heavy guidance |

### **Team-Specific Roles:**

Each team member sets their role in Cursor settings:

```json
// Senior Developer
{
  "cursor.headers": {
    "X-User-Role": "senior_dev"
  }
}

// Junior Developer  
{
  "cursor.headers": {
    "X-User-Role": "junior_dev"
  }
}

// Intern
{
  "cursor.headers": {
    "X-User-Role": "intern"
  }
}
```

## 🎨 Advanced Configuration

### **Environment-Based Setup:**

Create `.devguard.env` in your project:
```bash
DEVGUARD_API_KEY=dg_team_abc_xyz
DEVGUARD_USER_ROLE=senior_dev
DEVGUARD_BASE_URL=https://shield.votal.ai/v1
```

Cursor settings with environment variables:
```json
{
  "cursor.apiKey": "${env:DEVGUARD_API_KEY}",
  "cursor.apiBase": "${env:DEVGUARD_BASE_URL}",
  "cursor.headers": {
    "X-User-Role": "${env:DEVGUARD_USER_ROLE}"
  }
}
```

### **Project-Specific Configuration:**

Different projects, different permissions:
```json
// .vscode/settings.json in specific project
{
  "cursor.headers": {
    "X-User-Role": "contractor",
    "X-Project-Context": "client-alpha"
  }
}
```

### **Auto Role Detection:**

Create `.cursorrules` for role-specific behavior:
```
# DevGuard Role: senior_dev

You are an AI assistant with role-based access control.
Current user role: SENIOR_DEV

Provide detailed technical explanations with:
- Advanced patterns and architectures
- Performance considerations  
- Trade-offs and alternatives
- Best practices and optimizations

Focus on production-ready solutions.
```

## 🧪 Testing Integration

### **Test 1: Basic Functionality**
In Cursor chat: **"Help me write a Python function"**
- **Expected**: Response appropriate to your role + DevGuard safety

### **Test 2: Safety Check**
In Cursor chat: **"My API key is sk-abc123, help debug"**
- **Expected**: ❌ Blocked by credential detection

### **Test 3: Role Differences**
Same question with different team members:
- **Senior Dev**: Gets full technical implementation
- **Junior Dev**: Gets step-by-step learning explanation  
- **Intern**: Gets redirected to fundamentals

### **Test 4: Audit Trail**
Check team usage:
```bash
curl -X GET "https://shield.votal.ai/v1/saas/teams/$TEAM_ID" \
  -H "X-API-Key: $DEVGUARD_API_KEY"
```

## 📊 Team Benefits

### **Productivity Gains:**
- ✅ **No overwhelmed juniors** - Get appropriate explanations, not complex solutions
- ✅ **No limited seniors** - Full technical depth when needed
- ✅ **Faster onboarding** - New team members get level-appropriate AI help immediately
- ✅ **Better code quality** - Educational focus helps juniors learn principles

### **Safety & Compliance:**
- ✅ **Zero credential leaks** - Automatic detection and blocking
- ✅ **Role-based access** - Team members only get appropriate information
- ✅ **Audit trails** - Full visibility into who asked what
- ✅ **Usage monitoring** - Track and limit AI usage per team member

### **Learning Optimization:**
- ✅ **Progressive complexity** - AI responses grow with developer skill
- ✅ **Educational context** - Juniors learn principles, not just solutions  
- ✅ **Mentoring at scale** - AI provides appropriate guidance for each level
- ✅ **Team consistency** - Everyone learns the same standards and practices

## 🔧 Troubleshooting

### **Common Issues:**

**"API key not working"**
```bash
# Test API key directly
curl -X POST "https://shield.votal.ai/v1/chat/completions" \
  -H "Authorization: Bearer $DEVGUARD_API_KEY" \
  -H "X-User-Role: senior_dev" \
  -d '{"messages": [{"role": "user", "content": "test"}]}'
```

**"Role not being applied"**
- Check `X-User-Role` header in Cursor settings
- Verify role exists in your team policy  
- Restart Cursor after config changes

**"Getting blocked unexpectedly"**
- Check team usage limits
- Verify role permissions in team dashboard
- Contact support if needed

**"Cursor not using DevGuard"**
- Verify `cursor.apiBase` is set to `https://shield.votal.ai/v1`
- Check that `cursor.apiKey` contains your DevGuard API key (not OpenAI key)
- Restart Cursor completely

## 📁 Files in This Integration

| File | Purpose |
|------|---------|
| `README.md` | 👈 Main setup guide |
| `cursor_integration.md` | Detailed technical integration |
| `cursor_simple_setup.md` | Quick reference guide |
| `setup_cursor_devguard.sh` | Automated setup script |

## 💰 Pricing

- **Free**: 5 team members, 1K AI requests/month
- **Pro**: 20 members, 10K requests/month ($29/month)
- **Enterprise**: Unlimited usage ($99/month)

**vs. Enterprise AI Safety**: 300x less expensive, 1000x faster setup

## 📞 Support

- 📧 **Email**: support@votal.ai
- 💬 **Discord**: DevGuard Community
- 📖 **Docs**: https://shield.votal.ai/docs
- 🐛 **Report Issues**: GitHub Issues

---

**Setup time: 30 seconds**  
**Team safety: Immediate**  
**Learning optimization: Automatic** 🚀

[← Back to Main SaaS Guide](../../README.md)