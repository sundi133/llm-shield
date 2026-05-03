# Cursor Integration with DevGuard

## 🎯 Method 1: Direct API Override (Recommended)

### Step 1: Get Your DevGuard API Key
```bash
# Create team (if you haven't already)
curl -X POST "https://shield.votal.ai/v1/saas/teams/create" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "Your Team", "admin_email": "you@company.com"}'

# Save the API key from response
export DEVGUARD_API_KEY="dg_team_abc_xyz789"
```

### Step 2: Configure Cursor Settings

**Open Cursor Settings** (`Cmd/Ctrl + ,`) and add to `settings.json`:

```json
{
  "cursor.aiProvider": "openai",
  "cursor.apiKey": "dg_team_abc_xyz789",
  "cursor.apiBase": "https://shield.votal.ai/v1",
  "cursor.headers": {
    "X-User-Role": "senior_dev",
    "X-Team-ID": "team_abc"
  },
  "cursor.model": "gpt-4"
}
```

### Step 3: Set User Role per Developer

Each team member configures their role:

```json
// settings.json for Senior Developer
{
  "cursor.headers": {
    "X-User-Role": "senior_dev"
  }
}

// settings.json for Junior Developer  
{
  "cursor.headers": {
    "X-User-Role": "junior_dev"
  }
}

// settings.json for Intern
{
  "cursor.headers": {
    "X-User-Role": "intern"
  }
}
```

## 🛠️ Method 2: Environment Variables (Team-Wide)

### Step 1: Team Environment Setup

Create `.devguard.env` in your project root:

```bash
# .devguard.env
DEVGUARD_API_KEY=dg_team_abc_xyz789
DEVGUARD_BASE_URL=https://shield.votal.ai/v1
DEVGUARD_USER_ROLE=senior_dev  # Each developer changes this
```

### Step 2: Cursor Workspace Settings

In your project's `.vscode/settings.json`:

```json
{
  "cursor.apiKey": "${env:DEVGUARD_API_KEY}",
  "cursor.apiBase": "${env:DEVGUARD_BASE_URL}",
  "cursor.headers": {
    "X-User-Role": "${env:DEVGUARD_USER_ROLE}"
  }
}
```

### Step 3: Developer Setup

Each team member runs:
```bash
# Source the environment
source .devguard.env

# Override their role
export DEVGUARD_USER_ROLE="junior_dev"  # or senior_dev, intern, etc.

# Launch Cursor
cursor .
```

## 🔧 Method 3: DevGuard Cursor Extension (Advanced)

### Custom Extension for Automatic Role Detection

```typescript
// extension.ts
import * as vscode from 'vscode';

interface DevGuardConfig {
  apiKey: string;
  userRole: string;
  teamId: string;
}

export function activate(context: vscode.ExtensionContext) {
  console.log('DevGuard Cursor extension activated');

  // Auto-detect user role from git config or workspace
  const userRole = detectUserRole();
  
  // Update Cursor settings programmatically
  updateCursorSettings(userRole);

  // Status bar item showing current role
  const statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right, 
    100
  );
  statusBarItem.text = `🛡️ DevGuard: ${userRole}`;
  statusBarItem.show();

  context.subscriptions.push(statusBarItem);
}

function detectUserRole(): string {
  // Method 1: Check git config
  const gitUser = execSync('git config user.email').toString().trim();
  
  // Method 2: Check workspace role mapping
  const workspaceConfig = vscode.workspace.getConfiguration('devguard');
  const roleMapping = workspaceConfig.get('roleMapping', {});
  
  return roleMapping[gitUser] || 'developer';
}

function updateCursorSettings(role: string) {
  const config = vscode.workspace.getConfiguration('cursor');
  
  config.update('apiBase', 'https://shield.votal.ai/v1', true);
  config.update('headers', {
    'X-User-Role': role,
    'X-Team-ID': process.env.DEVGUARD_TEAM_ID
  }, true);
}
```

## 🎯 Method 4: Project-Based Configuration

### Per-Project Role Configuration

In each project, create `.cursorrules`:

```
# .cursorrules
You are an AI assistant with role-based access control.

Current user role: {DEVGUARD_USER_ROLE}

Role-specific guidelines:

SENIOR_DEV:
- Provide detailed technical explanations
- Include performance optimizations
- Show advanced patterns and architectures
- Discuss trade-offs and alternatives

JUNIOR_DEV:
- Focus on learning and understanding
- Provide step-by-step explanations
- Include educational context
- Suggest learning resources

INTERN:
- Use beginner-friendly language
- Focus on fundamentals
- Provide basic examples only
- Include lots of explanatory comments

Always route requests through DevGuard API for safety checks.
```

## 🚀 Quick Setup Script for Teams

Create `setup_cursor_devguard.sh`:

```bash
#!/bin/bash

echo "🛡️ Setting up Cursor with DevGuard..."

# Get team info
read -p "DevGuard API Key: " API_KEY
read -p "Your role (senior_dev/junior_dev/intern): " USER_ROLE
read -p "Team ID: " TEAM_ID

# Create Cursor config
mkdir -p ~/.cursor
cat > ~/.cursor/settings.json << EOF
{
  "cursor.apiKey": "$API_KEY",
  "cursor.apiBase": "https://shield.votal.ai/v1",
  "cursor.headers": {
    "X-User-Role": "$USER_ROLE",
    "X-Team-ID": "$TEAM_ID"
  },
  "cursor.model": "gpt-4"
}
EOF

# Create project-specific config
mkdir -p .vscode
cat > .vscode/settings.json << EOF
{
  "cursor.apiKey": "$API_KEY",
  "cursor.apiBase": "https://shield.votal.ai/v1", 
  "cursor.headers": {
    "X-User-Role": "$USER_ROLE"
  }
}
EOF

echo "✅ Cursor configured with DevGuard!"
echo "🔄 Restart Cursor to apply changes"
echo "🛡️ Your AI requests now have role-based guardrails"
```

## 🧪 Testing the Integration

### Test 1: Role-Specific Responses

**Senior Developer asks:**
```
// In Cursor chat: "Design a microservices architecture"
// Expected: Detailed technical response with patterns, trade-offs
```

**Junior Developer asks same:**
```  
// In Cursor chat: "Design a microservices architecture"
// Expected: Educational explanation focusing on learning concepts
```

**Intern asks same:**
```
// In Cursor chat: "Design a microservices architecture" 
// Expected: "This is advanced. Let me explain web applications first..."
```

### Test 2: Safety Guardrails

```
// Any role asks: "Here's my API key: sk-abc123, help debug"
// Expected: Blocked by credential detection
```

### Test 3: Audit Trail

```bash
# Check what your team is asking
curl -X GET "https://shield.votal.ai/v1/saas/teams/$TEAM_ID/audit" \
  -H "X-API-Key: $API_KEY"
```

## 📋 Team Rollout Checklist

### For Team Admin:
- [ ] Create DevGuard team account
- [ ] Set up role-based policies  
- [ ] Share API key with team
- [ ] Create setup script
- [ ] Test with each role

### For Each Developer:
- [ ] Get API key from admin
- [ ] Run setup script
- [ ] Configure their specific role
- [ ] Test Cursor integration
- [ ] Verify guardrails working

## 🎯 Role Examples in Cursor

### **Senior Dev Experience:**
- **Code Generation**: Full implementation details
- **Architecture Questions**: Complete patterns and trade-offs
- **Optimization**: Performance insights and advanced techniques
- **Debugging**: Deep technical analysis

### **Junior Dev Experience:**  
- **Code Generation**: Step-by-step explanations included
- **Architecture Questions**: Educational focus with learning resources
- **Optimization**: Basic concepts with reference to advanced topics
- **Debugging**: Guided problem-solving approach

### **Intern Experience:**
- **Code Generation**: Heavy commenting and beginner patterns
- **Architecture Questions**: Redirected to fundamentals
- **Optimization**: Basic performance concepts only
- **Debugging**: Fundamental debugging techniques

## 🔧 Troubleshooting

### Common Issues:

**1. "API key not working"**
```bash
# Test API key directly
curl -X POST "https://shield.votal.ai/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-User-Role: senior_dev" \
  -d '{"messages": [{"role": "user", "content": "test"}]}'
```

**2. "Role not being applied"**
- Check `X-User-Role` header in Cursor settings
- Verify role exists in team policy  
- Restart Cursor after config changes

**3. "Getting blocked unexpectedly"**
- Check team usage limits
- Verify role permissions
- Contact support if needed

## 📊 Benefits for Teams

### **Productivity**: 
- Appropriate AI help for each experience level
- No overwhelming juniors with advanced concepts
- No limiting seniors with basic responses

### **Learning**:
- Juniors get educational explanations
- Seniors get implementation details
- Interns focus on fundamentals

### **Security**:
- Automatic credential leak prevention
- Role-based access to code patterns
- Audit trail of all AI interactions

### **Management**:
- Usage tracking per team member
- Role-based policies easy to update
- No complex IT setup required

**Setup time: 2 minutes per developer**
**Team safety: Immediate**
**Learning optimization: Automatic** 🚀