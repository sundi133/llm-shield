#!/bin/bash

# DevGuard + Cursor Setup Script
# Automatically configures Cursor to use shield.votal.ai with role-based guardrails

set -e

echo "🛡️ DevGuard + Cursor Integration Setup"
echo "======================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Cursor is installed
check_cursor() {
    if ! command -v cursor &> /dev/null; then
        echo -e "${YELLOW}⚠️  Cursor not found in PATH${NC}"
        echo "Please make sure Cursor is installed and available in your PATH"
        echo "Download from: https://cursor.sh"
        read -p "Continue anyway? (y/n): " continue_choice
        if [[ $continue_choice != "y" && $continue_choice != "Y" ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Cursor found${NC}"
    fi
}

# Get team configuration
get_team_config() {
    echo ""
    echo "📋 Step 1: Team Configuration"
    echo "----------------------------"

    # Check if they have a DevGuard team
    read -p "Do you already have a DevGuard team? (y/n): " has_team

    if [[ $has_team == "n" || $has_team == "N" ]]; then
        echo ""
        echo "Creating new DevGuard team..."
        read -p "Team name: " team_name
        read -p "Admin email: " admin_email

        echo "Creating team..."
        team_response=$(curl -s -X POST "https://shield.votal.ai/v1/saas/teams/create" \
            -H "Content-Type: application/json" \
            -d "{\"team_name\": \"$team_name\", \"admin_email\": \"$admin_email\", \"plan\": \"free\"}")

        if echo "$team_response" | grep -q "api_key"; then
            API_KEY=$(echo "$team_response" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
            TEAM_ID=$(echo "$team_response" | grep -o '"team_id":"[^"]*"' | cut -d'"' -f4)
            echo -e "${GREEN}✅ Team created successfully!${NC}"
            echo -e "${BLUE}🔑 API Key: $API_KEY${NC}"
            echo -e "${BLUE}🆔 Team ID: $TEAM_ID${NC}"
        else
            echo -e "${RED}❌ Failed to create team: $team_response${NC}"
            exit 1
        fi
    else
        read -p "DevGuard API Key: " API_KEY
        read -p "Team ID (optional): " TEAM_ID
    fi
}

# Get user role
get_user_role() {
    echo ""
    echo "👤 Step 2: Your Role"
    echo "-------------------"
    echo "Choose your role:"
    echo "1. founder (full access)"
    echo "2. senior_dev (technical depth)"
    echo "3. junior_dev (learning focused)"
    echo "4. intern (basics only)"
    echo "5. custom (enter manually)"

    read -p "Select role (1-5): " role_choice

    case $role_choice in
        1) USER_ROLE="founder" ;;
        2) USER_ROLE="senior_dev" ;;
        3) USER_ROLE="junior_dev" ;;
        4) USER_ROLE="intern" ;;
        5)
            read -p "Enter your role: " USER_ROLE
            ;;
        *)
            echo -e "${YELLOW}Invalid choice, defaulting to senior_dev${NC}"
            USER_ROLE="senior_dev"
            ;;
    esac

    echo -e "${GREEN}✅ Role set to: $USER_ROLE${NC}"
}

# Setup global Cursor configuration
setup_global_config() {
    echo ""
    echo "⚙️ Step 3: Global Cursor Configuration"
    echo "-------------------------------------"

    # Create Cursor config directory
    CURSOR_CONFIG_DIR="$HOME/.cursor"
    mkdir -p "$CURSOR_CONFIG_DIR"

    # Backup existing settings
    if [ -f "$CURSOR_CONFIG_DIR/settings.json" ]; then
        echo "📋 Backing up existing settings..."
        cp "$CURSOR_CONFIG_DIR/settings.json" "$CURSOR_CONFIG_DIR/settings.json.backup.$(date +%Y%m%d_%H%M%S)"
    fi

    # Create or update settings
    cat > "$CURSOR_CONFIG_DIR/settings.json" << EOF
{
  "cursor.aiProvider": "openai",
  "cursor.apiKey": "$API_KEY",
  "cursor.apiBase": "https://shield.votal.ai/v1",
  "cursor.headers": {
    "X-User-Role": "$USER_ROLE"$([ ! -z "$TEAM_ID" ] && echo ",
    \"X-Team-ID\": \"$TEAM_ID\"")
  },
  "cursor.model": "gpt-4",
  "cursor.temperature": 0.1,
  "devguard.enabled": true
}
EOF

    echo -e "${GREEN}✅ Global Cursor configuration updated${NC}"
    echo "📁 Config file: $CURSOR_CONFIG_DIR/settings.json"
}

# Setup project-specific configuration
setup_project_config() {
    echo ""
    echo "📁 Step 4: Project Configuration"
    echo "--------------------------------"

    read -p "Setup project-specific config in current directory? (y/n): " setup_project

    if [[ $setup_project == "y" || $setup_project == "Y" ]]; then
        # Create .vscode directory
        mkdir -p .vscode

        # Create project settings
        cat > .vscode/settings.json << EOF
{
  "cursor.apiKey": "$API_KEY",
  "cursor.apiBase": "https://shield.votal.ai/v1",
  "cursor.headers": {
    "X-User-Role": "$USER_ROLE"$([ ! -z "$TEAM_ID" ] && echo ",
    \"X-Team-ID\": \"$TEAM_ID\"")
  }
}
EOF

        # Create .cursorrules for role-specific behavior
        cat > .cursorrules << EOF
# DevGuard Role-Based AI Assistant Rules

You are an AI assistant with role-based access control through DevGuard.
Current user role: $USER_ROLE

Role-specific behavior:

FOUNDER/ADMIN:
- Provide comprehensive technical and business guidance
- Include strategic considerations and trade-offs
- Full access to advanced patterns and architectures

SENIOR_DEV:
- Provide detailed technical explanations
- Include performance optimizations and best practices
- Show advanced patterns and architectural considerations
- Discuss trade-offs and alternatives

JUNIOR_DEV:
- Focus on learning and understanding
- Provide step-by-step explanations with educational context
- Include comments explaining the "why" behind code
- Suggest learning resources for deeper understanding
- Simplify complex concepts

INTERN:
- Use beginner-friendly language and concepts
- Focus on programming fundamentals
- Provide basic examples with extensive comments
- Avoid advanced topics unless specifically educational
- Include explanations of basic programming concepts

Always ensure responses are appropriate for the user's experience level.
All requests are automatically filtered through DevGuard safety checks.
EOF

        # Create environment file
        cat > .devguard.env << EOF
# DevGuard Configuration
DEVGUARD_API_KEY=$API_KEY
DEVGUARD_USER_ROLE=$USER_ROLE
DEVGUARD_BASE_URL=https://shield.votal.ai/v1$([ ! -z "$TEAM_ID" ] && echo "
DEVGUARD_TEAM_ID=$TEAM_ID")
EOF

        echo -e "${GREEN}✅ Project configuration created${NC}"
        echo "📁 Files created:"
        echo "   - .vscode/settings.json (Cursor project settings)"
        echo "   - .cursorrules (Role-specific AI behavior)"
        echo "   - .devguard.env (Environment variables)"

        # Add to .gitignore
        if [ -f .gitignore ]; then
            if ! grep -q ".devguard.env" .gitignore; then
                echo ".devguard.env" >> .gitignore
                echo "📝 Added .devguard.env to .gitignore"
            fi
        else
            echo ".devguard.env" > .gitignore
            echo "📝 Created .gitignore with .devguard.env"
        fi
    fi
}

# Test the configuration
test_integration() {
    echo ""
    echo "🧪 Step 5: Testing Integration"
    echo "-----------------------------"

    echo "Testing DevGuard API connection..."

    test_response=$(curl -s -w "%{http_code}" -o /tmp/devguard_test.json \
        -X POST "https://shield.votal.ai/v1/chat/completions" \
        -H "Authorization: Bearer $API_KEY" \
        -H "X-User-Role: $USER_ROLE" \
        -H "Content-Type: application/json" \
        -d '{"messages": [{"role": "user", "content": "Hello, test connection"}], "model": "gpt-4", "max_tokens": 50}')

    if [ "$test_response" = "200" ]; then
        echo -e "${GREEN}✅ API connection successful!${NC}"

        # Show test response
        if command -v jq &> /dev/null; then
            echo "📄 Test response:"
            jq -r '.choices[0].message.content // "No content"' /tmp/devguard_test.json
            echo ""
            echo "🛡️ DevGuard status:"
            jq -r '.devguard // "No devguard info"' /tmp/devguard_test.json
        fi

        rm -f /tmp/devguard_test.json
    else
        echo -e "${RED}❌ API test failed (HTTP $test_response)${NC}"
        if [ -f /tmp/devguard_test.json ]; then
            echo "Error response:"
            cat /tmp/devguard_test.json
            rm -f /tmp/devguard_test.json
        fi
        echo ""
        echo "Please check your API key and try again."
        echo "Support: support@votal.ai"
    fi
}

# Show final instructions
show_instructions() {
    echo ""
    echo "🎉 Setup Complete!"
    echo "=================="
    echo ""
    echo -e "${GREEN}✅ Cursor is now configured with DevGuard role-based AI guardrails!${NC}"
    echo ""
    echo "📋 What happens now:"
    echo "• Your AI requests go through DevGuard safety checks"
    echo "• Responses are tailored to your role ($USER_ROLE)"
    echo "• Automatic credential leak prevention"
    echo "• Team usage tracking and audit logs"
    echo ""
    echo "🚀 Next steps:"
    echo "1. Restart Cursor to apply the new settings"
    echo "2. Open a file and try the AI chat"
    echo "3. Test with: 'Help me write a Python function'"
    echo ""
    echo "👥 Team sharing:"
    echo "• Share this script with team members"
    echo "• Each person should use their role (senior_dev, junior_dev, intern)"
    echo "• API key: $API_KEY"
    echo ""
    echo "📞 Support:"
    echo "• Email: support@votal.ai"
    echo "• Docs: https://shield.votal.ai/docs"
    echo ""
    echo -e "${BLUE}Happy coding with safe AI! 🛡️${NC}"
}

# Main execution
main() {
    check_cursor
    get_team_config
    get_user_role
    setup_global_config
    setup_project_config
    test_integration
    show_instructions
}

# Run the script
main