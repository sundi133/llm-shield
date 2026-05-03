#!/usr/bin/env python3
"""
DevGuard Team Setup Wizard

Interactive script for small dev teams to set up role-based AI guardrails
in under 5 minutes using shield.votal.ai
"""

import requests
import json
import os
import sys

SHIELD_API = "https://shield.votal.ai"

def print_header():
    print("🛡️" + "=" * 50)
    print("   DevGuard Team Setup Wizard")
    print("   AI Safety & Role-Based Guardrails")
    print("=" * 52)
    print()

def create_team():
    """Step 1: Create team and get API key"""
    print("📋 Step 1: Create Your Team")
    print("-" * 30)

    team_name = input("Team/Company name: ").strip()
    admin_email = input("Admin email: ").strip()

    # Choose plan
    print("\nChoose plan:")
    print("1. Free (5 members, 1K requests/month)")
    print("2. Pro (20 members, 10K requests/month) - $29/month")

    plan_choice = input("Plan (1 or 2): ").strip()
    plan = "free" if plan_choice == "1" else "pro"

    print(f"\n⏳ Creating team '{team_name}'...")

    try:
        response = requests.post(
            f"{SHIELD_API}/v1/saas/teams/create",
            json={
                "team_name": team_name,
                "admin_email": admin_email,
                "plan": plan
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            print(f"✅ Team created successfully!")
            print(f"🔑 API Key: {data['api_key']}")
            print(f"🆔 Team ID: {data['team_id']}")
            return data
        else:
            print(f"❌ Failed to create team: {response.text}")
            return None

    except Exception as e:
        print(f"❌ Error creating team: {e}")
        return None

def choose_team_template():
    """Step 2: Choose team template"""
    print("\n📝 Step 2: Choose Your Team Template")
    print("-" * 40)

    print("1. 🏢 Startup (2-10 people)")
    print("   Roles: founder, senior_dev, junior_dev, intern")
    print("   Good for: Early stage companies, simple hierarchy")
    print()
    print("2. 🏗️ Agency (5-20 people)")
    print("   Roles: project_manager, lead_developer, contractor")
    print("   Good for: Client work, project-based teams")
    print()
    print("3. 🎓 Bootcamp/School (10-50 people)")
    print("   Roles: instructor, student, teaching_assistant")
    print("   Good for: Educational settings")
    print()
    print("4. 🛠️ Custom (Define your own roles)")

    choice = input("Choose template (1-4): ").strip()

    templates = {
        "1": "startup",
        "2": "agency",
        "3": "bootcamp",
        "4": "custom"
    }

    return templates.get(choice, "startup")

def get_startup_policy():
    """Startup team role policy"""
    return {
        "role_policies": [
            {
                "role": "founder",
                "action": "allow",
                "data_scope": ["all"],
                "input_rules": [
                    "Can ask anything related to business and code",
                    "Full access to strategic and technical questions"
                ],
                "output_rules": ["Full access to AI capabilities"]
            },
            {
                "role": "senior_dev",
                "action": "allow",
                "data_scope": ["code", "architecture", "debugging"],
                "input_rules": [
                    "Can request complex code generation",
                    "Can ask for architecture advice",
                    "Can access debugging help and optimization"
                ],
                "output_rules": [
                    "Show technical details and best practices",
                    "Provide advanced programming patterns"
                ]
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
                    "Simplify complex concepts",
                    "Focus on learning and fundamentals"
                ]
            },
            {
                "role": "intern",
                "action": "redact",
                "data_scope": ["learning"],
                "redaction_level": "full",
                "input_rules": [
                    "Can only ask basic programming questions",
                    "Cannot access proprietary patterns",
                    "Limited to educational content"
                ],
                "output_rules": [
                    "Provide beginner-friendly explanations only",
                    "Block advanced technical details",
                    "Focus on computer science fundamentals"
                ]
            }
        ]
    }

def get_agency_policy():
    """Agency team role policy"""
    return {
        "role_policies": [
            {
                "role": "project_manager",
                "action": "allow",
                "data_scope": ["project_planning", "communication"],
                "input_rules": [
                    "Can ask for project planning help",
                    "Can request client communication assistance",
                    "Cannot access technical implementation details"
                ],
                "output_rules": [
                    "Focus on project management and planning",
                    "Hide technical implementation details"
                ]
            },
            {
                "role": "lead_developer",
                "action": "allow",
                "data_scope": ["all_technical"],
                "input_rules": ["Full technical access for project delivery"],
                "output_rules": ["Complete technical information access"]
            },
            {
                "role": "contractor",
                "action": "redact",
                "data_scope": ["specific_project_only"],
                "redaction_level": "full",
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
    }

def setup_role_policies(api_key, template):
    """Step 3: Set up role-based policies"""
    print(f"\n🔧 Step 3: Setting Up {template.title()} Role Policies")
    print("-" * 50)

    if template == "startup":
        policy = get_startup_policy()
        roles = ["founder", "senior_dev", "junior_dev", "intern"]
    elif template == "agency":
        policy = get_agency_policy()
        roles = ["project_manager", "lead_developer", "contractor"]
    else:
        print("Custom templates not yet implemented in this wizard")
        return False, []

    try:
        response = requests.post(
            f"{SHIELD_API}/v1/data-policies/tools/general_ai/policy",
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json"
            },
            json=policy,
            timeout=10
        )

        if response.status_code == 200:
            print("✅ Role policies configured successfully!")
            print(f"📋 Available roles: {', '.join(roles)}")
            return True, roles
        else:
            print(f"❌ Failed to set up policies: {response.text}")
            return False, []

    except Exception as e:
        print(f"❌ Error setting up policies: {e}")
        return False, []

def add_team_members(api_key, team_id, available_roles):
    """Step 4: Add team members"""
    print(f"\n👥 Step 4: Add Team Members")
    print("-" * 30)

    members_added = 0

    while True:
        email = input("Team member email (or 'done'): ").strip()
        if email.lower() == 'done':
            break

        print(f"Available roles: {', '.join(available_roles)}")
        role = input(f"Role for {email}: ").strip()

        if role not in available_roles:
            print(f"❌ Invalid role. Choose from: {', '.join(available_roles)}")
            continue

        try:
            response = requests.post(
                f"{SHIELD_API}/v1/saas/teams/{team_id}/members",
                headers={"X-API-Key": api_key},
                params={"email": email, "role": role},
                timeout=10
            )

            if response.status_code == 200:
                print(f"✅ Added {email} as {role}")
                members_added += 1
            else:
                print(f"❌ Failed to add {email}: {response.text}")

        except Exception as e:
            print(f"❌ Error adding {email}: {e}")

    return members_added

def generate_usage_instructions(api_key, available_roles):
    """Step 5: Generate usage instructions"""
    print(f"\n📖 Step 5: Usage Instructions for Your Team")
    print("-" * 45)

    print("Share these instructions with your team members:\n")

    # Environment setup
    print("🔧 SETUP (one-time per developer):")
    print("-" * 35)
    print(f'export DEVGUARD_API_KEY="{api_key}"')
    print('export DEVGUARD_USER_ROLE="your_role"  # Replace with actual role')
    print()

    # Python example
    print("🐍 PYTHON USAGE:")
    print("-" * 15)
    print("""import os
import requests

def ai_chat(message, role=None):
    role = role or os.getenv('DEVGUARD_USER_ROLE', 'developer')

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

    result = response.json()
    return result['choices'][0]['message']['content']

# Usage examples:""")

    for role in available_roles[:2]:  # Show examples for first 2 roles
        print(f'print(ai_chat("Help me debug this code", role="{role}"))')

    print()

    # JavaScript example
    print("🟨 JAVASCRIPT USAGE:")
    print("-" * 18)
    print(f"""const DEVGUARD_API_KEY = "{api_key}";

async function aiChat(message, role = "developer") {{
  const response = await fetch("https://shield.votal.ai/v1/chat/completions", {{
    method: "POST",
    headers: {{
      "Authorization": `Bearer ${{DEVGUARD_API_KEY}}`,
      "X-User-Role": role,
      "Content-Type": "application/json"
    }},
    body: JSON.stringify({{
      messages: [{{role: "user", content: message}}],
      model: "gpt-4"
    }})
  }});

  const result = await response.json();
  return result.choices[0].message.content;
}}

// Usage:
aiChat("Help with React component", "{available_roles[0]}").then(console.log);""")

def main():
    """Main wizard flow"""
    print_header()

    # Step 1: Create team
    team_data = create_team()
    if not team_data:
        print("❌ Team creation failed. Exiting.")
        sys.exit(1)

    api_key = team_data['api_key']
    team_id = team_data['team_id']

    # Step 2: Choose template
    template = choose_team_template()

    # Step 3: Set up policies
    success, roles = setup_role_policies(api_key, template)
    if not success:
        print("❌ Policy setup failed. Exiting.")
        sys.exit(1)

    # Step 4: Add members
    members_count = add_team_members(api_key, team_id, roles)

    # Step 5: Show usage instructions
    generate_usage_instructions(api_key, roles)

    # Summary
    print("\n" + "🎉" + "=" * 50)
    print("    SETUP COMPLETE!")
    print("=" * 52)
    print(f"✅ Team created: {team_data.get('team_name', 'Unknown')}")
    print(f"✅ Template: {template}")
    print(f"✅ Roles configured: {', '.join(roles)}")
    print(f"✅ Members added: {members_count}")
    print(f"🔑 API Key: {api_key}")
    print("\n📧 Email these instructions to your team!")
    print("🛡️ Your AI is now protected with role-based guardrails!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️ Setup cancelled by user.")
    except Exception as e:
        print(f"\n💥 Setup failed: {e}")
        sys.exit(1)