#!/bin/bash
# Tenant Policy Manager — Manage guardrails, agents, and tool policies
# =====================================================================
# Hits the admin portal endpoints (not RunPod). Source your tenant
# credentials first:
#
#   source tenant-xxx.env
#   ./manage_policies.sh
#
# Required env vars:
#   ADMIN_PORTAL_URL  — Admin portal base URL
#   TENANT_API_KEY    — Tenant API key (X-API-Key header)
#
# Optional:
#   SHIELD_ADMIN_KEY  — For /v1/admin/* endpoints

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

ADMIN_PORTAL_URL="${ADMIN_PORTAL_URL:-}"
TENANT_API_KEY="${TENANT_API_KEY:-}"
SHIELD_ADMIN_KEY="${SHIELD_ADMIN_KEY:-}"

if [ -z "$ADMIN_PORTAL_URL" ] || [ -z "$TENANT_API_KEY" ]; then
    echo -e "${RED}Error: Missing credentials${NC}"
    echo ""
    echo "  source your-tenant.env"
    echo "  # or"
    echo "  export ADMIN_PORTAL_URL=\"https://your-admin-portal.com\""
    echo "  export TENANT_API_KEY=\"your-api-key\""
    echo ""
    exit 1
fi

ADMIN_PORTAL_URL="${ADMIN_PORTAL_URL%/}"

# ── HTTP helper ────────────────────────────
api() {
    local method="$1" path="$2" data="$3"
    local args=(-s -w "\n%{http_code}" -X "$method" "${ADMIN_PORTAL_URL}${path}")
    args+=(-H "X-API-Key: ${TENANT_API_KEY}")
    [ -n "$SHIELD_ADMIN_KEY" ] && args+=(-H "X-Admin-Key: ${SHIELD_ADMIN_KEY}")
    args+=(-H "Content-Type: application/json")
    [ -n "$data" ] && args+=(-d "$data")
    curl "${args[@]}"
}

api_file() {
    local method="$1" path="$2" file="$3"
    local args=(-s -w "\n%{http_code}" -X "$method" "${ADMIN_PORTAL_URL}${path}")
    args+=(-H "X-API-Key: ${TENANT_API_KEY}")
    [ -n "$SHIELD_ADMIN_KEY" ] && args+=(-H "X-Admin-Key: ${SHIELD_ADMIN_KEY}")
    args+=(-H "Content-Type: application/json")
    args+=(-d @"$file")
    curl "${args[@]}"
}

show_result() {
    local raw="$1"
    local http_code body
    http_code=$(echo "$raw" | tail -1)
    body=$(echo "$raw" | sed '$d')
    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        echo -e "${GREEN}OK (HTTP ${http_code})${NC}"
        echo "$body" | jq -C . 2>/dev/null || echo "$body"
    else
        echo -e "${RED}FAILED (HTTP ${http_code})${NC}"
        echo "$body" | jq -C . 2>/dev/null || echo "$body"
    fi
    echo ""
}

# ── Menu ───────────────────────────────────
while true; do
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     Votal Shield — Policy Manager        ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}Admin Portal: ${ADMIN_PORTAL_URL}${NC}"
    echo ""
    echo -e "  ${CYAN}GUARDRAIL POLICIES${NC}"
    echo "    1)  View current policies"
    echo "    2)  Apply policies from JSON file"
    echo "    3)  Export policies to JSON file"
    echo ""
    echo -e "  ${CYAN}AGENTS${NC}"
    echo "    4)  List agents"
    echo "    5)  Register agent from JSON file"
    echo "    6)  Delete agent"
    echo ""
    echo -e "  ${CYAN}TOOL POLICIES${NC}"
    echo "    7)  View tool policies"
    echo "    8)  Apply tool policies from JSON file"
    echo "    9)  Export tool policies to JSON file"
    echo "   10)  Delete a tool policy"
    echo ""
    echo -e "  ${CYAN}TEMPLATES${NC}"
    echo "   11)  Generate healthcare template"
    echo "   12)  Generate financial template"
    echo "   13)  Generate SaaS/general template"
    echo ""
    echo -e "  ${CYAN}INFO${NC}"
    echo "   14)  Tenant overview"
    echo "   15)  Usage & quota"
    echo "   16)  Available roles"
    echo "   17)  Audit log"
    echo ""
    echo "    0)  Exit"
    echo ""
    read -p "  Select [0-17]: " choice

    case $choice in

    # ── Guardrail Policies ─────────────────
    1)
        echo ""
        echo -e "${BLUE}Current Guardrail Policies${NC}"
        show_result "$(api GET /v1/tenant/me/policies)"
        ;;

    2)
        echo ""
        read -p "  JSON file path: " json_file
        if [ ! -f "$json_file" ]; then
            echo -e "${RED}File not found: $json_file${NC}"
        elif ! jq empty "$json_file" 2>/dev/null; then
            echo -e "${RED}Invalid JSON in: $json_file${NC}"
        else
            echo -e "${CYAN}Applying policies from ${json_file}...${NC}"
            show_result "$(api_file PUT /v1/tenant/me/policies "$json_file")"
        fi
        ;;

    3)
        echo ""
        read -p "  Output file [policies.json]: " out_file
        out_file="${out_file:-policies.json}"
        raw=$(api GET /v1/tenant/me/policies)
        http_code=$(echo "$raw" | tail -1)
        body=$(echo "$raw" | sed '$d')
        if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            echo "$body" | jq '{input_guardrails, output_guardrails}' > "$out_file"
            echo -e "${GREEN}Exported to: ${out_file}${NC}"
        else
            echo -e "${RED}Failed to export (HTTP ${http_code})${NC}"
        fi
        ;;

    # ── Agents ─────────────────────────────
    4)
        echo ""
        echo -e "${BLUE}Registered Agents${NC}"
        show_result "$(api GET /v1/agents/registry)"
        ;;

    5)
        echo ""
        read -p "  Agent JSON file path: " agent_file
        if [ ! -f "$agent_file" ]; then
            echo -e "${RED}File not found: $agent_file${NC}"
        elif ! jq empty "$agent_file" 2>/dev/null; then
            echo -e "${RED}Invalid JSON: $agent_file${NC}"
        else
            echo -e "${CYAN}Registering agent...${NC}"
            show_result "$(api_file POST /v1/agents/registry "$agent_file")"
        fi
        ;;

    6)
        echo ""
        read -p "  Agent ID to delete: " agent_id
        if [ -z "$agent_id" ]; then
            echo -e "${RED}Agent ID required${NC}"
        else
            read -p "  Confirm delete '$agent_id'? (y/N): " yn
            if [[ "$yn" =~ ^[Yy]$ ]]; then
                show_result "$(api DELETE "/v1/agents/registry/${agent_id}")"
            fi
        fi
        ;;

    # ── Tool Policies ──────────────────────
    7)
        echo ""
        echo -e "${BLUE}Tool Policies${NC}"
        show_result "$(api GET /v1/agents/tools/policies)"
        ;;

    8)
        echo ""
        read -p "  Tool policies JSON file path: " tp_file
        if [ ! -f "$tp_file" ]; then
            echo -e "${RED}File not found: $tp_file${NC}"
        elif ! jq empty "$tp_file" 2>/dev/null; then
            echo -e "${RED}Invalid JSON: $tp_file${NC}"
        else
            echo -e "${CYAN}Applying tool policies...${NC}"
            show_result "$(api_file PUT /v1/agents/tools/policies "$tp_file")"
        fi
        ;;

    9)
        echo ""
        read -p "  Output file [tool_policies.json]: " out_file
        out_file="${out_file:-tool_policies.json}"
        raw=$(api GET /v1/agents/tools/policies)
        http_code=$(echo "$raw" | tail -1)
        body=$(echo "$raw" | sed '$d')
        if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            echo "$body" | jq '.tool_policies' > "$out_file"
            echo -e "${GREEN}Exported to: ${out_file}${NC}"
        else
            echo -e "${RED}Failed to export (HTTP ${http_code})${NC}"
        fi
        ;;

    10)
        echo ""
        read -p "  Tool name to delete: " tool_name
        if [ -z "$tool_name" ]; then
            echo -e "${RED}Tool name required${NC}"
        else
            read -p "  Confirm delete policy for '$tool_name'? (y/N): " yn
            if [[ "$yn" =~ ^[Yy]$ ]]; then
                show_result "$(api DELETE "/v1/agents/tools/policies/${tool_name}")"
            fi
        fi
        ;;

    # ── Templates ──────────────────────────
    11)
        echo ""
        echo -e "${CYAN}Generating healthcare template files...${NC}"

        cat > "healthcare_policies.json" << 'TMPL'
{
  "input_guardrails": {
    "adversarial_detection": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "keyword_blocklist": {
      "enabled": true, "action": "block",
      "settings": { "keywords": ["hack", "exploit", "jailbreak", "ignore instructions"] }
    },
    "toxicity": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "language_detection": {
      "enabled": true, "action": "block",
      "settings": { "allowed_languages": ["en"] }
    },
    "system_prompt_leak": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "topic_restriction": {
      "enabled": true, "action": "block",
      "settings": { "allowed_topics": ["healthcare", "medical", "pharmacy", "appointments", "billing"] }
    },
    "custom_regex": { "enabled": true, "action": "block", "settings": {} },
    "continuous_adversarial": { "enabled": false, "action": "log", "settings": {} }
  },
  "output_guardrails": {
    "hallucinated_links": { "enabled": true, "action": "block", "settings": {} },
    "tone_enforcement": { "enabled": true, "action": "block", "settings": {} },
    "bias_detection": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.6 }
    },
    "pii_leakage": { "enabled": true, "action": "block", "settings": {} },
    "competitor_mention": { "enabled": true, "action": "block", "settings": {} }
  }
}
TMPL

        cat > "healthcare_agents.json" << 'TMPL'
{
  "agent_id": "healthcare-doctor",
  "name": "Doctor Assistant",
  "description": "AI assistant for doctors with full medical access",
  "tools": ["patient_lookup", "prescribe_medication", "diagnosis_update", "view_records", "lab_results"],
  "role_permissions": {
    "doctor": ["patient_lookup", "prescribe_medication", "diagnosis_update", "view_records", "lab_results"],
    "nurse": ["patient_lookup", "view_records", "lab_results"],
    "admin": ["patient_lookup"],
    "patient": []
  }
}
TMPL

        cat > "healthcare_tool_policies.json" << 'TMPL'
{
  "patient_lookup": {
    "data_sanitization": {
      "redact_ssn": true, "mask_phone": true,
      "patterns": [
        { "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]", "description": "Social Security Numbers" },
        { "regex": "\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b", "replacement": "[PHONE_REDACTED]", "description": "Phone Numbers" },
        { "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "replacement": "[EMAIL_REDACTED]", "description": "Email Addresses" },
        { "regex": "\\b\\d+\\s+[A-Za-z\\s]+(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr)\\b", "replacement": "[ADDRESS_REDACTED]", "description": "Street Addresses" }
      ]
    },
    "role_restrictions": { "doctor": "allow", "nurse": "redact", "admin": "redact", "patient": "block" }
  },
  "prescribe_medication": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]", "description": "SSN in prescriptions" },
        { "regex": "\\b(DEA|DEA#|DEA Number)\\s*:?\\s*[A-Z]{2}\\d{7}\\b", "replacement": "[DEA_NUMBER_REDACTED]", "description": "DEA Numbers" }
      ]
    },
    "llm_validation": {
      "enabled": true,
      "prompt": "Validate if {user_role} can safely prescribe this medication: {tool_input}. Consider medical appropriateness and role permissions.",
      "confidence_threshold": 0.8
    },
    "role_restrictions": { "doctor": "allow", "nurse": "block", "admin": "block", "patient": "block" }
  },
  "diagnosis_update": {
    "data_sanitization": { "patterns": [] },
    "role_restrictions": { "doctor": "allow", "nurse": "block", "admin": "block", "patient": "block" }
  },
  "view_records": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]", "description": "SSN" }
      ]
    },
    "role_restrictions": { "doctor": "allow", "nurse": "redact", "admin": "block", "patient": "block" }
  },
  "lab_results": {
    "data_sanitization": { "patterns": [] },
    "role_restrictions": { "doctor": "allow", "nurse": "allow", "admin": "block", "patient": "block" }
  }
}
TMPL

        echo -e "${GREEN}Created:${NC}"
        echo "  healthcare_policies.json       (guardrail config)"
        echo "  healthcare_agents.json         (agent registration)"
        echo "  healthcare_tool_policies.json  (tool data policies)"
        echo ""
        echo -e "${YELLOW}Apply them:${NC}"
        echo "  Option 2 → healthcare_policies.json"
        echo "  Option 5 → healthcare_agents.json"
        echo "  Option 8 → healthcare_tool_policies.json"
        ;;

    12)
        echo ""
        echo -e "${CYAN}Generating financial services template files...${NC}"

        cat > "financial_policies.json" << 'TMPL'
{
  "input_guardrails": {
    "adversarial_detection": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.85 }
    },
    "keyword_blocklist": {
      "enabled": true, "action": "block",
      "settings": { "keywords": ["hack", "exploit", "wire transfer override", "bypass verification"] }
    },
    "toxicity": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.7 }
    },
    "language_detection": {
      "enabled": true, "action": "block",
      "settings": { "allowed_languages": ["en"] }
    },
    "system_prompt_leak": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "topic_restriction": {
      "enabled": true, "action": "block",
      "settings": { "allowed_topics": ["banking", "loans", "investments", "account", "billing", "fraud"] }
    },
    "custom_regex": { "enabled": true, "action": "block", "settings": {} },
    "continuous_adversarial": { "enabled": true, "action": "block", "settings": {} }
  },
  "output_guardrails": {
    "hallucinated_links": { "enabled": true, "action": "block", "settings": {} },
    "tone_enforcement": { "enabled": true, "action": "block", "settings": {} },
    "bias_detection": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.5 }
    },
    "pii_leakage": { "enabled": true, "action": "block", "settings": {} },
    "competitor_mention": { "enabled": true, "action": "block", "settings": {} }
  }
}
TMPL

        cat > "financial_agents.json" << 'TMPL'
{
  "agent_id": "financial-advisor",
  "name": "Financial Advisor Agent",
  "description": "AI assistant for financial advisors and account managers",
  "tools": ["account_lookup", "transaction_history", "balance_check", "loan_calculator", "fraud_report"],
  "role_permissions": {
    "advisor": ["account_lookup", "transaction_history", "balance_check", "loan_calculator", "fraud_report"],
    "teller": ["account_lookup", "balance_check"],
    "compliance": ["account_lookup", "transaction_history", "fraud_report"],
    "customer": []
  }
}
TMPL

        cat > "financial_tool_policies.json" << 'TMPL'
{
  "account_lookup": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]", "description": "SSN" },
        { "regex": "\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b", "replacement": "[CARD_REDACTED]", "description": "Credit Card Numbers" },
        { "regex": "\\b\\d{9,18}\\b", "replacement": "[ACCT_REDACTED]", "description": "Account Numbers" }
      ]
    },
    "role_restrictions": { "advisor": "allow", "teller": "redact", "compliance": "allow", "customer": "block" }
  },
  "transaction_history": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\$[0-9,]+\\.?[0-9]*", "replacement": "[AMOUNT_REDACTED]", "description": "Dollar Amounts" }
      ]
    },
    "role_restrictions": { "advisor": "allow", "teller": "block", "compliance": "allow", "customer": "block" }
  },
  "balance_check": {
    "data_sanitization": { "patterns": [] },
    "role_restrictions": { "advisor": "allow", "teller": "allow", "compliance": "allow", "customer": "block" }
  },
  "loan_calculator": {
    "data_sanitization": { "patterns": [] },
    "role_restrictions": { "advisor": "allow", "teller": "block", "compliance": "block", "customer": "block" }
  },
  "fraud_report": {
    "data_sanitization": { "patterns": [] },
    "llm_validation": {
      "enabled": true,
      "prompt": "Validate if {user_role} can file or access this fraud report: {tool_input}. Only advisors and compliance should access.",
      "confidence_threshold": 0.9
    },
    "role_restrictions": { "advisor": "allow", "teller": "block", "compliance": "allow", "customer": "block" }
  }
}
TMPL

        echo -e "${GREEN}Created:${NC}"
        echo "  financial_policies.json       (guardrail config)"
        echo "  financial_agents.json         (agent registration)"
        echo "  financial_tool_policies.json  (tool data policies)"
        echo ""
        echo -e "${YELLOW}Apply them:${NC}"
        echo "  Option 2 → financial_policies.json"
        echo "  Option 5 → financial_agents.json"
        echo "  Option 8 → financial_tool_policies.json"
        ;;

    13)
        echo ""
        echo -e "${CYAN}Generating SaaS/general template files...${NC}"

        cat > "saas_policies.json" << 'TMPL'
{
  "input_guardrails": {
    "adversarial_detection": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "keyword_blocklist": {
      "enabled": true, "action": "block",
      "settings": { "keywords": ["hack", "exploit", "jailbreak"] }
    },
    "toxicity": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "language_detection": {
      "enabled": true, "action": "block",
      "settings": { "allowed_languages": ["en"] }
    },
    "system_prompt_leak": {
      "enabled": true, "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "topic_restriction": { "enabled": false, "action": "log", "settings": {} },
    "custom_regex": { "enabled": false, "action": "log", "settings": {} },
    "continuous_adversarial": { "enabled": false, "action": "log", "settings": {} }
  },
  "output_guardrails": {
    "hallucinated_links": { "enabled": true, "action": "block", "settings": {} },
    "tone_enforcement": { "enabled": true, "action": "warn", "settings": {} },
    "bias_detection": {
      "enabled": true, "action": "warn",
      "settings": { "threshold": 0.6 }
    },
    "pii_leakage": { "enabled": true, "action": "block", "settings": {} },
    "competitor_mention": { "enabled": false, "action": "log", "settings": {} }
  }
}
TMPL

        cat > "saas_agents.json" << 'TMPL'
{
  "agent_id": "support-agent",
  "name": "Support Agent",
  "description": "Customer support and knowledge base assistant",
  "tools": ["search_docs", "create_ticket", "user_lookup", "send_email"],
  "role_permissions": {
    "admin": ["search_docs", "create_ticket", "user_lookup", "send_email"],
    "support": ["search_docs", "create_ticket", "user_lookup"],
    "user": ["search_docs"]
  }
}
TMPL

        cat > "saas_tool_policies.json" << 'TMPL'
{
  "user_lookup": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "replacement": "[EMAIL_REDACTED]", "description": "Email" },
        { "regex": "\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b", "replacement": "[PHONE_REDACTED]", "description": "Phone" }
      ]
    },
    "role_restrictions": { "admin": "allow", "support": "redact", "user": "block" }
  },
  "send_email": {
    "data_sanitization": { "patterns": [] },
    "llm_validation": {
      "enabled": true,
      "prompt": "Validate if {user_role} should send this email: {tool_input}. Check for phishing, spam, or impersonation.",
      "confidence_threshold": 0.85
    },
    "role_restrictions": { "admin": "allow", "support": "block", "user": "block" }
  },
  "search_docs": { "data_sanitization": { "patterns": [] } },
  "create_ticket": { "data_sanitization": { "patterns": [] } }
}
TMPL

        echo -e "${GREEN}Created:${NC}"
        echo "  saas_policies.json       (guardrail config)"
        echo "  saas_agents.json         (agent registration)"
        echo "  saas_tool_policies.json  (tool data policies)"
        echo ""
        echo -e "${YELLOW}Apply them:${NC}"
        echo "  Option 2 → saas_policies.json"
        echo "  Option 5 → saas_agents.json"
        echo "  Option 8 → saas_tool_policies.json"
        ;;

    # ── Info ───────────────────────────────
    14)
        echo ""
        echo -e "${BLUE}Tenant Overview${NC}"
        show_result "$(api GET /v1/tenant/me)"
        ;;

    15)
        echo ""
        echo -e "${BLUE}Usage & Quota${NC}"
        show_result "$(api GET /v1/tenant/me/usage)"
        ;;

    16)
        echo ""
        echo -e "${BLUE}Available Roles${NC}"
        show_result "$(api GET /v1/agents/roles)"
        ;;

    17)
        echo ""
        echo -e "${BLUE}Audit Log (last 20)${NC}"
        show_result "$(api GET '/v1/tenant/me/audit?limit=20')"
        ;;

    0)
        echo -e "${GREEN}Done.${NC}"
        exit 0
        ;;

    *)
        echo -e "${RED}Invalid choice${NC}"
        ;;
    esac

    echo -e "${DIM}Press Enter...${NC}"
    read -r
done
