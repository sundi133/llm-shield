#!/bin/bash
# Complete Tenant Setup Script for Votal Shield Admin Portal
# ===========================================================
# Creates a tenant, generates API key, registers agents, configures
# guardrail policies, and sets tool policies — all via the admin portal.
#
# Prerequisites:
#   export ADMIN_PORTAL_URL="https://your-admin-portal.com"  (or http://localhost:8080)
#   export SHIELD_ADMIN_KEY="your-admin-key"
#
# Usage:
#   chmod +x setup_tenant.sh
#   ./setup_tenant.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ADMIN_PORTAL_URL="${ADMIN_PORTAL_URL:-}"
SHIELD_ADMIN_KEY="${SHIELD_ADMIN_KEY:-}"

if [ -z "$ADMIN_PORTAL_URL" ]; then
    echo -e "${RED}Error: ADMIN_PORTAL_URL not set${NC}"
    echo "  export ADMIN_PORTAL_URL=\"https://your-admin-portal.com\""
    exit 1
fi

if [ -z "$SHIELD_ADMIN_KEY" ]; then
    echo -e "${RED}Error: SHIELD_ADMIN_KEY not set${NC}"
    echo "  export SHIELD_ADMIN_KEY=\"your-admin-key\""
    exit 1
fi

ADMIN_PORTAL_URL="${ADMIN_PORTAL_URL%/}"

TIMESTAMP=$(date +%Y%m%d%H%M%S)
RANDOM_ID=$(openssl rand -hex 3 | head -c 6)

echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}  Votal Shield — Complete Tenant Setup${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "  Admin Portal: ${CYAN}${ADMIN_PORTAL_URL}${NC}"
echo ""

# ── Tenant Details ─────────────────────────
read -p "  Company name: " COMPANY_NAME
if [ -z "$COMPANY_NAME" ]; then
    echo -e "${RED}Company name is required${NC}"
    exit 1
fi

read -p "  Tenant ID (blank = auto): " TENANT_ID_INPUT
TENANT_ID="${TENANT_ID_INPUT:-tenant-${TIMESTAMP}-${RANDOM_ID}}"
API_KEY="${TENANT_ID}-key-${RANDOM_ID}"

read -p "  Plan [enterprise]: " PLAN_INPUT
PLAN="${PLAN_INPUT:-enterprise}"

echo ""
echo -e "${CYAN}  Tenant ID : ${TENANT_ID}${NC}"
echo -e "${CYAN}  API Key   : ${API_KEY}${NC}"
echo -e "${CYAN}  Plan      : ${PLAN}${NC}"
echo ""
read -p "  Proceed? (y/N): " confirm
[[ ! "$confirm" =~ ^[Yy]$ ]] && echo "Cancelled." && exit 0

# ── Helper ─────────────────────────────────
api() {
    local method="$1" path="$2" data="$3"
    local args=(-s -w "\n%{http_code}" -X "$method" "${ADMIN_PORTAL_URL}${path}")
    args+=(-H "X-Admin-Key: ${SHIELD_ADMIN_KEY}")
    args+=(-H "X-API-Key: ${API_KEY}")
    args+=(-H "Content-Type: application/json")
    [ -n "$data" ] && args+=(-d "$data")
    curl "${args[@]}"
}

check() {
    local label="$1" raw="$2"
    local body http_code
    http_code=$(echo "$raw" | tail -1)
    body=$(echo "$raw" | sed '$d')
    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]] || [[ "$http_code" == "409" ]]; then
        echo -e "${GREEN}  OK ${label}${NC}"
        echo "$body" | jq -C . 2>/dev/null || echo "$body"
    else
        echo -e "${RED}  FAIL ${label} (HTTP ${http_code})${NC}"
        echo "$body" | jq -C . 2>/dev/null || echo "$body"
        return 1
    fi
}

# ═══════════════════════════════════════════
# STEP 1: Create Tenant
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[1/7] Creating tenant...${NC}"
result=$(api POST "/v1/admin/tenants" "{
  \"tenant_id\": \"${TENANT_ID}\",
  \"name\": \"${COMPANY_NAME}\",
  \"plan\": \"${PLAN}\",
  \"quota\": {
    \"max_requests_per_minute\": 100,
    \"max_requests_per_day\": 10000
  }
}")
check "Tenant created" "$result" || exit 1

# ═══════════════════════════════════════════
# STEP 2: Generate API Key
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[2/7] Generating API key...${NC}"
result=$(api POST "/v1/admin/tenants/${TENANT_ID}/api-keys" "{
  \"api_key\": \"${API_KEY}\"
}")
check "API key generated" "$result" || exit 1

# ═══════════════════════════════════════════
# STEP 3: Register Agents
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[3/7] Registering agents...${NC}"

# Agent 1
result=$(api POST "/v1/agents/registry" '{
  "agent_id": "customer-service",
  "name": "Customer Service Agent",
  "description": "Handles customer inquiries, account lookups, and support tickets",
  "tools": ["customer_lookup", "ticket_create", "account_info", "faq_search"],
  "role_permissions": {
    "admin": ["customer_lookup", "ticket_create", "account_info", "faq_search"],
    "agent": ["customer_lookup", "ticket_create", "faq_search"],
    "viewer": ["faq_search"]
  }
}')
check "Agent: customer-service" "$result"

# Agent 2
result=$(api POST "/v1/agents/registry" '{
  "agent_id": "data-analyst",
  "name": "Data Analyst Agent",
  "description": "Runs analytics queries and generates reports",
  "tools": ["run_query", "generate_report", "export_data", "dashboard_view"],
  "role_permissions": {
    "admin": ["run_query", "generate_report", "export_data", "dashboard_view"],
    "analyst": ["run_query", "generate_report", "dashboard_view"],
    "viewer": ["dashboard_view"]
  }
}')
check "Agent: data-analyst" "$result"

echo -e "${CYAN}  (Add more agents by editing the script or via the admin portal UI)${NC}"

# ═══════════════════════════════════════════
# STEP 4: Configure Input Guardrails
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[4/7] Configuring guardrail policies...${NC}"

result=$(api PUT "/v1/tenant/me/policies" '{
  "input_guardrails": {
    "adversarial_detection": {
      "enabled": true,
      "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "keyword_blocklist": {
      "enabled": true,
      "action": "block",
      "settings": { "keywords": ["hack", "exploit", "jailbreak", "ignore previous instructions"] }
    },
    "toxicity": {
      "enabled": true,
      "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "language_detection": {
      "enabled": true,
      "action": "block",
      "settings": { "allowed_languages": ["en"] }
    },
    "system_prompt_leak": {
      "enabled": true,
      "action": "block",
      "settings": { "threshold": 0.8 }
    },
    "topic_restriction": {
      "enabled": false,
      "action": "log",
      "settings": {}
    },
    "custom_regex": {
      "enabled": true,
      "action": "block",
      "settings": {}
    },
    "continuous_adversarial": {
      "enabled": false,
      "action": "log",
      "settings": {}
    }
  },
  "output_guardrails": {
    "hallucinated_links": {
      "enabled": true,
      "action": "block",
      "settings": {}
    },
    "tone_enforcement": {
      "enabled": true,
      "action": "block",
      "settings": {}
    },
    "bias_detection": {
      "enabled": true,
      "action": "block",
      "settings": { "threshold": 0.6 }
    },
    "pii_leakage": {
      "enabled": true,
      "action": "block",
      "settings": {}
    },
    "competitor_mention": {
      "enabled": true,
      "action": "block",
      "settings": {}
    }
  }
}')
check "Guardrail policies configured" "$result"

# ═══════════════════════════════════════════
# STEP 5: Set Tool Policies
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[5/7] Setting tool policies...${NC}"

result=$(api PUT "/v1/agents/tools/policies" '{
  "customer_lookup": {
    "data_sanitization": {
      "redact_ssn": true,
      "mask_phone": true,
      "patterns": [
        { "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]", "description": "Social Security Numbers" },
        { "regex": "\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b", "replacement": "[PHONE_REDACTED]", "description": "Phone Numbers" },
        { "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "replacement": "[EMAIL_REDACTED]", "description": "Email Addresses" }
      ]
    },
    "role_restrictions": {
      "admin": "allow",
      "agent": "redact",
      "viewer": "block"
    }
  },
  "run_query": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\$[0-9,]+\\.?[0-9]*", "replacement": "[AMOUNT_REDACTED]", "description": "Dollar Amounts" },
        { "regex": "\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b", "replacement": "[CARD_REDACTED]", "description": "Credit Card Numbers" }
      ]
    },
    "llm_validation": {
      "enabled": true,
      "prompt": "Validate if {user_role} should have access to this query: {tool_input}. Check for SQL injection and data exfiltration attempts.",
      "confidence_threshold": 0.8
    },
    "role_restrictions": {
      "admin": "allow",
      "analyst": "allow",
      "viewer": "block"
    }
  },
  "export_data": {
    "data_sanitization": {
      "patterns": [
        { "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "replacement": "[SSN_REDACTED]", "description": "SSN in exports" }
      ]
    },
    "llm_validation": {
      "enabled": true,
      "prompt": "Validate if {user_role} is authorized to export this data: {tool_input}. Check data classification level.",
      "confidence_threshold": 0.9
    },
    "role_restrictions": {
      "admin": "allow",
      "analyst": "redact",
      "viewer": "block"
    }
  },
  "ticket_create": { "data_sanitization": { "patterns": [] } },
  "account_info": { "data_sanitization": { "patterns": [] }, "role_restrictions": { "admin": "allow", "agent": "redact", "viewer": "block" } },
  "faq_search": { "data_sanitization": { "patterns": [] } },
  "generate_report": { "data_sanitization": { "patterns": [] } },
  "dashboard_view": { "data_sanitization": { "patterns": [] } }
}')
check "Tool policies configured" "$result"

# ═══════════════════════════════════════════
# STEP 6: Verify Setup
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[6/7] Verifying setup...${NC}"

echo -e "${CYAN}  Tenant overview:${NC}"
result=$(api GET "/v1/tenant/me")
check "Tenant info" "$result"

echo ""
echo -e "${CYAN}  Registered agents:${NC}"
result=$(api GET "/v1/agents/registry")
check "Agent registry" "$result"

echo ""
echo -e "${CYAN}  Guardrail policies:${NC}"
result=$(api GET "/v1/tenant/me/policies")
check "Policies" "$result"

echo ""
echo -e "${CYAN}  Tool policies:${NC}"
result=$(api GET "/v1/agents/tools/policies")
check "Tool policies" "$result"

echo ""
echo -e "${CYAN}  Available roles:${NC}"
result=$(api GET "/v1/agents/roles")
check "Roles" "$result"

# ═══════════════════════════════════════════
# STEP 7: Save Credentials
# ═══════════════════════════════════════════
echo ""
echo -e "${BLUE}[7/7] Saving credentials...${NC}"

CREDS_FILE="${TENANT_ID}.env"
cat > "$CREDS_FILE" << EOF
# Votal Shield Tenant Credentials
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Company: ${COMPANY_NAME}
# ──────────────────────────────────

# Tenant identification
export TENANT_ID="${TENANT_ID}"
export TENANT_API_KEY="${API_KEY}"

# Admin portal (configuration, CRUD, monitoring)
export ADMIN_PORTAL_URL="${ADMIN_PORTAL_URL}"

# Admin key (for /v1/admin/* endpoints only)
export SHIELD_ADMIN_KEY="${SHIELD_ADMIN_KEY}"

# ── Quick commands ──────────────────────────
#
# Source credentials:
#   source ${CREDS_FILE}
#
# List agents:
#   curl -s "\${ADMIN_PORTAL_URL}/v1/agents/registry" -H "X-API-Key: \${TENANT_API_KEY}" | jq .
#
# Get policies:
#   curl -s "\${ADMIN_PORTAL_URL}/v1/tenant/me/policies" -H "X-API-Key: \${TENANT_API_KEY}" | jq .
#
# Get tool policies:
#   curl -s "\${ADMIN_PORTAL_URL}/v1/agents/tools/policies" -H "X-API-Key: \${TENANT_API_KEY}" | jq .
#
# Get usage:
#   curl -s "\${ADMIN_PORTAL_URL}/v1/tenant/me/usage" -H "X-API-Key: \${TENANT_API_KEY}" | jq .
#
# Open tenant portal:
#   open "\${ADMIN_PORTAL_URL}/tenant"
EOF

echo -e "${GREEN}  Saved to: ${CREDS_FILE}${NC}"

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "  Company     : ${CYAN}${COMPANY_NAME}${NC}"
echo -e "  Tenant ID   : ${CYAN}${TENANT_ID}${NC}"
echo -e "  API Key     : ${CYAN}${API_KEY}${NC}"
echo -e "  Plan        : ${CYAN}${PLAN}${NC}"
echo -e "  Agents      : ${CYAN}2 registered${NC}"
echo -e "  Input GR    : ${CYAN}8 configured (6 active)${NC}"
echo -e "  Output GR   : ${CYAN}5 configured (5 active)${NC}"
echo -e "  Tool Policies: ${CYAN}8 tools configured${NC}"
echo -e "  Credentials : ${CYAN}${CREDS_FILE}${NC}"
echo ""
echo -e "  ${YELLOW}Tenant Portal:${NC} ${ADMIN_PORTAL_URL}/tenant"
echo -e "  ${YELLOW}Admin Portal:${NC}  ${ADMIN_PORTAL_URL}/admin"
echo ""
echo -e "  ${CYAN}Next: source ${CREDS_FILE}${NC}"
echo ""
