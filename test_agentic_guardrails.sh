#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
# Enhanced Agentic Guardrails Test Suite
#
# Tests the new unified /guardrails/output endpoint with:
# - Agent registration and tool policies
# - Role-based tool authorization
# - LLM validation of tool calls
# - Data sanitization policies per tool
# ═══════════════════════════════════════════════════════════════════

# ── Configuration ─────────────────────────────────────────────────
RUNPOD_HOST="${RUNPOD_HOST:-https://kk5losqxwr2ui7.api.runpod.ai}"
TOKEN="${RUNPOD_TOKEN:-}"
SHIELD_ADMIN_KEY="${SHIELD_ADMIN_KEY:-}"
TENANT_ID="${TENANT_ID:-agentic-test-co}"
TENANT_API_KEY="${TENANT_API_KEY:-agentic-api-key-12345}"
AGENT_ID="${AGENT_ID:-healthcare-bot-1}"

BASE_URL="$RUNPOD_HOST"
ADMIN_URL="$BASE_URL/v1/admin/tenants"
AGENTS_URL="$BASE_URL/v1/agents"
GUARDRAILS_URL="$BASE_URL/guardrails/output"

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helper Functions ──────────────────────────────────────────────
echo_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║              Enhanced Agentic Guardrails         ║"
    echo "║         Tool Authorization & Validation          ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  Endpoint : $BASE_URL"
    echo -e "  Tenant   : $TENANT_ID"
    echo -e "  Agent    : $AGENT_ID"
    echo ""
}

section() {
    echo ""
    echo -e "${YELLOW}${BOLD}  ▸ $1${RESET}"
}

check_requirements() {
    if [ -z "$RUNPOD_TOKEN" ]; then
        echo -e "${RED}Error: RUNPOD_TOKEN not set${RESET}"
        echo "  export RUNPOD_TOKEN=\"your-token\""
        exit 1
    fi

    if [ -z "$SHIELD_ADMIN_KEY" ]; then
        echo -e "${RED}Error: SHIELD_ADMIN_KEY not set${RESET}"
        echo "  export SHIELD_ADMIN_KEY=\"your-admin-key\""
        exit 1
    fi
}

test_endpoint() {
    local name="$1" url="$2" method="$3" headers="$4" body="$5" expected="$6"

    echo -e "  ${CYAN}Testing:${RESET} $name"

    if [ "$method" = "POST" ]; then
        response=$(curl -s -X POST "$url" -H "Authorization: Bearer $TOKEN" $headers -d "$body" 2>/dev/null)
    elif [ "$method" = "GET" ]; then
        response=$(curl -s -X GET "$url" -H "Authorization: Bearer $TOKEN" $headers 2>/dev/null)
    fi

    if echo "$response" | grep -q "$expected" 2>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} $name → OK"
    else
        echo -e "  ${RED}✗${RESET} $name → Failed"
        echo -e "  ${YELLOW}Response:${RESET} $response" | head -3
    fi

    echo ""
}

# ── Main Test Flow ────────────────────────────────────────────────

echo_header
check_requirements

# ── 1. Create Test Tenant ────────────────────────────────────────
section "1. Create Test Tenant"

TENANT_PAYLOAD=$(cat <<EOF
{
    "tenant_id": "$TENANT_ID",
    "name": "Agentic Test Company",
    "description": "Test tenant for agentic guardrails",
    "api_keys": ["$TENANT_API_KEY"],
    "rate_limits": {
        "requests_per_day": 10000,
        "requests_per_minute": 100
    }
}
EOF
)

echo "Creating tenant $TENANT_ID..."
TENANT_RESPONSE=$(curl -s -X POST "$ADMIN_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Admin-Key: $SHIELD_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d "$TENANT_PAYLOAD" 2>/dev/null)

if echo "$TENANT_RESPONSE" | grep -q "success.*true" 2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} Tenant created successfully"
else
    echo -e "  ${YELLOW}⚠${RESET} Tenant might already exist (continuing...)"
fi

# ── 2. Register Healthcare Agent ─────────────────────────────────
section "2. Register Healthcare Agent"

AGENT_PAYLOAD=$(cat <<EOF
{
    "agent_id": "$AGENT_ID",
    "name": "Healthcare Support Bot",
    "description": "AI assistant for healthcare workflows",
    "tools": ["patient_lookup", "schedule_appointment", "update_records", "send_notification"],
    "role_permissions": {
        "admin": ["patient_lookup", "schedule_appointment", "update_records", "send_notification"],
        "doctor": ["patient_lookup", "schedule_appointment", "update_records"],
        "nurse": ["patient_lookup", "schedule_appointment"],
        "patient": ["schedule_appointment"],
        "guest": []
    }
}
EOF
)

test_endpoint \
    "Agent Registration" \
    "$AGENTS_URL/register" \
    "POST" \
    "-H 'X-API-Key: $TENANT_API_KEY' -H 'Content-Type: application/json'" \
    "$AGENT_PAYLOAD" \
    "success"

# ── 3. Configure Tool Policies ───────────────────────────────────
section "3. Configure Tool Policies"

TOOL_POLICIES_PAYLOAD=$(cat <<EOF
{
    "policies": {
        "patient_lookup": {
            "data_sanitization": {
                "redact_ssn": true,
                "mask_phone": true,
                "patterns": [
                    {"regex": "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b", "replacement": "[SSN_REDACTED]"},
                    {"regex": "\\\\b\\\\d{3}-\\\\d{3}-\\\\d{4}\\\\b", "replacement": "[PHONE_REDACTED]"}
                ]
            },
            "llm_validation": {
                "enabled": true,
                "prompt": "Analyze if this patient lookup is appropriate for {user_role}: {tool_input}. Is this a legitimate medical need? Respond APPROPRIATE or INAPPROPRIATE with reasoning.",
                "confidence_threshold": 0.7
            },
            "role_restrictions": {
                "doctor": "allow",
                "nurse": "allow",
                "patient": "block",
                "guest": "block"
            }
        },
        "update_records": {
            "llm_validation": {
                "enabled": true,
                "prompt": "Is this medical record update appropriate for {user_role}? Check if the user has permission to modify this type of data: {tool_input}",
                "confidence_threshold": 0.8
            },
            "role_restrictions": {
                "admin": "allow",
                "doctor": "allow",
                "nurse": "redact",
                "patient": "block"
            }
        },
        "schedule_appointment": {
            "role_restrictions": {
                "admin": "allow",
                "doctor": "allow",
                "nurse": "allow",
                "patient": "allow",
                "guest": "block"
            }
        }
    }
}
EOF
)

test_endpoint \
    "Tool Policies Configuration" \
    "$AGENTS_URL/tools/policies" \
    "POST" \
    "-H 'X-API-Key: $TENANT_API_KEY' -H 'Content-Type: application/json'" \
    "$TOOL_POLICIES_PAYLOAD" \
    "success"

# ── 4. Test Authorization Checks ─────────────────────────────────
section "4. Test Role-Based Authorization"

# Test 1: Doctor accessing patient lookup (should be allowed)
AUTH_TEST_1=$(cat <<EOF
{
    "agent_id": "$AGENT_ID",
    "tool_name": "patient_lookup",
    "user_role": "doctor",
    "tool_input": {"patient_id": "P12345"}
}
EOF
)

test_endpoint \
    "Doctor → Patient Lookup (Allow)" \
    "$AGENTS_URL/authorize" \
    "POST" \
    "-H 'X-API-Key: $TENANT_API_KEY' -H 'Content-Type: application/json'" \
    "$AUTH_TEST_1" \
    "allowed.*true"

# Test 2: Patient accessing update_records (should be blocked)
AUTH_TEST_2=$(cat <<EOF
{
    "agent_id": "$AGENT_ID",
    "tool_name": "update_records",
    "user_role": "patient",
    "tool_input": {"patient_id": "P12345", "diagnosis": "Updated condition"}
}
EOF
)

test_endpoint \
    "Patient → Update Records (Block)" \
    "$AGENTS_URL/authorize" \
    "POST" \
    "-H 'X-API-Key: $TENANT_API_KEY' -H 'Content-Type: application/json'" \
    "$AUTH_TEST_2" \
    "allowed.*false"

# ── 5. Test Enhanced Guardrails Output ───────────────────────────
section "5. Test Enhanced /guardrails/output"

# Test 1: Legitimate tool output with data sanitization
TOOL_OUTPUT_TEST_1=$(cat <<EOF
{
    "output": "Patient John Doe (SSN: 123-45-6789) has appointment scheduled. Contact: 555-123-4567",
    "context": {
        "tool_name": "patient_lookup",
        "agent_id": "$AGENT_ID",
        "user_role": "nurse",
        "tool_input": {"patient_id": "P12345"}
    }
}
EOF
)

echo -e "  ${CYAN}Testing:${RESET} Tool output with data sanitization"
GUARDRAIL_RESPONSE_1=$(curl -s -X POST "$GUARDRAILS_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-API-Key: $TENANT_API_KEY" \
    -H "X-User-Role: nurse" \
    -H "X-Agent-ID: $AGENT_ID" \
    -H "Content-Type: application/json" \
    -d "$TOOL_OUTPUT_TEST_1" 2>/dev/null)

if echo "$GUARDRAIL_RESPONSE_1" | grep -q "SSN_REDACTED\|PHONE_REDACTED" 2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} Data sanitization working"
else
    echo -e "  ${RED}✗${RESET} Data sanitization failed"
    echo -e "  ${YELLOW}Response:${RESET} $GUARDRAIL_RESPONSE_1" | head -2
fi

# Test 2: Unauthorized tool call (patient trying to update records)
TOOL_OUTPUT_TEST_2=$(cat <<EOF
{
    "output": "Updated patient diagnosis to chronic condition",
    "context": {
        "tool_name": "update_records",
        "agent_id": "$AGENT_ID",
        "user_role": "patient",
        "tool_input": {"patient_id": "P12345", "diagnosis": "chronic condition"}
    }
}
EOF
)

echo -e "  ${CYAN}Testing:${RESET} Unauthorized tool call (should block)"
GUARDRAIL_RESPONSE_2=$(curl -s -X POST "$GUARDRAILS_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-API-Key: $TENANT_API_KEY" \
    -H "X-User-Role: patient" \
    -H "X-Agent-ID: $AGENT_ID" \
    -H "Content-Type: application/json" \
    -d "$TOOL_OUTPUT_TEST_2" 2>/dev/null)

if echo "$GUARDRAIL_RESPONSE_2" | grep -q "safe.*false\|action.*block" 2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} Unauthorized access blocked"
else
    echo -e "  ${RED}✗${RESET} Authorization check failed"
    echo -e "  ${YELLOW}Response:${RESET} $GUARDRAIL_RESPONSE_2" | head -2
fi

# ── 6. Test Agent Registry Query ─────────────────────────────────
section "6. Verify Agent Registry"

test_endpoint \
    "Get Agent Registry" \
    "$AGENTS_URL/registry" \
    "GET" \
    "-H 'X-API-Key: $TENANT_API_KEY'" \
    "" \
    "$AGENT_ID"

test_endpoint \
    "Get Tool Policies" \
    "$AGENTS_URL/tools/policies" \
    "GET" \
    "-H 'X-API-Key: $TENANT_API_KEY'" \
    "" \
    "patient_lookup"

# ── Summary ───────────────────────────────────────────────────────
section "Test Summary"

echo -e "${CYAN}${BOLD}Enhanced Agentic Guardrails Test Complete!${RESET}"
echo ""
echo -e "${YELLOW}What was tested:${RESET}"
echo "  • Agent registration with role-based tool permissions"
echo "  • Tool policy configuration (data sanitization, LLM validation)"
echo "  • Role-based authorization checks"
echo "  • Enhanced /guardrails/output with tool call validation"
echo "  • Data sanitization (SSN/phone redaction)"
echo "  • Authorization blocking for unauthorized tool calls"
echo ""
echo -e "${GREEN}Integration Guide:${RESET}"
echo "  1. Register agents: POST $AGENTS_URL/register"
echo "  2. Set tool policies: PUT $AGENTS_URL/tools/policies"
echo "  3. Check authorization: POST $AGENTS_URL/authorize"
echo "  4. Validate output: POST $GUARDRAILS_URL (with X-User-Role, X-Agent-ID)"
echo ""
echo -e "${CYAN}Developer Resources:${RESET}"
echo "  • API Examples: GET $AGENTS_URL/integration/examples"
echo "  • Supported Roles: GET $AGENTS_URL/roles"
echo "  • Documentation: $BASE_URL/docs"
echo ""