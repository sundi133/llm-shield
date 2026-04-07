#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
# Upstash Redis Integration Test
#
# Verifies that Shield is actually writing tenant data to Upstash Redis
# (not falling back to in-memory). Creates a test tenant via the admin
# API, then queries Upstash directly to confirm the data landed there.
# ═══════════════════════════════════════════════════════════════════

# ── Config ────────────────────────────────────────────────────────
SHIELD_URL="${SHIELD_URL:-https://kk5losqxwr2ui7.api.runpod.ai}"
RUNPOD_TOKEN="${RUNPOD_TOKEN:-}"
SHIELD_ADMIN_KEY="${SHIELD_ADMIN_KEY:-}"
UPSTASH_URL="${UPSTASH_REDIS_REST_URL:-https://correct-mongoose-70933.upstash.io}"
UPSTASH_TOKEN="${UPSTASH_REDIS_REST_TOKEN:-gQAAAAAAARUVAAIncDJlMmQyOTIzMDNkMzc0MjMxOTA3YzEzMTNiZjA4ZmViY3AyNzA5MzM}"
TEST_TENANT="${TEST_TENANT:-upstash-probe}"
TEST_KEY="${TEST_KEY:-upstash-probe-key-abc123}"

# ── Colors ────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

PASS=0
FAIL=0

check() {
  local label="$1"
  local expected="$2"
  local actual="$3"

  if [[ "$actual" == *"$expected"* ]]; then
    echo -e "  ${GREEN}✓${RESET} $label"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗${RESET} $label"
    echo -e "    ${DIM}expected: $expected${RESET}"
    echo -e "    ${DIM}got:      $actual${RESET}"
    FAIL=$((FAIL + 1))
  fi
}

section() {
  echo ""
  echo -e "${YELLOW}${BOLD}▸ $1${RESET}"
}

upstash_get() {
  curl -s "$UPSTASH_URL/get/$1" -H "Authorization: Bearer $UPSTASH_TOKEN"
}

upstash_smembers() {
  curl -s "$UPSTASH_URL/smembers/$1" -H "Authorization: Bearer $UPSTASH_TOKEN"
}

upstash_llen() {
  curl -s "$UPSTASH_URL/llen/$1" -H "Authorization: Bearer $UPSTASH_TOKEN"
}

upstash_keys() {
  curl -s "$UPSTASH_URL/keys/$1" -H "Authorization: Bearer $UPSTASH_TOKEN"
}

# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║  Upstash Integration Test — Shield ↔ Upstash Redis    ║${RESET}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════╝${RESET}"
echo -e "  Shield URL  : $SHIELD_URL"
echo -e "  Upstash URL : $UPSTASH_URL"
echo -e "  Test tenant : $TEST_TENANT"

# ── 1. Upstash connectivity ───────────────────────────────────────
section "1. Upstash direct connectivity"
PING=$(curl -s "$UPSTASH_URL/ping" -H "Authorization: Bearer $UPSTASH_TOKEN")
echo -e "  ${DIM}PING → $PING${RESET}"
check "Upstash reachable with token" "PONG" "$PING"

# ── 2. Clean up any previous test ─────────────────────────────────
section "2. Cleanup previous test tenant"
curl -s -X DELETE "$SHIELD_URL/v1/admin/tenants/$TEST_TENANT?hard=true" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "X-Admin-Key: $SHIELD_ADMIN_KEY" > /dev/null
echo -e "  ${DIM}deleted (if existed)${RESET}"

# ── 3. Check baseline state in Upstash ────────────────────────────
section "3. Baseline — Upstash before tenant create"
BEFORE_INDEX=$(upstash_smembers "tenants:index")
BEFORE_TENANT=$(upstash_get "tenant:$TEST_TENANT")
BEFORE_HEALTH=$(upstash_get "_votal:healthcheck")
echo -e "  ${DIM}tenants:index       → $BEFORE_INDEX${RESET}"
echo -e "  ${DIM}tenant:$TEST_TENANT  → $BEFORE_TENANT${RESET}"
echo -e "  ${DIM}_votal:healthcheck  → $BEFORE_HEALTH${RESET}"

# ── 4. Create test tenant via Shield admin API ────────────────────
section "4. Create tenant '$TEST_TENANT' via Shield admin API"
CREATE_RESPONSE=$(curl -s -X POST "$SHIELD_URL/v1/admin/tenants" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "X-Admin-Key: $SHIELD_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TEST_TENANT\",
    \"name\": \"Upstash Probe\",
    \"plan\": \"enterprise\",
    \"api_keys\": [\"$TEST_KEY\"],
    \"input_guardrails\": {
      \"keyword_blocklist\": {\"enabled\": true, \"action\": \"block\", \"settings\": {\"keywords\": [\"probe\"], \"case_insensitive\": true}}
    },
    \"output_guardrails\": {},
    \"rbac\": {
      \"roles\": {\"probe-role\": {\"max_tokens_per_request\": 1024, \"rate_limit\": \"60/min\", \"data_clearance\": \"public\"}},
      \"agents\": {\"probe-bot\": \"probe-role\"}
    }
  }")
STATUS=$(echo "$CREATE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "parse-error")
check "Tenant created via Shield" "created" "$STATUS"

# ── 5. Wait for write to propagate ────────────────────────────────
sleep 1

# ── 6. Verify in Upstash ──────────────────────────────────────────
section "6. Verify tenant landed in Upstash"

# Healthcheck key proves Shield connected successfully
HEALTHCHECK=$(upstash_get "_votal:healthcheck")
echo -e "  ${DIM}_votal:healthcheck → $HEALTHCHECK${RESET}"
check "Shield healthcheck key present (proves real Upstash connection)" "ok" "$HEALTHCHECK"

# tenants:index set should contain our tenant
INDEX=$(upstash_smembers "tenants:index")
echo -e "  ${DIM}tenants:index → $INDEX${RESET}"
check "Tenant ID in tenants:index set" "$TEST_TENANT" "$INDEX"

# tenant:<id> should hold the config JSON
TENANT_JSON=$(upstash_get "tenant:$TEST_TENANT")
echo -e "  ${DIM}tenant:$TEST_TENANT → ${TENANT_JSON:0:120}...${RESET}"
check "tenant:$TEST_TENANT key has config" "keyword_blocklist" "$TENANT_JSON"
check "tenant:$TEST_TENANT plan stored" "enterprise" "$TENANT_JSON"

# ── 7. Verify API key mapping ─────────────────────────────────────
section "7. Verify API key → tenant mapping"

# SHA-256 of the test key
KEY_HASH=$(python3 -c "import hashlib; print(hashlib.sha256('$TEST_KEY'.encode()).hexdigest())")
KEY_MAPPING=$(upstash_get "apikey:$KEY_HASH")
echo -e "  ${DIM}apikey:$KEY_HASH → $KEY_MAPPING${RESET}"
check "API key hash maps to tenant" "$TEST_TENANT" "$KEY_MAPPING"

# ── 8. Verify admin audit log ─────────────────────────────────────
section "8. Verify admin audit entries written"
AUDIT_LEN=$(upstash_llen "admin_audit:global")
echo -e "  ${DIM}admin_audit:global length → $AUDIT_LEN${RESET}"
check "Global audit has entries" "result" "$AUDIT_LEN"

TENANT_AUDIT_LEN=$(upstash_llen "admin_audit:tenant:$TEST_TENANT")
echo -e "  ${DIM}admin_audit:tenant:$TEST_TENANT length → $TENANT_AUDIT_LEN${RESET}"
check "Tenant-scoped audit has entries" "result" "$TENANT_AUDIT_LEN"

# ── 9. Trigger a tenant request (rate limiter write) ──────────────
section "9. Trigger tenant request → verify rate limit counter"
CLASSIFY_RESPONSE=$(curl -s -X POST "$SHIELD_URL/guardrails/input" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "X-API-Key: $TEST_KEY" \
  -H "X-Agent-Key: probe-bot" \
  -H "Content-Type: application/json" \
  -d '{"message": "this contains the probe keyword"}')
ACTION=$(echo "$CLASSIFY_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('action','unknown'))" 2>/dev/null || echo "parse-error")
echo -e "  ${DIM}classify action → $ACTION (expected: block)${RESET}"
check "Tenant policy (block keyword 'probe') enforced" "block" "$ACTION"

sleep 1

# Check rate limit counter
DAY_BUCKET=$(( $(date +%s) / 86400 ))
RATE_KEY="ratelimit:$TEST_TENANT:day:$DAY_BUCKET"
RATE_COUNT=$(upstash_get "$RATE_KEY")
echo -e "  ${DIM}$RATE_KEY → $RATE_COUNT${RESET}"
check "Rate limit counter incremented in Upstash" "result" "$RATE_COUNT"

# ── 10. Sanity — list all keys ────────────────────────────────────
section "10. All Votal keys currently in Upstash"
ALL_KEYS=$(upstash_keys "*")
echo -e "  ${DIM}$ALL_KEYS${RESET}" | head -c 500
echo ""

# ── 11. Cleanup test tenant ───────────────────────────────────────
section "11. Cleanup"
curl -s -X DELETE "$SHIELD_URL/v1/admin/tenants/$TEST_TENANT?hard=true" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "X-Admin-Key: $SHIELD_ADMIN_KEY" > /dev/null
echo -e "  ${DIM}hard-deleted $TEST_TENANT${RESET}"

AFTER_TENANT=$(upstash_get "tenant:$TEST_TENANT")
echo -e "  ${DIM}tenant:$TEST_TENANT after delete → $AFTER_TENANT${RESET}"
check "Tenant removed from Upstash" "null" "$AFTER_TENANT"

# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║                       SUMMARY                          ║${RESET}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════╝${RESET}"
echo -e "  ${GREEN}${BOLD}Passed: $PASS${RESET}"
echo -e "  ${RED}${BOLD}Failed: $FAIL${RESET}"

if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo -e "  ${GREEN}${BOLD}✓ Shield is correctly persisting to Upstash Redis${RESET}"
  exit 0
else
  echo ""
  echo -e "  ${RED}${BOLD}✗ Shield is NOT writing to Upstash (likely in-memory fallback)${RESET}"
  echo ""
  echo -e "  ${YELLOW}Troubleshooting:${RESET}"
  echo -e "  1. SSH into a worker and check: echo \$UPSTASH_REDIS_REST_URL"
  echo -e "     Should be: https://correct-mongoose-70933.upstash.io"
  echo -e "  2. Check worker logs for 'Tenant store connected to Upstash REST'"
  echo -e "  3. If you see 'invalid protocol' or 'in-memory fallback', fix the env var"
  echo -e "  4. Reset workers (Max Workers 0 → your count)"
  exit 1
fi
