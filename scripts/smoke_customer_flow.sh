#!/usr/bin/env bash
#
# Customer-flow smoke test. Hits a RUNNING Shield instance (your docker
# container, RunPod deployment, etc.) using ONLY a tenant API key —
# exactly what an external customer would do. No admin key involved.
#
# Usage:
#   SHIELD_URL=http://localhost:8080 \
#   TENANT_KEY=bank-co-key \
#   ./scripts/smoke_customer_flow.sh
#
# Optional:
#   SHIELD_ADMIN_KEY=...   if set, the script will also auto-create the
#                          tenant + agent role on first run so a fresh
#                          container is usable in one go.
#   AGENT_ID=billing-bot   default agent id (must match an RBAC role if
#                          RBAC is configured).
#   SKIP_DENIAL=1          skip the RBAC-denial step (use if you don't
#                          want this script to touch tenant config).
#
# Exit codes:
#   0   all assertions pass
#   1   one or more assertions failed
#   2   container not reachable

set -u  # NOT -e: keep running on failures so the summary is complete

SHIELD_URL="${SHIELD_URL:-http://localhost:8080}"
TENANT_KEY="${TENANT_KEY:-}"
ADMIN_KEY="${SHIELD_ADMIN_KEY:-}"
AGENT_ID="${AGENT_ID:-billing-bot}"
TENANT_ID_HINT="${TENANT_ID_HINT:-bank-co}"   # used only when auto-provisioning

PASS=0; FAIL=0; FAILED=()
C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'

if [[ -z "$TENANT_KEY" ]]; then
  echo "${C_RED}TENANT_KEY env var required.${C_RESET}" >&2
  echo "Example: SHIELD_URL=$SHIELD_URL TENANT_KEY=bank-co-key $0" >&2
  exit 2
fi

# ── helpers ─────────────────────────────────────────────────────────────

step() { printf '\n%s── %s%s\n' "$C_BOLD" "$1" "$C_RESET"; }
pass() { PASS=$((PASS+1)); printf '  %s✓ PASS%s  %s\n' "$C_GREEN" "$C_RESET" "${1:-}"; }
fail() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  %s✗ FAIL%s  %s\n' "$C_RED" "$C_RESET" "${1:-}"; [[ -n "${2:-}" ]] && printf '         %sgot: %s%s\n' "$C_DIM" "$2" "$C_RESET"; }
note() { printf '  %s· %s%s\n' "$C_DIM" "$*" "$C_RESET"; }

json_get() {
  python3 - "$1" "$2" <<'PY' 2>/dev/null
import json, sys
try:
    obj = json.loads(sys.argv[1])
    for part in sys.argv[2].split('.'):
        if isinstance(obj, list):
            obj = obj[int(part)]
        else:
            obj = obj[part]
    sys.stdout.write(str(obj))
except Exception:
    sys.exit(1)
PY
}

call() {
  # call <method> <path> [body_json] [extra_curl_args...]
  local method="$1"; shift
  local path="$1"; shift
  local body="${1:-}"; shift || true
  local args=(-s -o /tmp/_csmoke.$$ -w '%{http_code}' -X "$method" "$SHIELD_URL$path")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  args+=("$@")
  local status; status=$(curl "${args[@]}")
  local body_out; body_out=$(cat /tmp/_csmoke.$$ 2>/dev/null || echo '')
  rm -f /tmp/_csmoke.$$
  printf '%s|%s' "$status" "$body_out"
}

# ── pre-flight ──────────────────────────────────────────────────────────

step "0. Pre-flight: container reachable?"
if curl -fs -o /dev/null -m 5 "$SHIELD_URL/healthz" 2>/dev/null || \
   curl -fs -o /dev/null -m 5 "$SHIELD_URL/" 2>/dev/null; then
  pass "$SHIELD_URL reachable"
else
  fail "$SHIELD_URL not reachable" "container not running, or URL wrong"
  echo
  echo "  Common fixes:"
  echo "    docker ps             — confirm shield is running"
  echo "    docker logs shield    — check for startup errors"
  echo "    SHIELD_URL=...        — set the right host:port"
  exit 2
fi

# ── optional auto-provision ─────────────────────────────────────────────

if [[ -n "$ADMIN_KEY" ]]; then
  step "1. Auto-provision tenant '$TENANT_ID_HINT' (admin key set)"
  body="{\"tenant_id\":\"$TENANT_ID_HINT\",\"name\":\"$TENANT_ID_HINT demo\",\"api_keys\":[\"$TENANT_KEY\"],\"plan\":\"enterprise\"}"
  result=$(call POST /v1/admin/tenants "$body" -H "X-Admin-Key: $ADMIN_KEY")
  status="${result%%|*}"
  if [[ "$status" == "200" || "$status" == "201" ]]; then
    pass "tenant created"
  elif [[ "$status" == "409" ]]; then
    note "tenant already exists — using it"
    pass "tenant present"
  else
    fail "could not create tenant ($status)" "${result#*|}"
    note "continuing — maybe the tenant is already there"
  fi
else
  step "1. Skipping tenant auto-provision (no SHIELD_ADMIN_KEY set)"
  note "if tenant '$TENANT_ID_HINT' isn't registered yet, step 2 will return 401"
  note "to enable auto-provision: export SHIELD_ADMIN_KEY=..."
fi

# ── 2. Tenant-scoped token issuance (the customer-facing endpoint) ──────

step "2. Customer mints an agent token using their tenant API key"
TOKEN_BODY=$(cat <<JSON
{
  "user_sub": "alice@$TENANT_ID_HINT.com",
  "agent_id": "$AGENT_ID",
  "agent_instance_id": "smoke-customer-$$",
  "build_hash": "sha256:smoke",
  "model_version": "claude-opus-4.7",
  "session_id": "smoke-session-$$",
  "ttl_seconds": 600
}
JSON
)
result=$(call POST /v1/tenant/me/agent-auth/agent-token "$TOKEN_BODY" -H "X-API-Key: $TENANT_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  TOKEN=$(json_get "$body" "agent_token")
  if [[ -n "$TOKEN" && "$TOKEN" == *.* ]]; then
    pass "token issued (length=${#TOKEN})"
  else
    fail "200 but no agent_token field" "$body"
    exit 1
  fi
elif [[ "$status" == "401" ]]; then
  fail "401 — tenant key '$TENANT_KEY' not recognized" "$body"
  echo
  echo "  ${C_YELLOW}Fix:${C_RESET} create the tenant first. Two options:"
  echo "    (a) rerun with SHIELD_ADMIN_KEY set so this script auto-creates it"
  echo "    (b) manually:"
  echo "        curl -X POST $SHIELD_URL/v1/admin/tenants \\"
  echo "          -H \"X-Admin-Key: \$YOUR_ADMIN_KEY\" \\"
  echo "          -H 'Content-Type: application/json' \\"
  echo "          -d '{\"tenant_id\":\"$TENANT_ID_HINT\",\"api_keys\":[\"$TENANT_KEY\"]}'"
  exit 1
else
  fail "unexpected status $status" "$body"
  exit 1
fi

# Pull the tenant_id back from the token so later assertions are exact
TENANT_FROM_TOKEN=$(python3 -c "
import base64, json, sys
payload = '$TOKEN'.split('.', 1)[0]
pad = '=' * (-len(payload) % 4)
print(json.loads(base64.urlsafe_b64decode(payload + pad).decode())['tenant_id'])
")
note "token tenant_id resolved server-side = $TENANT_FROM_TOKEN"

# ── 3. Tenant isolation (cannot spoof tenant_id in the body) ────────────

step "3. Customer cannot forge a different tenant_id"
SPOOF_BODY=$(cat <<JSON
{
  "user_sub": "mallory",
  "agent_id": "$AGENT_ID",
  "agent_instance_id": "spoof-$$",
  "tenant_id": "victim-tenant",
  "build_hash": "x", "model_version": "m", "session_id": "s"
}
JSON
)
result=$(call POST /v1/tenant/me/agent-auth/agent-token "$SPOOF_BODY" -H "X-API-Key: $TENANT_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  SPOOF_TOKEN=$(json_get "$body" "agent_token")
  SPOOF_TENANT=$(python3 -c "
import base64, json
payload = '$SPOOF_TOKEN'.split('.', 1)[0]
pad = '=' * (-len(payload) % 4)
print(json.loads(base64.urlsafe_b64decode(payload + pad).decode())['tenant_id'])
")
  if [[ "$SPOOF_TENANT" == "$TENANT_FROM_TOKEN" && "$SPOOF_TENANT" != "victim-tenant" ]]; then
    pass "tenant_id from API key wins ($SPOOF_TENANT, not 'victim-tenant')"
  else
    fail "tenant_id spoofing SUCCEEDED" "got tenant_id=$SPOOF_TENANT"
  fi
else
  fail "spoof attempt got unexpected status $status" "$body"
fi

# ── 4. Mint a capability ─────────────────────────────────────────────────

step "4. Mint a cap for a specific tool + resource"
CAP_BODY='{"tool":"send_email","resource":"user/u-42/inbox","ttl_seconds":30}'
result=$(call POST /v1/shield/cap/mint "$CAP_BODY" -H "X-Agent-Token: $TOKEN")
status="${result%%|*}"; body="${result#*|}"
CAP=""
if [[ "$status" == "200" ]]; then
  CAP=$(json_get "$body" "cap_token")
  pass "cap minted (length=${#CAP})"
elif [[ "$status" == "403" ]]; then
  fail "cap mint denied — agent '$AGENT_ID' may lack 'send_email' permission" "$body"
  note "if your tenant has RBAC configured, set AGENT_ID to one with send_email allowed"
  CAP=""
elif [[ "$status" == "429" ]]; then
  fail "rate limited at cap mint" "$body"
elif [[ "$status" == "401" ]]; then
  fail "agent token rejected at middleware" "$body"
else
  fail "cap mint unexpected status $status" "$body"
fi

# Many of the following steps need a valid cap. Skip them gracefully if not.

if [[ -n "$CAP" ]]; then
  # ── 5. Verify cap (first use succeeds) ─────────────────────────────────
  step "5. Tool server verifies the cap (first use)"
  verify_body=$(printf '{"cap_token":"%s","expected_tool":"send_email"}' "$CAP")
  result=$(call POST /v1/shield/cap/verify "$verify_body")
  body="${result#*|}"
  valid=$(json_get "$body" "valid")
  user=$(json_get "$body" "claims.user_sub")
  tenant=$(json_get "$body" "claims.tenant_id")
  if [[ "$valid" == "True" && "$tenant" == "$TENANT_FROM_TOKEN" ]]; then
    pass "valid=True, user=$user, tenant=$tenant"
  else
    fail "verify returned wrong shape" "valid=$valid tenant=$tenant"
  fi

  # ── 6. Replay rejected ────────────────────────────────────────────────
  step "6. Replay the same cap → must be rejected (nonce one-shot)"
  result=$(call POST /v1/shield/cap/verify "$verify_body")
  body="${result#*|}"
  valid=$(json_get "$body" "valid")
  err=$(json_get "$body" "error")
  if [[ "$valid" == "False" && "$err" == *replay* ]]; then
    pass "replay caught: $err"
  else
    fail "replay NOT detected (Redis may not be reachable from container)" \
         "valid=$valid err=$err"
  fi

  # ── 7. Wrong tool name → rejected ─────────────────────────────────────
  step "7. Mint another cap, try to use it with WRONG tool name"
  CAP3=$(curl -s -X POST $SHIELD_URL/v1/shield/cap/mint \
    -H "X-Agent-Token: $TOKEN" -H "Content-Type: application/json" \
    -d '{"tool":"send_email","resource":"u/x"}' 2>/dev/null \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('cap_token',''))")
  if [[ -n "$CAP3" ]]; then
    result=$(call POST /v1/shield/cap/verify \
      "{\"cap_token\":\"$CAP3\",\"expected_tool\":\"db_query\"}")
    body="${result#*|}"
    valid=$(json_get "$body" "valid"); err=$(json_get "$body" "error")
    if [[ "$valid" == "False" && "$err" == *"tool mismatch"* ]]; then
      pass "tool mismatch caught: $err"
    else
      fail "tool mismatch NOT detected" "valid=$valid err=$err"
    fi
  else
    fail "could not mint second cap for tool-mismatch test"
  fi
fi

# ── 8. Stats endpoint (tenant-scoped) ───────────────────────────────────

step "8. Read tenant stats via tenant key"
result=$(call GET "/v1/tenant/me/agent-auth/stats?days=1" "" -H "X-API-Key: $TENANT_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  issued=$(json_get "$body" "totals.token_issued")
  minted=$(json_get "$body" "totals.cap_minted")
  pass "stats: token_issued=$issued, cap_minted=$minted (today)"
else
  fail "stats endpoint not 200" "$status $body"
fi

# ── 9. Recent events endpoint ───────────────────────────────────────────

step "9. Read tenant recent events via tenant key"
result=$(call GET "/v1/tenant/me/agent-auth/recent?limit=5" "" -H "X-API-Key: $TENANT_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  count=$(python3 -c "import sys,json;print(len(json.loads(sys.stdin.read())['events']))" <<<"$body" 2>/dev/null)
  if [[ "$count" -gt 0 ]]; then
    pass "got $count event(s) — latest visible in portal"
  else
    fail "events list empty (stats endpoint shows counters but recent is empty)" ""
  fi
else
  fail "recent endpoint not 200" "$status $body"
fi

# ── 10. Quiet denial mode (M3) — only if SKIP_DENIAL is unset ───────────

if [[ "${SKIP_DENIAL:-0}" != "1" ]]; then
  step "10. AuthZ denial returns NO reasons in the body (M3 default)"
  # We rely on the deployment HAVING an RBAC config where the chosen agent
  # lacks SOME tool. If RBAC is unconfigured (open policy), this step skips.
  result=$(call POST /v1/shield/cap/mint \
    '{"tool":"definitely-not-allowed-xyz","resource":"r"}' \
    -H "X-Agent-Token: $TOKEN")
  status="${result%%|*}"; body="${result#*|}"
  if [[ "$status" == "403" ]]; then
    has_reasons=$(echo "$body" | grep -c '"reasons"' || true)
    has_request_id=$(echo "$body" | grep -c '"request_id"' || true)
    if [[ "$has_reasons" == "0" && "$has_request_id" -ge 1 ]]; then
      pass "denial body has request_id, NO reasons (M3 quiet mode working)"
    elif [[ "$has_reasons" -ge 1 ]]; then
      note "verbose mode is ON (SHIELD_VERBOSE_REASONS=1) — reasons present in body"
      pass "verbose mode confirmed"
    else
      fail "denial body unexpected shape" "$body"
    fi
  elif [[ "$status" == "200" ]]; then
    note "tool was allowed — RBAC may be unconfigured. Skipping M3 check."
  else
    note "unexpected status $status — skipping M3 check"
  fi
else
  note "skipping denial check (SKIP_DENIAL=1)"
fi

# ── summary ─────────────────────────────────────────────────────────────

printf '\n%s════════════════════════════════════════════%s\n' "$C_BOLD" "$C_RESET"
printf '%sCUSTOMER FLOW SUMMARY%s  %sPASS%s=%d  %sFAIL%s=%d\n' \
  "$C_BOLD" "$C_RESET" "$C_GREEN" "$C_RESET" "$PASS" "$C_RED" "$C_RESET" "$FAIL"

if (( FAIL > 0 )); then
  printf '\n%sFailed:%s\n' "$C_YELLOW" "$C_RESET"
  for f in "${FAILED[@]}"; do printf '  • %s\n' "$f"; done
  exit 1
fi

printf '\n%sAll customer-flow checks passed.%s\n' "$C_GREEN" "$C_RESET"
printf '%sNow open %s/tenant in a browser, log in with your tenant key,%s\n' "$C_DIM" "$SHIELD_URL" "$C_RESET"
printf '%sand click "Agent AuthN/AuthZ" — the events you just generated%s\n' "$C_DIM" "$C_RESET"
printf '%sare in the Recent Decisions table.%s\n' "$C_DIM" "$C_RESET"
exit 0
