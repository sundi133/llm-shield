#!/usr/bin/env bash
#
# End-to-end smoke test for the agent AuthN/AuthZ feature.
#
# Exercises mint/verify/revoke/replay/expiry/binding/build-allowlist/
# signer-backend dispatch through the real HTTP server. Prints PASS/FAIL
# per step and exits non-zero if any step fails.
#
# Usage:  scripts/smoke_agent_auth.sh
# Env:    PORT (default 8765), KEEP_LOG=1 to dump server log on exit
#
# Requires: python3, uvicorn, cryptography>=42, fastapi, httpx, pydantic, curl

set -u  # NOT -e: we want to keep running on test failures

PORT="${PORT:-8765}"
HOST="http://localhost:${PORT}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_LOG="$(mktemp -t shield-smoke.XXXXXX.log)"
SERVER_PID=""

PASS_COUNT=0
FAIL_COUNT=0
FAILED_STEPS=()
CURRENT_STEP=""

# ── pretty output ────────────────────────────────────────────────────────

C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'

step() {
  CURRENT_STEP="$1"
  printf '\n%s%s%s\n' "$C_BOLD" "── $1" "$C_RESET"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '  %s✓ PASS%s  %s\n' "$C_GREEN" "$C_RESET" "${1:-}"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  FAILED_STEPS+=("$CURRENT_STEP — ${1:-assertion}")
  printf '  %s✗ FAIL%s  %s\n' "$C_RED" "$C_RESET" "${1:-}"
  if [[ -n "${2:-}" ]]; then
    printf '         %sgot: %s%s\n' "$C_DIM" "$2" "$C_RESET"
  fi
}

note() { printf '  %s· %s%s\n' "$C_DIM" "$*" "$C_RESET"; }

# ── server lifecycle ─────────────────────────────────────────────────────

start_server() {
  local extra_env="$1"   # e.g. 'SHIELD_AGENT_ALLOWED_BUILDS=sha256:foo'
  cd "$REPO_ROOT"
  (
    [[ -n "$extra_env" ]] && export $extra_env
    exec python3 -m uvicorn scripts._smoke_app:app --port "$PORT" \
         --log-level warning >>"$SERVER_LOG" 2>&1
  ) &
  SERVER_PID=$!
  # Wait until healthz responds (up to 10s)
  local i
  for i in $(seq 1 50); do
    if curl -fs -o /dev/null "$HOST/healthz" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  echo "${C_RED}server failed to start in 10s${C_RESET}"
  cat "$SERVER_LOG"
  exit 99
}

stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

cleanup() {
  stop_server
  if [[ "${KEEP_LOG:-0}" == "1" ]]; then
    echo
    echo "── server log ($SERVER_LOG) ──"
    cat "$SERVER_LOG"
  else
    rm -f "$SERVER_LOG"
  fi
}
trap cleanup EXIT INT TERM

# ── helpers ──────────────────────────────────────────────────────────────

# json_get '<json>' '<dotted.path>' → prints value, exits 1 if missing
json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    obj = json.loads(sys.argv[1])
    for part in sys.argv[2].split('.'):
        obj = obj[part]
    sys.stdout.write(str(obj))
except Exception:
    sys.exit(1)
PY
}

# call <method> <path> [body_json] [extra_curl_args...]
# Always returns: "<HTTP_STATUS>|<BODY>" on stdout
call() {
  local method="$1"; shift
  local path="$1"; shift
  local body="${1:-}"; shift || true
  local args=(-s -o /tmp/_smoke_body.$$ -w '%{http_code}' -X "$method" "$HOST$path")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  args+=("$@")
  local status
  status=$(curl "${args[@]}")
  local body_out
  body_out=$(cat /tmp/_smoke_body.$$ 2>/dev/null || echo '')
  rm -f /tmp/_smoke_body.$$
  printf '%s|%s' "$status" "$body_out"
}

# Quick env setup for keys used by the local backend
generate_keys() {
  export SHIELD_AGENT_TOKEN_PRIVATE_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
  export SHIELD_CAP_TOKEN_PRIVATE_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
  export SHIELD_ADMIN_KEY="smoke-admin-$(date +%s)"
}

# Default body for issuing an agent token
TOKEN_BODY='{"user_sub":"alice","agent_id":"billing-bot","agent_instance_id":"inst-1","tenant_id":"t1","build_hash":"sha256:abc","model_version":"opus-4.7","session_id":"s1","ttl_seconds":600}'

# ══════════════════════════════════════════════════════════════════════════
# PHASE A — happy path, binding, replay, expiry, revocation
# ══════════════════════════════════════════════════════════════════════════

generate_keys
start_server ''
note "server up on $HOST"

# ─── Step 1: issue an agent token ───────────────────────────────────────
step "1. Issue an agent token (admin key valid)"
result=$(call POST /v1/shield/auth/agent-token "$TOKEN_BODY" -H "X-Admin-Key: $SHIELD_ADMIN_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  TOKEN=$(json_get "$body" "agent_token")
  if [[ -n "$TOKEN" && "$TOKEN" == *.* ]]; then
    pass "token issued (len=${#TOKEN})"
  else
    fail "response missing or malformed agent_token" "$body"
  fi
else
  fail "expected 200" "$status $body"
fi

# ─── Step 2: issuance is admin-gated ────────────────────────────────────
step "2. Issuance requires admin key"
result=$(call POST /v1/shield/auth/agent-token "$TOKEN_BODY")
status="${result%%|*}"
[[ "$status" == "403" ]] && pass "no key → 403" || fail "no key did not 403" "$status"
result=$(call POST /v1/shield/auth/agent-token "$TOKEN_BODY" -H "X-Admin-Key: wrong-key")
status="${result%%|*}"
[[ "$status" == "403" ]] && pass "wrong key → 403" || fail "wrong key did not 403" "$status"

# ─── Step 3: TTL ceiling ─────────────────────────────────────────────────
step "3. Agent-token TTL ceiling (15m)"
oversize='{"user_sub":"a","agent_id":"a","agent_instance_id":"a","tenant_id":"a","build_hash":"a","model_version":"m","session_id":"s","ttl_seconds":1000}'
result=$(call POST /v1/shield/auth/agent-token "$oversize" -H "X-Admin-Key: $SHIELD_ADMIN_KEY")
status="${result%%|*}"
[[ "$status" == "422" || "$status" == "400" ]] && pass "ttl=1000 rejected ($status)" || fail "ttl=1000 not rejected" "$status"

# ─── Step 4: cap mint rejects missing/bogus/tampered tokens ──────────────
step "4. Cap mint requires verified agent token"
mint_body='{"tool":"send_email","resource":"alice/inbox"}'
result=$(call POST /v1/shield/cap/mint "$mint_body")
[[ "${result%%|*}" == "401" ]] && pass "no token → 401" || fail "no token did not 401" "${result%%|*}"
result=$(call POST /v1/shield/cap/mint "$mint_body" -H "X-Agent-Token: garbage")
[[ "${result%%|*}" == "401" ]] && pass "garbage token → 401" || fail "garbage token did not 401" "${result%%|*}"
# Tamper a char in the middle of the payload half (safe against base64 padding edges)
mid=$((${#TOKEN} / 4))
TAMPERED="${TOKEN:0:$mid}X${TOKEN:$((mid+1))}"
result=$(call POST /v1/shield/cap/mint "$mint_body" -H "X-Agent-Token: $TAMPERED")
[[ "${result%%|*}" == "401" ]] && pass "tampered token → 401" || fail "tampered token did not 401" "${result%%|*}"

# ─── Step 5: cap mint happy path ─────────────────────────────────────────
step "5. Cap mint happy path"
result=$(call POST /v1/shield/cap/mint "$mint_body" -H "X-Agent-Token: $TOKEN")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  CAP=$(json_get "$body" "cap_token")
  if [[ -n "$CAP" && "$CAP" == *.* ]]; then
    pass "cap minted (len=${#CAP})"
  else
    fail "response missing cap_token" "$body"
  fi
else
  fail "expected 200" "$status $body"
fi

# ─── Step 6: cap verify happy path ──────────────────────────────────────
step "6. Cap verify happy path"
verify_body=$(printf '{"cap_token":"%s","expected_tool":"send_email"}' "$CAP")
result=$(call POST /v1/shield/cap/verify "$verify_body")
status="${result%%|*}"; body="${result#*|}"
valid=$(json_get "$body" "valid" 2>/dev/null || echo "?")
user=$(json_get "$body" "claims.user_sub" 2>/dev/null || echo "?")
tenant=$(json_get "$body" "claims.tenant_id" 2>/dev/null || echo "?")
if [[ "$status" == "200" && "$valid" == "True" && "$user" == "alice" && "$tenant" == "t1" ]]; then
  pass "valid=True, user=alice, tenant=t1"
else
  fail "verify response wrong" "status=$status valid=$valid user=$user tenant=$tenant"
fi

# ─── Step 7: replay rejected ────────────────────────────────────────────
step "7. Replay rejected (nonce one-shot)"
result=$(call POST /v1/shield/cap/verify "$verify_body")
body="${result#*|}"
valid=$(json_get "$body" "valid" 2>/dev/null || echo "?")
err=$(json_get "$body" "error" 2>/dev/null || echo "")
if [[ "$valid" == "False" && "$err" == *replay* ]]; then
  pass "second verify → valid=False, error mentions replay"
else
  fail "replay not detected" "valid=$valid error=$err"
fi

# ─── Step 8: tool binding ───────────────────────────────────────────────
step "8. Tool binding enforced"
result=$(call POST /v1/shield/cap/mint '{"tool":"db_query","resource":"orders"}' -H "X-Agent-Token: $TOKEN")
CAP2=$(json_get "${result#*|}" "cap_token")
verify_body=$(printf '{"cap_token":"%s","expected_tool":"send_email"}' "$CAP2")
result=$(call POST /v1/shield/cap/verify "$verify_body")
body="${result#*|}"
valid=$(json_get "$body" "valid" 2>/dev/null || echo "?")
err=$(json_get "$body" "error" 2>/dev/null || echo "")
if [[ "$valid" == "False" && "$err" == *"tool mismatch"* ]]; then
  pass "wrong tool → valid=False, error mentions tool mismatch"
else
  fail "tool mismatch not detected" "valid=$valid error=$err"
fi

# ─── Step 9: resource binding ───────────────────────────────────────────
step "9. Resource binding enforced"
result=$(call POST /v1/shield/cap/mint '{"tool":"db_query","resource":"orders"}' -H "X-Agent-Token: $TOKEN")
CAP3=$(json_get "${result#*|}" "cap_token")
verify_body=$(printf '{"cap_token":"%s","expected_tool":"db_query","expected_resource":"users"}' "$CAP3")
result=$(call POST /v1/shield/cap/verify "$verify_body")
body="${result#*|}"
valid=$(json_get "$body" "valid" 2>/dev/null || echo "?")
err=$(json_get "$body" "error" 2>/dev/null || echo "")
if [[ "$valid" == "False" && "$err" == *"resource mismatch"* ]]; then
  pass "wrong resource → valid=False, error mentions resource mismatch"
else
  fail "resource mismatch not detected" "valid=$valid error=$err"
fi

# ─── Step 10: cap expiry ────────────────────────────────────────────────
step "10. Cap expires (1s TTL, sleep past clock-skew window)"
result=$(call POST /v1/shield/cap/mint '{"tool":"t","resource":"r","ttl_seconds":1}' -H "X-Agent-Token: $TOKEN")
CAP4=$(json_get "${result#*|}" "cap_token")
# verify_cap allows up to 2s of clock skew (exp < now - 2). Sleep 5s to be
# strictly past the skew window regardless of sub-second timing jitter.
sleep 5
verify_body=$(printf '{"cap_token":"%s","expected_tool":"t"}' "$CAP4")
result=$(call POST /v1/shield/cap/verify "$verify_body")
body="${result#*|}"
valid=$(json_get "$body" "valid" 2>/dev/null || echo "?")
err=$(json_get "$body" "error" 2>/dev/null || echo "")
if [[ "$valid" == "False" && "$err" == *expired* ]]; then
  pass "expired cap → valid=False, error mentions expired"
else
  fail "expired cap not detected" "valid=$valid error=$err"
fi

# ─── Step 11: cap TTL ceiling ───────────────────────────────────────────
step "11. Cap TTL ceiling (60s)"
result=$(call POST /v1/shield/cap/mint '{"tool":"t","resource":"r","ttl_seconds":90}' -H "X-Agent-Token: $TOKEN")
status="${result%%|*}"
[[ "$status" == "422" || "$status" == "400" ]] && pass "ttl=90 rejected ($status)" || fail "ttl=90 not rejected" "$status"

# ─── Step 12: revocation propagation ────────────────────────────────────
step "12. Revoke instance and observe propagation"
result=$(call POST /v1/shield/auth/revoke '{"agent_instance_id":"inst-1"}' -H "X-Admin-Key: $SHIELD_ADMIN_KEY")
[[ "${result%%|*}" == "200" ]] && pass "revoke → 200" || fail "revoke did not 200" "${result%%|*}"
# Reuse the original TOKEN — should now be rejected at the middleware
result=$(call POST /v1/shield/cap/mint '{"tool":"t","resource":"r"}' -H "X-Agent-Token: $TOKEN")
[[ "${result%%|*}" == "401" ]] && pass "revoked instance → cap mint 401" || fail "revoked instance was not rejected" "${result%%|*}"

# ─── Step 13: revoke is admin-gated ─────────────────────────────────────
step "13. Revoke requires admin"
result=$(call POST /v1/shield/auth/revoke '{"agent_instance_id":"inst-x"}')
[[ "${result%%|*}" == "403" ]] && pass "no key → 403" || fail "no key did not 403" "${result%%|*}"

stop_server

# ══════════════════════════════════════════════════════════════════════════
# PHASE B — build allowlist (needs server restart with new env)
# ══════════════════════════════════════════════════════════════════════════

step "14. Build allowlist blocks unknown build_hash"
start_server "SHIELD_AGENT_ALLOWED_BUILDS=sha256:approved-1,sha256:approved-2"
# Issue a token with a NOT-allowlisted build
bad_build='{"user_sub":"a","agent_id":"a","agent_instance_id":"a","tenant_id":"a","build_hash":"sha256:UNKNOWN","model_version":"m","session_id":"s","ttl_seconds":300}'
result=$(call POST /v1/shield/auth/agent-token "$bad_build" -H "X-Admin-Key: $SHIELD_ADMIN_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  pass "issuance trusts caller (200, by design)"
  BAD_TOKEN=$(json_get "$body" "agent_token")
  result=$(call POST /v1/shield/cap/mint '{"tool":"t","resource":"r"}' -H "X-Agent-Token: $BAD_TOKEN")
  if [[ "${result%%|*}" == "401" ]]; then
    pass "unknown build → cap mint 401 (rejected at middleware)"
  else
    fail "unknown build was not rejected" "${result%%|*}"
  fi
else
  fail "issuance failed unexpectedly" "$status $body"
fi
stop_server

# ══════════════════════════════════════════════════════════════════════════
# PHASE C — signer backend dispatcher
# ══════════════════════════════════════════════════════════════════════════

step "15a. Signer backend 'vault' routes to stub and fails loudly"
start_server "SHIELD_SIGNER_BACKEND_AGENT=vault"
result=$(call POST /v1/shield/auth/agent-token "$TOKEN_BODY" -H "X-Admin-Key: $SHIELD_ADMIN_KEY")
status="${result%%|*}"; body="${result#*|}"
detail=$(json_get "$body" "detail" 2>/dev/null || echo "")
if [[ "$status" == "400" && "$detail" == *VAULT* ]]; then
  pass "vault backend without config → 400 with VAULT_* hint"
else
  fail "vault backend dispatch broken" "status=$status detail=$detail"
fi
stop_server

step "15b. Unknown signer backend rejected"
start_server "SHIELD_SIGNER_BACKEND_AGENT=ozymandias"
result=$(call POST /v1/shield/auth/agent-token "$TOKEN_BODY" -H "X-Admin-Key: $SHIELD_ADMIN_KEY")
status="${result%%|*}"; body="${result#*|}"
detail=$(json_get "$body" "detail" 2>/dev/null || echo "")
if [[ "$status" == "400" && "$detail" == *"unknown signer backend"* ]]; then
  pass "unknown backend → 400 with clear error"
else
  fail "unknown backend dispatch broken" "status=$status detail=$detail"
fi
stop_server

# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════

printf '\n%s════════════════════════════════════════════%s\n' "$C_BOLD" "$C_RESET"
printf '%sSUMMARY%s  %sPASS%s=%d  %sFAIL%s=%d\n' \
  "$C_BOLD" "$C_RESET" "$C_GREEN" "$C_RESET" "$PASS_COUNT" "$C_RED" "$C_RESET" "$FAIL_COUNT"

if (( FAIL_COUNT > 0 )); then
  printf '\n%sFailed steps:%s\n' "$C_YELLOW" "$C_RESET"
  for s in "${FAILED_STEPS[@]}"; do
    printf '  • %s\n' "$s"
  done
  printf '\n%sRe-run with KEEP_LOG=1 to see the server log.%s\n' "$C_DIM" "$C_RESET"
  exit 1
fi

printf '\n%sAll smoke checks passed.%s\n' "$C_GREEN" "$C_RESET"
exit 0
