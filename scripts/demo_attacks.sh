#!/usr/bin/env bash
#
# Adversarial demo. Walks through every way an unauthorized agent could
# try to make a tool call and shows each attempt being blocked.
#
# Designed for showing to customers / execs / security review. Every
# "PASS" means an attack was correctly REJECTED. Every "FAIL" means
# something concerning got through.
#
# Usage:
#   SHIELD_URL=http://localhost:8080 \
#   TENANT_KEY=bank-co-key \
#   ./scripts/demo_attacks.sh

set -u

SHIELD_URL="${SHIELD_URL:-http://localhost:8080}"
TENANT_KEY="${TENANT_KEY:-}"
ADMIN_KEY="${SHIELD_ADMIN_KEY:-}"

if [[ -z "$TENANT_KEY" ]]; then
  echo "TENANT_KEY env var required" >&2
  exit 2
fi

C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_YEL=$'\033[33m'; C_BLUE=$'\033[34m'
ATTACKS_BLOCKED=0; ATTACKS_LEAKED=0; FAILED_ATTACKS=()

attack() {
  printf '\n%s%s%s %s%s%s\n' \
    "$C_BOLD" "▶ ATTACK:" "$C_RESET" \
    "$C_YEL" "$1" "$C_RESET"
  printf '%s   %s%s\n' "$C_DIM" "$2" "$C_RESET"
}

blocked() {
  ATTACKS_BLOCKED=$((ATTACKS_BLOCKED+1))
  printf '   %s✓ BLOCKED%s — %s\n' "$C_GREEN" "$C_RESET" "$1"
}

leaked() {
  ATTACKS_LEAKED=$((ATTACKS_LEAKED+1))
  FAILED_ATTACKS+=("$1")
  printf '   %s✗ LEAKED %s — %s\n' "$C_RED" "$C_RESET" "$1"
  [[ -n "${2:-}" ]] && printf '             %s%s%s\n' "$C_DIM" "$2" "$C_RESET"
}

info() { printf '   %s· %s%s\n' "$C_BLUE" "$*" "$C_RESET"; }

# json_get '<json>' '<dotted.path>'
jq_get() {
  python3 - "$1" "$2" <<'PY' 2>/dev/null
import json, sys
try:
    obj = json.loads(sys.argv[1])
    for p in sys.argv[2].split('.'):
        obj = obj[p] if not isinstance(obj, list) else obj[int(p)]
    sys.stdout.write(str(obj))
except Exception:
    sys.exit(1)
PY
}

call() {
  local method="$1" path="$2" body="${3:-}"
  shift 3 || true
  local args=(-s -o /tmp/_atk.$$ -w '%{http_code}' -X "$method" "$SHIELD_URL$path")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' -d "$body")
  args+=("$@")
  local st; st=$(curl "${args[@]}")
  local b; b=$(cat /tmp/_atk.$$ 2>/dev/null || echo '')
  rm -f /tmp/_atk.$$
  printf '%s|%s' "$st" "$b"
}

# ─── Setup: get a legitimate token so we have a baseline ────────────────

cat <<HEADER
${C_BOLD}═══════════════════════════════════════════════════════════════
Adversarial demo against $SHIELD_URL
Tenant key: $TENANT_KEY
═══════════════════════════════════════════════════════════════${C_RESET}

This script tries every way an unauthorized agent could try to call a
tool. Each "BLOCKED" is the system correctly rejecting an attack.
Each "LEAKED" is a vulnerability. Run with portal open in a browser —
every blocked attack also lands in the Recent Decisions table.
HEADER

printf '\n%sSetting up legitimate baseline...%s\n' "$C_DIM" "$C_RESET"
TOKEN_BODY=$(cat <<JSON
{"user_sub":"alice@bank-co.com","agent_id":"billing-bot","agent_instance_id":"legit-pod-$$","build_hash":"b","model_version":"m","session_id":"s","ttl_seconds":600}
JSON
)
result=$(call POST /v1/tenant/me/agent-auth/agent-token "$TOKEN_BODY" -H "X-API-Key: $TENANT_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" != "200" ]]; then
  echo "${C_RED}Could not get a baseline token (status=$status, body=$body).${C_RESET}"
  echo "Is your tenant '$TENANT_KEY' registered? Container reachable at $SHIELD_URL?"
  exit 2
fi
LEGIT_TOKEN=$(jq_get "$body" "agent_token")
LEGIT_CAP=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"user/u-42/inbox"}' -H "X-Agent-Token: $LEGIT_TOKEN" | sed 's/^[0-9]*|//' | python3 -c "import sys,json;print(json.load(sys.stdin)['cap_token'])")
info "baseline OK: token + cap minted"


# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 1 — No agent token at all
# ═══════════════════════════════════════════════════════════════════════

attack "No agent token at all" \
  "Attacker calls /cap/mint with no X-Agent-Token header. Should be 401."
result=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"user/x"}')
status="${result%%|*}"
if [[ "$status" == "401" ]]; then
  blocked "401 returned — middleware refuses unauthenticated requests"
else
  leaked "expected 401, got $status" "${result#*|}"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 2 — Random garbage as token
# ═══════════════════════════════════════════════════════════════════════

attack "Garbage in X-Agent-Token" \
  "Attacker submits 'not-a-real-token'. Should be 401 with 'malformed token'."
result=$(call POST /v1/shield/cap/mint \
  '{"tool":"send_email","resource":"x"}' \
  -H "X-Agent-Token: not-a-real-token")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "401" && "$body" == *malformed* ]]; then
  blocked "401 + malformed — token decoder refused to parse"
elif [[ "$status" == "401" ]]; then
  blocked "401 — rejected (reason: $(jq_get "$body" "detail"))"
else
  leaked "expected 401, got $status" "$body"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 3 — Tampered signature
# ═══════════════════════════════════════════════════════════════════════

attack "Tampered signature on a real token" \
  "Take a legit token, flip a character in the signature half. Should be 401 invalid signature."
PAYLOAD="${LEGIT_TOKEN%.*}"
SIG="${LEGIT_TOKEN##*.}"
MID=$((${#SIG}/2))
TAMPERED="${PAYLOAD}.${SIG:0:$MID}X${SIG:$((MID+1))}"
result=$(call POST /v1/shield/cap/mint \
  '{"tool":"send_email","resource":"x"}' \
  -H "X-Agent-Token: $TAMPERED")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "401" && "$body" == *signature* ]]; then
  blocked "401 + invalid signature — Ed25519 caught the tamper"
elif [[ "$status" == "401" ]]; then
  blocked "401 — Ed25519 rejected"
else
  leaked "expected 401, got $status" "$body"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 4 — Forged token (custom payload, signed with attacker's own key)
# ═══════════════════════════════════════════════════════════════════════

attack "Forged token: attacker tries to sign their own claims" \
  "Attacker generates their own Ed25519 keypair, signs valid-looking claims. Server doesn't know that key. Must reject."
FORGED=$(python3 <<'PY'
import base64, json, time, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sk = Ed25519PrivateKey.generate()
claims = {
  "iss": "shield-mac-dev", "aud": "shield-agent-tokens",
  "user_sub": "mallory", "agent_id": "billing-bot",
  "agent_instance_id": "forged", "tenant_id": "bank-co",
  "build_hash": "b", "model_version": "m", "session_id": "s",
  "iat": int(time.time()), "exp": int(time.time())+600,
  "jti": uuid.uuid4().hex, "kid": "env",
}
payload = json.dumps(claims, separators=(",",":"), sort_keys=True).encode()
sig = sk.sign(payload)
b64 = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
print(f"{b64(payload)}.{b64(sig)}")
PY
)
result=$(call POST /v1/shield/cap/mint \
  '{"tool":"send_email","resource":"x"}' \
  -H "X-Agent-Token: $FORGED")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "401" ]]; then
  blocked "401 — signature key doesn't match server's, forgery caught"
else
  leaked "expected 401, got $status" "$body"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 5 — Cross-tenant: try to mint as someone else's tenant
# ═══════════════════════════════════════════════════════════════════════

attack "Tenant-ID spoofing in the request body" \
  "Attacker puts tenant_id='victim-tenant' in the mint body. Server should ignore it and use the API key's tenant."
SPOOF_BODY='{"user_sub":"mallory","agent_id":"x","agent_instance_id":"i","tenant_id":"victim-tenant","build_hash":"b","model_version":"m","session_id":"s"}'
result=$(call POST /v1/tenant/me/agent-auth/agent-token "$SPOOF_BODY" -H "X-API-Key: $TENANT_KEY")
status="${result%%|*}"; body="${result#*|}"
if [[ "$status" == "200" ]]; then
  SPOOFED_TOKEN=$(jq_get "$body" "agent_token")
  ACTUAL=$(python3 -c "
import base64, json
p = '$SPOOFED_TOKEN'.split('.', 1)[0]
pad = '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p + pad).decode())['tenant_id'])
")
  if [[ "$ACTUAL" != "victim-tenant" ]]; then
    blocked "tenant_id resolved to '$ACTUAL' (from API key), NOT 'victim-tenant'"
  else
    leaked "tenant_id spoofing SUCCEEDED" "got tenant_id=$ACTUAL"
  fi
else
  blocked "request rejected at status $status"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 6 — Cap replay
# ═══════════════════════════════════════════════════════════════════════

attack "Cap replay: use the same cap twice" \
  "Attacker intercepts a cap, replays it. Second use should be rejected."
# Mint a fresh cap so the test is hermetic
REPLAY_CAP=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"user/x"}' -H "X-Agent-Token: $LEGIT_TOKEN" | sed 's/^[0-9]*|//' | python3 -c "import sys,json;print(json.load(sys.stdin)['cap_token'])")
# First verify — should succeed
r1=$(call POST /v1/shield/cap/verify "{\"cap_token\":\"$REPLAY_CAP\",\"expected_tool\":\"send_email\"}")
b1="${r1#*|}"
ok1=$(jq_get "$b1" "valid")
# Second verify — replay
r2=$(call POST /v1/shield/cap/verify "{\"cap_token\":\"$REPLAY_CAP\",\"expected_tool\":\"send_email\"}")
b2="${r2#*|}"
ok2=$(jq_get "$b2" "valid")
err2=$(jq_get "$b2" "error")
if [[ "$ok1" == "True" && "$ok2" == "False" && "$err2" == *replay* ]]; then
  blocked "first use ok, second use → 'cap replay detected'"
else
  leaked "replay not detected" "first=$ok1 second=$ok2 err=$err2"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 7 — Wrong tool: cap minted for X, used for Y
# ═══════════════════════════════════════════════════════════════════════

attack "Cap used for the WRONG tool" \
  "Cap was minted for 'send_email'. Attacker tries to use it for 'db_query'. Must reject."
NEW_CAP=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"user/y"}' -H "X-Agent-Token: $LEGIT_TOKEN" | sed 's/^[0-9]*|//' | python3 -c "import sys,json;print(json.load(sys.stdin)['cap_token'])")
result=$(call POST /v1/shield/cap/verify "{\"cap_token\":\"$NEW_CAP\",\"expected_tool\":\"db_query\"}")
body="${result#*|}"
valid=$(jq_get "$body" "valid"); err=$(jq_get "$body" "error")
if [[ "$valid" == "False" && "$err" == *"tool mismatch"* ]]; then
  blocked "valid=False, error='$err'"
else
  leaked "wrong tool wasn't caught" "valid=$valid err=$err"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 8 — Wrong resource: cap for user A used for user B
# ═══════════════════════════════════════════════════════════════════════

attack "Cap used on the WRONG resource" \
  "Cap was minted for 'user/u-42/inbox'. Attacker tries to use it for 'user/admin/inbox'. Must reject."
RES_CAP=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"user/u-42/inbox"}' -H "X-Agent-Token: $LEGIT_TOKEN" | sed 's/^[0-9]*|//' | python3 -c "import sys,json;print(json.load(sys.stdin)['cap_token'])")
result=$(call POST /v1/shield/cap/verify "{\"cap_token\":\"$RES_CAP\",\"expected_tool\":\"send_email\",\"expected_resource\":\"user/admin/inbox\"}")
body="${result#*|}"
valid=$(jq_get "$body" "valid"); err=$(jq_get "$body" "error")
if [[ "$valid" == "False" && "$err" == *"resource mismatch"* ]]; then
  blocked "valid=False, error='$err'"
else
  leaked "resource binding leaked" "valid=$valid err=$err"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 9 — Expired cap
# ═══════════════════════════════════════════════════════════════════════

attack "Expired cap" \
  "Mint a cap with the minimum TTL (1s), wait past the clock-skew window (5s), try to use it. Must reject."
SHORT_CAP=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"x","ttl_seconds":1}' -H "X-Agent-Token: $LEGIT_TOKEN" | sed 's/^[0-9]*|//' | python3 -c "import sys,json;print(json.load(sys.stdin)['cap_token'])")
info "sleeping 5s past TTL + clock-skew window..."
sleep 5
result=$(call POST /v1/shield/cap/verify "{\"cap_token\":\"$SHORT_CAP\",\"expected_tool\":\"send_email\"}")
body="${result#*|}"
valid=$(jq_get "$body" "valid"); err=$(jq_get "$body" "error")
if [[ "$valid" == "False" && "$err" == *expired* ]]; then
  blocked "valid=False, error='$err'"
else
  leaked "expired cap accepted" "valid=$valid err=$err"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 10 — Revoked instance kills all its tokens (requires admin)
# ═══════════════════════════════════════════════════════════════════════

if [[ -n "$ADMIN_KEY" ]]; then
  attack "Revoke the agent instance and reuse its token" \
    "Admin revokes 'legit-pod-$$'. Any token from it must instantly fail."
  call POST /v1/shield/auth/revoke "{\"agent_instance_id\":\"legit-pod-$$\"}" -H "X-Admin-Key: $ADMIN_KEY" >/dev/null
  result=$(call POST /v1/shield/cap/mint '{"tool":"send_email","resource":"x"}' -H "X-Agent-Token: $LEGIT_TOKEN")
  status="${result%%|*}"; body="${result#*|}"
  if [[ "$status" == "401" ]]; then
    blocked "401 — revoked instance can no longer mint caps"
  else
    leaked "revoked token still works" "status=$status"
  fi
else
  printf '\n%s▶ ATTACK 10 — Revocation (skipped, no SHIELD_ADMIN_KEY)%s\n' "$C_DIM" "$C_RESET"
  info "to demo this, run with SHIELD_ADMIN_KEY=... in the env"
fi

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK 11 — Unknown tenant API key
# ═══════════════════════════════════════════════════════════════════════

attack "Unknown tenant API key tries to mint a token" \
  "Attacker has a bogus tenant key 'fake-key-i-found'. Must be rejected at issuance."
result=$(call POST /v1/tenant/me/agent-auth/agent-token "$TOKEN_BODY" -H "X-API-Key: fake-key-i-found")
status="${result%%|*}"
if [[ "$status" == "401" ]]; then
  blocked "401 — tenant key not recognized, no token issued"
else
  leaked "unknown key got past auth" "status=$status"
fi

# ═══════════════════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════════════════

TOTAL=$((ATTACKS_BLOCKED + ATTACKS_LEAKED))
printf '\n%s═══════════════════════════════════════════════════════════════%s\n' "$C_BOLD" "$C_RESET"
printf '%sATTACK SURFACE SUMMARY%s\n' "$C_BOLD" "$C_RESET"
printf '  %sBlocked: %d/%d%s\n' "$C_GREEN" "$ATTACKS_BLOCKED" "$TOTAL" "$C_RESET"
printf '  %sLeaked:  %d/%d%s\n' "$C_RED" "$ATTACKS_LEAKED" "$TOTAL" "$C_RESET"
printf '%s═══════════════════════════════════════════════════════════════%s\n' "$C_BOLD" "$C_RESET"

if (( ATTACKS_LEAKED > 0 )); then
  printf '\n%sLeaked attacks (need investigation):%s\n' "$C_RED" "$C_RESET"
  for a in "${FAILED_ATTACKS[@]}"; do printf '  • %s\n' "$a"; done
  exit 1
fi

cat <<DONE

${C_GREEN}All attacks were correctly blocked.${C_RESET}

${C_DIM}Now open the portal — every blocked attack also landed in the
Recent Decisions table with the actual rejection reason. That's how
you demo this to a security reviewer or a customer:
  1. Show this script's output (proof of blocking)
  2. Show the portal's Recent Decisions (proof of audit trail)${C_RESET}
DONE
exit 0
