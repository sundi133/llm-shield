#!/usr/bin/env bash
# =============================================================================
#  Customer Integration: Agent Auth (AuthN) & Authorization (AuthZ)
#  Step-by-step with SUCCESS and FAILURE paths
#
#  Prerequisites:
#    - Shield running at $SHIELD_URL (default: http://localhost:80)
#    - Tenant API key in $TENANT_KEY
#    - Admin key in $ADMIN_KEY (optional, for admin endpoint)
# =============================================================================

set -euo pipefail

SHIELD_URL="${SHIELD_URL:-http://localhost:80}"
TENANT_KEY="${TENANT_KEY:-sk-test-demo}"
ADMIN_KEY="${ADMIN_KEY:-test-admin-key}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

step() { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  STEP $1: $2${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"; }
success() { echo -e "${GREEN}  ✓ SUCCESS: $1${NC}"; }
failure() { echo -e "${RED}  ✗ FAILURE: $1${NC}"; }
info() { echo -e "${YELLOW}  → $1${NC}"; }

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 1: AGENT TOKEN ISSUANCE (AuthN — proving WHO the agent is)
# ─────────────────────────────────────────────────────────────────────────────

step "1a" "Get Agent Token (Customer Self-Service — SUCCESS)"
cat <<'EXPLAIN'
  The customer's agent calls POST /v1/tenant/me/agent-auth/agent-token
  with their tenant API key. This proves the agent belongs to the tenant.

  Required headers:
    X-API-Key: <tenant-api-key>

  The tenant_id is LOCKED to the key — cannot be overridden.
EXPLAIN

info "Request:"
echo '  curl -s -X POST '"$SHIELD_URL"'/v1/tenant/me/agent-auth/agent-token \'
echo '    -H "X-API-Key: '"$TENANT_KEY"'" \'
echo '    -H "Content-Type: application/json" \'
echo '    -d '"'"'{'
echo '      "user_sub": "user-42",              # OIDC sub of the human'
echo '      "agent_id": "billing-bot",           # logical agent name'
echo '      "agent_instance_id": "inst-abc-001", # unique per process'
echo '      "build_hash": "sha256:a1b2c3d4",    # exact code build'
echo '      "model_version": "claude-opus-4",    # LLM version'
echo '      "session_id": "sess-789",            # conversation ID'
echo '      "ttl_seconds": 600                   # 10 minutes (max: 900)'
echo '    }'"'"

AGENT_TOKEN_RESP=$(curl -s -X POST "$SHIELD_URL/v1/tenant/me/agent-auth/agent-token" \
  -H "X-API-Key: $TENANT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_sub": "user-42",
    "agent_id": "billing-bot",
    "agent_instance_id": "inst-abc-001",
    "build_hash": "sha256:a1b2c3d4",
    "model_version": "claude-opus-4",
    "session_id": "sess-789",
    "ttl_seconds": 600
  }' 2>/dev/null) || true

echo ""
info "Response (200 OK):"
echo "$AGENT_TOKEN_RESP" | python3 -m json.tool 2>/dev/null || echo "$AGENT_TOKEN_RESP"

AGENT_TOKEN=$(echo "$AGENT_TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_token'])" 2>/dev/null) || AGENT_TOKEN=""

if [ -n "$AGENT_TOKEN" ]; then
  success "Agent token issued — standard JWT (EdDSA/Ed25519)"
  echo ""
  info "Token format: header.payload.signature (3 segments)"
  info "Segments: $(echo "$AGENT_TOKEN" | tr '.' '\n' | wc -l | tr -d ' ')"
  echo ""
  info "Decoded header:"
  echo "$AGENT_TOKEN" | cut -d. -f1 | python3 -c "import sys,base64,json; d=sys.stdin.read().strip(); d+='='*(-len(d)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(d)),indent=2))" 2>/dev/null || true
  echo ""
  info "Decoded claims (unverified):"
  echo "$AGENT_TOKEN" | cut -d. -f2 | python3 -c "import sys,base64,json; d=sys.stdin.read().strip(); d+='='*(-len(d)%4); c=json.loads(base64.urlsafe_b64decode(d)); print(json.dumps({k:v for k,v in c.items() if k != 'kid'},indent=2))" 2>/dev/null || true
else
  failure "Could not extract agent token"
fi

# ─────────────────────────────────────────────────────────────────────────────

step "1b" "Get Agent Token — FAILURE: No API Key"
cat <<'EXPLAIN'
  Without an API key, the AuthMiddleware rejects the request.
  The tenant_id cannot be resolved.
EXPLAIN

info "Request: (no X-API-Key header)"
FAIL_RESP=$(curl -s -X POST "$SHIELD_URL/v1/tenant/me/agent-auth/agent-token" \
  -H "Content-Type: application/json" \
  -d '{"user_sub":"u","agent_id":"a","agent_instance_id":"i","build_hash":"b","model_version":"m","session_id":"s"}' \
  2>/dev/null) || true

info "Response (401 or 403):"
echo "$FAIL_RESP" | python3 -m json.tool 2>/dev/null || echo "$FAIL_RESP"
failure "Rejected — no tenant identity"

# ─────────────────────────────────────────────────────────────────────────────

step "1c" "Get Agent Token — FAILURE: Missing Required Fields"
cat <<'EXPLAIN'
  All claims are mandatory. Missing any one → 400 or 422.
EXPLAIN

FAIL_RESP2=$(curl -s -X POST "$SHIELD_URL/v1/tenant/me/agent-auth/agent-token" \
  -H "X-API-Key: $TENANT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_sub":"user-42","agent_id":"billing-bot"}' \
  2>/dev/null) || true

info "Response (422 Validation Error):"
echo "$FAIL_RESP2" | python3 -m json.tool 2>/dev/null || echo "$FAIL_RESP2"
failure "Rejected — missing required fields (agent_instance_id, build_hash, etc.)"

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 2: CAPABILITY MINTING (AuthZ — proving WHAT the agent may do)
# ─────────────────────────────────────────────────────────────────────────────

step "2a" "Mint Capability Token — SUCCESS"
cat <<'EXPLAIN'
  BEFORE calling any tool, the agent requests a capability token.
  The cap is minted BEFORE the LLM sees user input — this prevents
  prompt injection from tricking the agent into unauthorized actions.

  Required headers:
    X-Agent-Token: <jwt-from-step-1>
    X-API-Key: <tenant-api-key>

  The request specifies the EXACT tool + resource + clearance level.
EXPLAIN

if [ -z "$AGENT_TOKEN" ]; then
  info "Skipping (no agent token from Step 1)"
else
  info "Request:"
  echo '  curl -s -X POST '"$SHIELD_URL"'/v1/shield/cap/mint \'
  echo '    -H "X-Agent-Token: <jwt>" \'
  echo '    -H "X-API-Key: '"$TENANT_KEY"'" \'
  echo '    -d '"'"'{'
  echo '      "tool": "send_email",             # exact tool name'
  echo '      "resource": "user/42/inbox",       # exact target'
  echo '      "clearance_max": "internal",       # data ceiling'
  echo '      "scope_constraints": ["to:billing@co.com"],'
  echo '      "ttl_seconds": 30                  # max: 60 seconds'
  echo '    }'"'"

  CAP_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/mint" \
    -H "X-Agent-Token: $AGENT_TOKEN" \
    -H "X-API-Key: $TENANT_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "tool": "send_email",
      "resource": "user/42/inbox",
      "clearance_max": "internal",
      "scope_constraints": ["to:billing@co.com"],
      "ttl_seconds": 30
    }' 2>/dev/null) || true

  echo ""
  info "Response (200 OK):"
  echo "$CAP_RESP" | python3 -m json.tool 2>/dev/null || echo "$CAP_RESP"

  CAP_TOKEN=$(echo "$CAP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['cap_token'])" 2>/dev/null) || CAP_TOKEN=""

  if [ -n "$CAP_TOKEN" ]; then
    success "Capability token minted"
    info "Cap is single-use (nonce), tool-bound, 30s TTL"
    echo ""
    info "Decoded cap claims:"
    echo "$CAP_TOKEN" | cut -d. -f2 | python3 -c "
import sys,base64,json
d=sys.stdin.read().strip()
d+='='*(-len(d)%4)
c=json.loads(base64.urlsafe_b64decode(d))
# Show key fields
for k in ['tool','resource','scope','clearance_max','nonce','exp','cap_id','aud']:
    if k in c: print(f'    {k}: {c[k]}')
" 2>/dev/null || true
  else
    failure "Could not mint capability token"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────

step "2b" "Mint Capability — FAILURE: No Agent Token"
cat <<'EXPLAIN'
  Without X-Agent-Token, the cap endpoint cannot identify WHO is asking.
  → 401 Unauthorized
EXPLAIN

FAIL_CAP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/mint" \
  -H "X-API-Key: $TENANT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"send_email","resource":"user/42/inbox"}' \
  2>/dev/null) || true

info "Response (401):"
echo "$FAIL_CAP" | python3 -m json.tool 2>/dev/null || echo "$FAIL_CAP"
failure "Rejected — no X-Agent-Token"

# ─────────────────────────────────────────────────────────────────────────────

step "2c" "Mint Capability — FAILURE: RBAC Denied"
cat <<'EXPLAIN'
  If RBAC is configured and the agent's role doesn't allow the tool:
  → 403 Forbidden

  Default response hides reasons (M3 — prevents enumeration):
    {"error": "authz_denied", "request_id": "a1b2c3d4e5f6"}

  With SHIELD_VERBOSE_REASONS=1:
    {"error": "authz_denied", "reasons": ["role 'reader' not permitted to use tool 'delete_database'"]}
EXPLAIN

if [ -n "$AGENT_TOKEN" ]; then
  info "(This will succeed if RBAC is not configured — denied if billing-bot lacks delete_database)"
  RBAC_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/mint" \
    -H "X-Agent-Token: $AGENT_TOKEN" \
    -H "X-API-Key: $TENANT_KEY" \
    -H "Content-Type: application/json" \
    -d '{"tool":"delete_database","resource":"prod/all-tables","clearance_max":"restricted"}' \
    2>/dev/null) || true
  info "Response:"
  echo "$RBAC_RESP" | python3 -m json.tool 2>/dev/null || echo "$RBAC_RESP"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 3: CAPABILITY VERIFICATION (Tool-side — proving the cap is valid)
# ─────────────────────────────────────────────────────────────────────────────

step "3a" "Verify Capability — SUCCESS (Tool/MCP Server Side)"
cat <<'EXPLAIN'
  The tool/MCP server receives the cap token from the agent and verifies it
  BEFORE executing the action.

  NOTE: This endpoint is deliberately NOT gated by X-Agent-Token.
  The cap itself is the bearer credential. No API key needed either.

  Checks performed:
    1. EdDSA signature verification
    2. Token not expired (2s clock skew)
    3. Tool name matches expected_tool
    4. Resource matches expected_resource (if provided)
    5. Cap not revoked
    6. Nonce burned (one-shot — first use only)
EXPLAIN

if [ -z "$CAP_TOKEN" ]; then
  info "Skipping (no cap token from Step 2)"
else
  info "Request:"
  echo '  curl -s -X POST '"$SHIELD_URL"'/v1/shield/cap/verify \'
  echo '    -H "Content-Type: application/json" \'
  echo '    -d '"'"'{'
  echo '      "cap_token": "<jwt>",       # cap from step 2'
  echo '      "expected_tool": "send_email",  # must match'
  echo '      "expected_resource": "user/42/inbox"  # optional strict check'
  echo '    }'"'"

  VERIFY_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/verify" \
    -H "Content-Type: application/json" \
    -d "{
      \"cap_token\": \"$CAP_TOKEN\",
      \"expected_tool\": \"send_email\",
      \"expected_resource\": \"user/42/inbox\"
    }" 2>/dev/null) || true

  echo ""
  info "Response (200, valid=true):"
  echo "$VERIFY_RESP" | python3 -m json.tool 2>/dev/null || echo "$VERIFY_RESP"

  VALID=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('valid',False))" 2>/dev/null) || VALID=""
  if [ "$VALID" = "True" ]; then
    success "Cap verified — tool may proceed with send_email on user/42/inbox"
  else
    failure "Cap verification failed"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────

step "3b" "Verify Capability — FAILURE: Replay (Nonce Already Used)"
cat <<'EXPLAIN'
  The same cap token CANNOT be used twice. The nonce was burned in step 3a.
  This prevents replay attacks even within the 30-second TTL window.
EXPLAIN

if [ -z "$CAP_TOKEN" ]; then
  info "Skipping (no cap token)"
else
  REPLAY_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/verify" \
    -H "Content-Type: application/json" \
    -d "{
      \"cap_token\": \"$CAP_TOKEN\",
      \"expected_tool\": \"send_email\"
    }" 2>/dev/null) || true

  info "Response (200, valid=false):"
  echo "$REPLAY_RESP" | python3 -m json.tool 2>/dev/null || echo "$REPLAY_RESP"
  failure "Cap replay detected — nonce already used"
fi

# ─────────────────────────────────────────────────────────────────────────────

step "3c" "Verify Capability — FAILURE: Wrong Tool"
cat <<'EXPLAIN'
  Even if the cap is valid, if the tool name doesn't match → denied.
  A cap for "send_email" cannot be used to authorize "delete_user".
EXPLAIN

if [ -n "$AGENT_TOKEN" ]; then
  # Mint a fresh cap
  FRESH_CAP_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/mint" \
    -H "X-Agent-Token: $AGENT_TOKEN" \
    -H "X-API-Key: $TENANT_KEY" \
    -H "Content-Type: application/json" \
    -d '{"tool":"send_email","resource":"user/42/inbox","ttl_seconds":30}' \
    2>/dev/null) || true
  FRESH_CAP=$(echo "$FRESH_CAP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['cap_token'])" 2>/dev/null) || FRESH_CAP=""

  if [ -n "$FRESH_CAP" ]; then
    WRONG_TOOL_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/verify" \
      -H "Content-Type: application/json" \
      -d "{
        \"cap_token\": \"$FRESH_CAP\",
        \"expected_tool\": \"delete_user\"
      }" 2>/dev/null) || true

    info "Response (200, valid=false):"
    echo "$WRONG_TOOL_RESP" | python3 -m json.tool 2>/dev/null || echo "$WRONG_TOOL_RESP"
    failure "Tool mismatch: cap was for 'send_email', tried 'delete_user'"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────

step "3d" "Verify Capability — FAILURE: Tampered Token"
cat <<'EXPLAIN'
  If any byte of the JWT is modified, the Ed25519 signature check fails.
  Cannot be forged — tool servers only have the public key.
EXPLAIN

if [ -n "$AGENT_TOKEN" ]; then
  FRESH_CAP2_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/mint" \
    -H "X-Agent-Token: $AGENT_TOKEN" \
    -H "X-API-Key: $TENANT_KEY" \
    -H "Content-Type: application/json" \
    -d '{"tool":"send_email","resource":"user/42/inbox","ttl_seconds":30}' \
    2>/dev/null) || true
  FRESH_CAP2=$(echo "$FRESH_CAP2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['cap_token'])" 2>/dev/null) || FRESH_CAP2=""

  if [ -n "$FRESH_CAP2" ]; then
    # Tamper with the payload (flip a char)
    TAMPERED=$(echo "$FRESH_CAP2" | python3 -c "
import sys
t = sys.stdin.read().strip()
parts = t.split('.')
p = list(parts[1])
mid = len(p) // 2
p[mid] = 'X' if p[mid] != 'X' else 'Y'
parts[1] = ''.join(p)
print('.'.join(parts))
" 2>/dev/null) || TAMPERED=""

    if [ -n "$TAMPERED" ]; then
      TAMPER_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/verify" \
        -H "Content-Type: application/json" \
        -d "{
          \"cap_token\": \"$TAMPERED\",
          \"expected_tool\": \"send_email\"
        }" 2>/dev/null) || true

      info "Response (200, valid=false):"
      echo "$TAMPER_RESP" | python3 -m json.tool 2>/dev/null || echo "$TAMPER_RESP"
      failure "Invalid signature — token was tampered with"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 4: REVOCATION (Emergency kill switches)
# ─────────────────────────────────────────────────────────────────────────────

step "4" "Revoke an Agent Instance"
cat <<'EXPLAIN'
  Three independent revocation axes:
    1. agent_instance_id → kill one running process
    2. user_sub → kill ALL tokens for a compromised user
    3. jti → kill one specific token

  Any token verified after revocation will be rejected.
EXPLAIN

info "Request: revoke inst-abc-001"
REVOKE_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/auth/revoke" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_instance_id":"inst-abc-001","ttl_seconds":3600}' \
  2>/dev/null) || true

info "Response:"
echo "$REVOKE_RESP" | python3 -m json.tool 2>/dev/null || echo "$REVOKE_RESP"

# Now try to use the revoked token
if [ -n "$AGENT_TOKEN" ]; then
  info "Attempting to mint cap with revoked agent token..."
  REVOKED_RESP=$(curl -s -X POST "$SHIELD_URL/v1/shield/cap/mint" \
    -H "X-Agent-Token: $AGENT_TOKEN" \
    -H "X-API-Key: $TENANT_KEY" \
    -H "Content-Type: application/json" \
    -d '{"tool":"send_email","resource":"inbox","ttl_seconds":30}' \
    2>/dev/null) || true
  info "Response (401):"
  echo "$REVOKED_RESP" | python3 -m json.tool 2>/dev/null || echo "$REVOKED_RESP"
  failure "Agent instance revoked — token no longer valid"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 5: OAUTH 2.1 / MCP FLOW (New standard auth)
# ─────────────────────────────────────────────────────────────────────────────

step "5a" "Discover OAuth Metadata (MCP clients start here)"
cat <<'EXPLAIN'
  MCP clients discover Shield's OAuth endpoints via RFC 8414.
  No authentication required for this endpoint.
EXPLAIN

META_RESP=$(curl -s "$SHIELD_URL/.well-known/oauth-authorization-server" 2>/dev/null) || true
info "Response:"
echo "$META_RESP" | python3 -m json.tool 2>/dev/null || echo "$META_RESP"
success "OAuth metadata discovered — clients now know all endpoints"

# ─────────────────────────────────────────────────────────────────────────────

step "5b" "Fetch JWKS (Public Keys for Token Verification)"
cat <<'EXPLAIN'
  Any service can fetch Shield's public keys to verify JWTs locally.
  No round-trip to Shield needed after initial JWKS fetch.
EXPLAIN

JWKS_RESP=$(curl -s "$SHIELD_URL/oauth/jwks" 2>/dev/null) || true
info "Response:"
echo "$JWKS_RESP" | python3 -m json.tool 2>/dev/null || echo "$JWKS_RESP"
success "JWKS fetched — Ed25519 public key in OKP format"

# ─────────────────────────────────────────────────────────────────────────────

step "5c" "Dynamic Client Registration (MCP client registers itself)"
cat <<'EXPLAIN'
  MCP clients register dynamically per RFC 7591.
  Returns client_id (+ client_secret for confidential clients).
EXPLAIN

REG_RESP=$(curl -s -X POST "$SHIELD_URL/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "none",
    "scope": "shield"
  }' 2>/dev/null) || true

info "Response (201 Created):"
echo "$REG_RESP" | python3 -m json.tool 2>/dev/null || echo "$REG_RESP"
success "Client registered — use client_id for OAuth flows"

# ─────────────────────────────────────────────────────────────────────────────

step "5d" "A2A Agent Card Discovery"
cat <<'EXPLAIN'
  External agents discover Shield's capabilities via the A2A Agent Card.
  Served at /.well-known/agent.json per the Google A2A spec.
EXPLAIN

A2A_RESP=$(curl -s "$SHIELD_URL/.well-known/agent.json" 2>/dev/null) || true
info "Response:"
echo "$A2A_RESP" | python3 -m json.tool 2>/dev/null || echo "$A2A_RESP"
success "Agent Card served — external agents know how to connect"

# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  COMPLETE FLOW SUMMARY${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
cat <<'SUMMARY'

  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
  │  Customer    │────>│  Agent Token │────>│  Cap Token  │────>│  Tool    │
  │  Agent       │     │  (AuthN)     │     │  (AuthZ)    │     │  Server  │
  └─────────────┘     └──────────────┘     └─────────────┘     └──────────┘
        │                    │                    │                   │
    X-API-Key           X-Agent-Token         cap_token          cap_token
    + claims            + tool/resource       (bearer)           (verify)
        │                    │                    │                   │
    ┌───▼───┐           ┌────▼────┐          ┌───▼───┐          ┌───▼───┐
    │Tenant │           │  RBAC   │          │ Nonce │          │ Sig + │
    │ Auth  │           │ Check   │          │ Burn  │          │ Tool  │
    │ + Rate│           │Clearance│          │Single │          │ Match │
    │ Limit │           │ Check   │          │ Use   │          │ Check │
    └───────┘           └─────────┘          └───────┘          └───────┘

  Failure points:
    Step 1: 401 (no key) | 429 (rate limit) | 422 (missing fields)
    Step 2: 401 (no/bad agent token) | 403 (RBAC denied) | 429 (rate limit)
    Step 3: valid=false (wrong tool | replay | tampered | expired | revoked)
    Step 4: Revocation → all future verifications fail

  Security properties:
    • Agent tokens: JWT EdDSA, ≤15min TTL, 3 revocation axes
    • Cap tokens:   JWT EdDSA, ≤60s TTL, single-use nonce, tool-bound
    • Separate signers: agent-token key ≠ cap key (confused deputy defense)
    • Separate audiences: "shield-agent-tokens" ≠ "shield-capabilities"

SUMMARY
