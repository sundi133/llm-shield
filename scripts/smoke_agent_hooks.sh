#!/usr/bin/env bash
# smoke_agent_hooks.sh: check a deployed Shield's coding-agent hooks.
#
# Covers docs/claude-code-runtime-guardrails.md, from the outside, after a
# deploy. Ordered so each step isolates a different failure:
#   1. the routes exist and need a key       (a deploy that missed them)
#   2. the portal routes answer               (admin API on the data plane)
#   3. an ordinary command is allowed         (the hook does not block work)
#   4. a denied command is denied             (the decisive check: it ENFORCES)
#   5. a bad request is refused               (input checks)
#
# Step 4 needs the agent (SMOKE_AGENT, default claude-code) bound to a runtime
# profile that denies DENIED_COMMAND (the coding-agent-baseline template does).
# Without a profile the step is skipped, not failed, and says why.
#
# Every call is tagged X-Shield-User: smoke-check and session smoke-<time>, so
# its audit rows are easy to tell apart. Nothing is created or changed.
#
# Usage:
#   SHIELD_URL=https://<data-plane-host> TENANT_KEY=<tenant-api-key> \
#     [SMOKE_AGENT=claude-code] [DENIED_COMMAND='openssl enc -in a.txt'] \
#     ./scripts/smoke_agent_hooks.sh
#
# Exit status: 0 when nothing failed (skips allowed), 1 otherwise.
set -uo pipefail

: "${SHIELD_URL:?set SHIELD_URL to the Shield data-plane base URL}"
: "${TENANT_KEY:?set TENANT_KEY to the tenant API key}"
SHIELD_URL="${SHIELD_URL%/}"
SMOKE_AGENT="${SMOKE_AGENT:-claude-code}"
DENIED_COMMAND="${DENIED_COMMAND:-openssl enc -in a.txt}"
SESSION="smoke-$(date +%s)"

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
[ -t 1 ] || { G=""; R=""; Y=""; Z=""; }
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); echo "  ${G}PASS${Z} $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ${R}FAIL${Z} $1"; }
skip() { SKIP=$((SKIP+1)); echo "  ${Y}SKIP${Z} $1"; }

BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT

# _call METHOD PATH [json-body] [extra curl args...] -> sets CODE, OUT
_call() {
  local method=$1 path=$2 data=${3:-}
  shift 3 2>/dev/null || shift $#
  local args=(-s -m 20 -o "$BODY" -w '%{http_code}' -X "$method" "$SHIELD_URL$path"
              -H "Content-Type: application/json" -H "X-Shield-User: smoke-check")
  [ -n "$data" ] && args+=(-d "$data")
  CODE=$(curl "${args[@]}" "$@" 2>/dev/null) || CODE=000
  OUT=$(cat "$BODY")
}

# _hook COMMAND [extra curl args...]: one Claude Code Bash call.
_hook() {
  local cmd=$1; shift
  local esc=${cmd//\\/\\\\}; esc=${esc//\"/\\\"}
  _call POST /v1/shield/hooks/claude-code \
    "{\"session_id\":\"$SESSION\",\"cwd\":\"/Users/smoke/proj\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$esc\"}}" \
    -H "X-API-Key: $TENANT_KEY" -H "X-Agent-Key: $SMOKE_AGENT" "$@"
}

_json() { # _json <python expression on d> : evaluates against $OUT
  printf '%s' "$OUT" | python3 -c "import json,sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(2)
print($1)" 2>/dev/null
}

echo "Coding-agent hooks smoke check: $SHIELD_URL (agent $SMOKE_AGENT, session $SESSION)"

echo "1. Routes"
_call POST /v1/shield/hooks/claude-code '{}'
if [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then ok "hook route exists and needs a key ($CODE)"
elif [ "$CODE" = "404" ]; then bad "hook route missing (404): this Shield does not have the hook adapter"
else bad "hook route without a key answered $CODE"; fi

echo "2. Portal routes"
_call GET /v1/tenant/me/hooks/fleets "" -H "X-API-Key: $TENANT_KEY"
if [ "$CODE" = "200" ] && [ "$(_json '"fleets" in d')" = "True" ]; then
  ok "fleets: $(_json 'len(d["fleets"])') fleet(s), configured=$(_json 'd["configured"]')"
else bad "GET /v1/tenant/me/hooks/fleets answered $CODE"; fi
_call GET /v1/tenant/me/hooks/claude-code "" -H "X-API-Key: $TENANT_KEY"
PROFILE=""
if [ "$CODE" = "200" ]; then
  PROFILE=$(_json 'd.get("status", {}).get("claude_code", {}).get("profile", "")')
  ok "overview: agent claude-code profile '${PROFILE:-none}', Shield URL $(_json 'd["shield_url"]') ($(_json 'd["shield_url_source"]'))"
else bad "GET /v1/tenant/me/hooks/claude-code answered $CODE"; fi

echo "3. Ordinary work is allowed"
_hook "git status"
if [ "$CODE" = "200" ] && [ "$OUT" = "{}" ]; then ok "git status: allowed"
else bad "git status: HTTP $CODE $OUT"; fi

echo "4. A denied command is denied"
_hook "$DENIED_COMMAND"
DECISION=$(_json 'd.get("hookSpecificOutput", {}).get("permissionDecision", "allow")')
if [ "$CODE" != "200" ]; then bad "$DENIED_COMMAND: HTTP $CODE $OUT"
elif [ "$DECISION" = "deny" ]; then ok "$DENIED_COMMAND: denied ($(_json 'd["hookSpecificOutput"]["permissionDecisionReason"]'))"
elif [ "$SMOKE_AGENT" = "claude-code" ] && [ -z "$PROFILE" ]; then
  skip "$DENIED_COMMAND: allowed, because agent claude-code has no runtime profile (Turn on for Claude Code first)"
else bad "$DENIED_COMMAND: answered '$DECISION', expected deny (does agent $SMOKE_AGENT's profile deny it?)"; fi

echo "5. Bad requests are refused"
_call POST /v1/shield/hooks/claude-code '{"tool_name":"Bash"}' -H "X-API-Key: $TENANT_KEY"
if [ "$CODE" = "400" ]; then ok "missing X-Agent-Key: 400"; else bad "missing X-Agent-Key answered $CODE"; fi
_call POST /v1/shield/hooks/claude-code 'not json' -H "X-API-Key: $TENANT_KEY" -H "X-Agent-Key: $SMOKE_AGENT"
if [ "$CODE" = "422" ]; then ok "body that is not JSON: 422"; else bad "body that is not JSON answered $CODE"; fi

echo "Result: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
