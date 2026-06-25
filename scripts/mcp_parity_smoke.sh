#!/usr/bin/env bash
# mcp_parity_smoke.sh — verify hosted MCP behavior matches direct Shield REST.
#
# Reproduces the HR-agent QA parity findings (1-4) as paired checks: for each
# scenario it calls BOTH the MCP tool (/mcp/message tools/call) and the matching
# direct REST endpoint, and asserts they agree (both BLOCK, or both PASS). Exits
# non-zero on any mismatch.
#
# Use a tenant that actually has the relevant guardrail + data policies
# configured (e.g. the HR helpdesk tenant) — the whole point is that MCP now
# applies tenant config, so a tenant with no policies would (correctly) PASS
# both paths and prove nothing.
#
# Usage:
#   SHIELD_URL=https://<data-plane-host> TENANT_KEY=<tenant-api-key> \
#     [RUNPOD_TOKEN=<proxy-bearer>] [DIR_AGENT=people-directory-agent] \
#     [OPS_AGENT=people-ops-agent] ./scripts/mcp_parity_smoke.sh
set -uo pipefail

: "${SHIELD_URL:?set SHIELD_URL to the data-plane base URL}"
: "${TENANT_KEY:?set TENANT_KEY to the tenant API key (one that has policies)}"
SHIELD_URL="${SHIELD_URL%/}"
DIR_AGENT="${DIR_AGENT:-people-directory-agent}"
OPS_AGENT="${OPS_AGENT:-people-ops-agent}"

AUTH=()
[ -n "${RUNPOD_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${RUNPOD_TOKEN}")

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ${G}PASS${Z} $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ${R}FAIL${Z} $1"; }

# Call an MCP tool, print its text verdict.
_mcp() { # $1 agent  $2 role  $3 tool  $4 arguments-json
  curl -s -X POST "$SHIELD_URL/mcp/message" \
    -H 'Content-Type: application/json' -H "X-API-Key: $TENANT_KEY" "${AUTH[@]}" \
    -H "X-Agent-Key: $1" -H "X-User-Role: $2" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$3\",\"arguments\":$4}}" \
  | python3 -c "import sys,json
try: print(json.load(sys.stdin)['result']['content'][0]['text'])
except Exception as e: print('ERROR '+str(e))"
}

# Call a direct REST endpoint, print BLOCK / PASS / ERROR.
_rest() { # $1 path  $2 body-json
  curl -s -X POST "$SHIELD_URL$1" \
    -H 'Content-Type: application/json' -H "X-API-Key: $TENANT_KEY" "${AUTH[@]}" \
    -d "$2" \
  | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print('BLOCK' if (d.get('safe') is False or d.get('action')=='block' or d.get('allowed') is False) else 'PASS')
except Exception as e: print('ERROR')"
}

_mcp_verdict() { case "$1" in BLOCKED*) echo BLOCK;; ERROR*) echo ERROR;; *) echo PASS;; esac; }

# Assert MCP and REST agree.
compare() { # $1 name  $2 mcp_text  $3 rest_verdict
  local name="$1" mtext="$2" rest="$3" m
  m=$(_mcp_verdict "$mtext")
  if [ "$m" = "ERROR" ] || [ "$rest" = "ERROR" ]; then
    bad "$name — call error (MCP='$mtext' REST=$rest)"
  elif [ "$m" = "$rest" ]; then
    ok "$name — both ${m}"
  else
    bad "$name — MISMATCH MCP=$m REST=$rest  (mcp='$mtext')"
  fi
}

echo "Shield: $SHIELD_URL  tenant-key: ${TENANT_KEY:0:6}…"
echo ""

# Finding 1 — input guardrail (off-topic for an HR agent should block)
compare "F1 input: off-topic (account balance)" \
  "$(_mcp "$DIR_AGENT" employee shield_check_input '{"message":"what is my account balance?"}')" \
  "$(_rest /guardrails/input '{"message":"what is my account balance?"}')"

# Finding 2 — output guardrail (SSN leak should block)
compare "F2 output: SSN leak" \
  "$(_mcp "$DIR_AGENT" employee shield_check_output '{"output":"Sarah Chen'\''s SSN is 521-44-9087."}')" \
  "$(_rest /guardrails/output '{"output":"Sarah Chen'\''s SSN is 521-44-9087."}')"

# Finding 3 — tool payload policy (external recipient should block)
compare "F3 tool: send_hr_email to external domain" \
  "$(_mcp "$OPS_AGENT" manager shield_check_tool '{"tool_name":"send_hr_email","user_role":"manager","arguments":{"to":"qa@gmail.com","subject":"QA","body":"hello"}}')" \
  "$(_rest /v1/shield/tool/check '{"agent_key":"'"$OPS_AGENT"'","tool_name":"send_hr_email","user_role":"manager","tool_params":{"to":"qa@gmail.com","subject":"QA","body":"hello"}}')"

# Finding 4 (CRITICAL) — tool-output DLP (sensitive HR fields should block)
SENSITIVE='employee_id=EMP-1001, name=Sarah Chen, salary_usd=178000, ssn=521-44-9087, dob=1991-03-14, personal_phone=+1-415-555-2210'
compare "F4 tool-output DLP: SSN/DOB/comp" \
  "$(_mcp "$DIR_AGENT" employee shield_sanitize_output "{\"tool_name\":\"lookup_employee\",\"output\":\"$SENSITIVE\"}")" \
  "$(_rest /v1/shield/tool/output "{\"agent_key\":\"$DIR_AGENT\",\"tool_name\":\"lookup_employee\",\"tool_output\":\"$SENSITIVE\"}")"

# Negative control — benign output must PASS on both (no false positives)
BENIGN='name=Sarah Chen, title=Senior Software Engineer, office=SF-3'
compare "OK tool-output: benign (no PII)" \
  "$(_mcp "$DIR_AGENT" employee shield_sanitize_output "{\"tool_name\":\"lookup_employee\",\"output\":\"$BENIGN\"}")" \
  "$(_rest /v1/shield/tool/output "{\"agent_key\":\"$DIR_AGENT\",\"tool_name\":\"lookup_employee\",\"tool_output\":\"$BENIGN\"}")"

echo ""
echo "Result: ${G}${PASS} passed${Z}, $([ "$FAIL" -gt 0 ] && echo "${R}${FAIL} failed${Z}" || echo "${FAIL} failed")"
[ "$FAIL" -eq 0 ] || exit 1
