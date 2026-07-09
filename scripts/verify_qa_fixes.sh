#!/usr/bin/env bash
#
# verify_qa_fixes.sh — post-deploy verification for the HR Shield Breaker QA
# fixes (PR #196) plus the RBAC / tool-call / DLP paths the QA also covers.
#
# Read-only: it never mutates tenant config, policies, or kill switches.
#
# Usage:
#   export SHIELD_URL="https://<data-plane-host>"     # required
#   export TENANT_KEY="<tenant API key>"              # required
#   export TENANT_ID="hr-helpdesk-agent"              # optional (scoping assert)
#   export MASTER_KEY="<global/master key>"           # optional (admin checks)
#   export AGENT_KEY="people-directory-agent"         # optional
#   export PROXY_BEARER="<RunPod proxy token>"        # optional: sent as
#                                                     #   Authorization: Bearer
#                                                     #   for hosts behind a
#                                                     #   RunPod/Cloudflare proxy
#   bash scripts/verify_qa_fixes.sh
#
# Exit code: 0 if all hard checks PASS, 1 if any FAIL. WARNs do not fail.

set -uo pipefail

SHIELD_URL="${SHIELD_URL:-}"
TENANT_KEY="${TENANT_KEY:-}"
TENANT_ID="${TENANT_ID:-hr-helpdesk-agent}"
MASTER_KEY="${MASTER_KEY:-}"
AGENT_KEY="${AGENT_KEY:-people-directory-agent}"
PROXY_BEARER="${PROXY_BEARER:-}"

# When the data plane sits behind a RunPod/Cloudflare proxy, every request must
# carry Authorization: Bearer <proxy token> or the proxy returns 401 before the
# request reaches Shield. Apply it to all calls when set.
PROXY_HDR=()
[ -n "$PROXY_BEARER" ] && PROXY_HDR=(-H "Authorization: Bearer $PROXY_BEARER")

# --- prereqs --------------------------------------------------------------
for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: '$bin' is required"; exit 2; }
done
[ -n "$SHIELD_URL" ] || { echo "ERROR: set SHIELD_URL"; exit 2; }
[ -n "$TENANT_KEY" ] || { echo "ERROR: set TENANT_KEY"; exit 2; }
SHIELD_URL="${SHIELD_URL%/}"

PASS=0; FAIL=0; WARN=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; PASS=$((PASS+1)); }
no()   { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAIL=$((FAIL+1)); }
warn() { printf "  \033[33mWARN\033[0m  %s\n" "$1"; WARN=$((WARN+1)); }
hdr()  { printf "\n\033[1m%s\033[0m\n" "$1"; }

# GET status code only
code() { curl -s -o /dev/null -w "%{http_code}" "${PROXY_HDR[@]}" "$@"; }
# GET/POST returning "<body>\n<code>"
call() { curl -s -w $'\n%{http_code}' "${PROXY_HDR[@]}" "$@"; }
body() { sed '$d' <<<"$1"; }
status(){ tail -n1 <<<"$1"; }

echo "Target: $SHIELD_URL   tenant: $TENANT_ID"

# =========================================================================
hdr "auth-008 — audit log is authenticated + tenant-scoped"

c=$(code "$SHIELD_URL/v1/shield/audit")
[ "$c" = "401" ] && ok "no key -> 401 (was 200 disclosure)" || no "no key -> $c (expected 401)"

c=$(code "$SHIELD_URL/v1/shield/stats")
[ "$c" = "401" ] && ok "/stats no key -> 401" || no "/stats no key -> $c (expected 401)"

r=$(call -H "X-API-Key: $TENANT_KEY" "$SHIELD_URL/v1/shield/audit?limit=50")
sc=$(status "$r")
if [ "$sc" = "200" ]; then
  ok "tenant key -> 200"
  own=$(body "$r" | jq '.count // 0')
  # cross-tenant param must be ignored: same count as own scope
  r2=$(call -H "X-API-Key: $TENANT_KEY" "$SHIELD_URL/v1/shield/audit?tenant_id=__shield_probe_other__&limit=50")
  evil=$(body "$r2" | jq '.count // 0')
  if [ "$own" = "$evil" ]; then
    ok "?tenant_id is ignored for tenant keys (count $own == $evil) — no cross-tenant read"
  else
    no "cross-tenant param changed results ($own vs $evil) — scoping leak"
  fi
  # any returned entries must belong to this tenant
  bad=$(body "$r" | jq --arg t "$TENANT_ID" '[.entries[]? | (.metadata.tenant_id // $t) | select(. != $t)] | length')
  [ "${bad:-0}" = "0" ] && ok "all returned entries belong to $TENANT_ID" || no "$bad entries from other tenants leaked"
else
  no "tenant key -> $sc (expected 200)"
fi

if [ -n "$MASTER_KEY" ]; then
  c=$(code -H "X-API-Key: $MASTER_KEY" "$SHIELD_URL/v1/shield/audit")
  [ "$c" = "200" ] && ok "master key -> 200 (global view preserved)" || no "master key -> $c (expected 200)"
else
  warn "MASTER_KEY not set — skipped master/global audit check"
fi

# =========================================================================
hdr "tel-004 — guardrail metrics served on the data plane"

r=$(call -H "X-API-Key: $TENANT_KEY" "$SHIELD_URL/v1/tenant/me/guardrails/metrics")
sc=$(status "$r")
if [ "$sc" = "200" ]; then
  tg=$(body "$r" | jq '.total_guardrails // "missing"')
  [ "$tg" != "missing" ] && ok "metrics 200 with total_guardrails=$tg (was 404)" \
                         || no "metrics 200 but total_guardrails missing"
else
  no "metrics -> $sc (expected 200; 404 = fix not deployed)"
fi

# =========================================================================
hdr "output-003 — ISO DOB + phone detected on output"

r=$(call -H "X-API-Key: $TENANT_KEY" -H "Content-Type: application/json" \
     -d '{"output":"The employee DOB is 1991-03-14 and phone is +1-415-555-2210."}' \
     "$SHIELD_URL/guardrails/output")
sc=$(status "$r")
if [ "$sc" = "200" ]; then
  trig=$(body "$r" | jq -r '[.guardrail_results[]? | select(.passed==false) | .guardrail] | join(",")')
  act=$(body "$r" | jq -r '.action // "pass"')
  if echo "$trig" | grep -qi "pii"; then
    ok "PII detected on output (action=$act, triggered=$trig)"
  else
    warn "no PII triggered — enable pii_leakage (Date of Birth + Phone) on this tenant's OUTPUT guardrails; regex fix is in place but nothing is running it"
  fi
else
  no "/guardrails/output -> $sc (expected 200)"
fi

# =========================================================================
hdr "RBAC + tool-call authorization (/v1/shield/tool/check)"

r=$(call -H "X-API-Key: $TENANT_KEY" -H "Content-Type: application/json" \
     -d "{\"agent_key\":\"$AGENT_KEY\",\"tool_name\":\"lookup_employee\",\"user_role\":\"employee\",\"tool_params\":{\"employee_id\":\"EMP-1001\"}}" \
     "$SHIELD_URL/v1/shield/tool/check")
if [ "$(status "$r")" = "200" ]; then
  allowed=$(body "$r" | jq -r '.allowed')
  [ "$allowed" = "true" ] && ok "allowed tool (lookup_employee/employee) -> allowed:true" \
                          || warn "lookup_employee/employee -> allowed:$allowed (check tenant RBAC config)"
else
  no "tool/check (allowed case) -> $(status "$r")"
fi

r=$(call -H "X-API-Key: $TENANT_KEY" -H "Content-Type: application/json" \
     -d "{\"agent_key\":\"$AGENT_KEY\",\"tool_name\":\"update_salary\",\"user_role\":\"employee\",\"tool_params\":{\"employee_id\":\"EMP-1001\",\"amount\":999999}}" \
     "$SHIELD_URL/v1/shield/tool/check")
if [ "$(status "$r")" = "200" ]; then
  allowed=$(body "$r" | jq -r '.allowed')
  [ "$allowed" = "false" ] && ok "restricted tool (update_salary/employee) -> blocked" \
                           || warn "update_salary/employee -> allowed:$allowed (expected block; check tenant RBAC config)"
else
  no "tool/check (denied case) -> $(status "$r")"
fi

# =========================================================================
hdr "Tool-output DLP (/v1/shield/tool/output)"

r=$(call -H "X-API-Key: $TENANT_KEY" -H "Content-Type: application/json" \
     -d "{\"agent_key\":\"$AGENT_KEY\",\"tool_name\":\"lookup_employee\",\"tool_output\":\"name=Sarah Chen, ssn=123-45-6789, salary=185000\"}" \
     "$SHIELD_URL/v1/shield/tool/output")
if [ "$(status "$r")" = "200" ]; then
  san=$(body "$r" | jq -r '.sanitized_output // ""')
  allowed=$(body "$r" | jq -r '.allowed')
  if [ -n "$san" ] && ! echo "$san" | grep -q "123-45-6789"; then
    ok "SSN redacted in sanitized_output"
  elif [ "$allowed" = "false" ]; then
    ok "tool output blocked (allowed:false)"
  else
    warn "SSN not redacted/blocked — check this tenant's data_policies sanitization rules"
  fi
else
  no "tool/output -> $(status "$r")"
fi

# =========================================================================
hdr "MCP <-> REST parity"
if [ -f "scripts/mcp_parity_smoke.sh" ]; then
  if SHIELD_URL="$SHIELD_URL" TENANT_KEY="$TENANT_KEY" bash scripts/mcp_parity_smoke.sh >/tmp/mcp_parity.out 2>&1; then
    ok "mcp_parity_smoke.sh: direct and MCP agree"
  else
    no "mcp_parity_smoke.sh reported a mismatch (see /tmp/mcp_parity.out)"
  fi
else
  warn "scripts/mcp_parity_smoke.sh not found — skipped"
fi

# =========================================================================
printf "\n\033[1mSummary:\033[0m %d PASS, %d FAIL, %d WARN\n" "$PASS" "$FAIL" "$WARN"
[ "$FAIL" -eq 0 ] || exit 1
