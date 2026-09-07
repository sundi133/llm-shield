#!/usr/bin/env bash
# Live reproductions for LS-14, LS-15, and LS-21 (MCP Gateway findings) against
# a real production Shield deployment, using the voyager-mcp demo app
# (https://github.com/<org>/voyager-mcp, deployed on Railway) as a real
# registered gateway upstream. See LLM-Shield-Issues-Improvements.xlsx for the
# full write-up; this is the live counterpart to
# scripts/repro_mcp_gateway_findings.py (which covers LS-13..LS-16 at the code
# level, no network required).
#
# Requires:
#   SHIELD_API_KEY   tenant API key for the voyager-mcp tenant (never hardcode
#                    this -- pass it as an env var, e.g. from a password
#                    manager or a local .env you do not commit)
#   SHIELD_HOST      defaults to the production host below
#   ROUTE            the registered gateway route name for voyager-mcp
#
# Usage:
#   SHIELD_API_KEY=sk-... ./scripts/repro_mcp_gateway_live_voyager.sh
#
# Safety: this creates and then REMOVES a tenant-wide approval rule and a
# tool data policy. The `cleanup` trap runs even if a step fails or the
# script is interrupted, so the tenant should never be left in a modified
# state. cancel_booking is only ever exercised against voyager-mcp's
# in-memory demo data (BK-7002), which resets on a Railway restart.

set -euo pipefail

SHIELD_HOST="${SHIELD_HOST:-https://api.guardrails.votal.ai}"
ROUTE="${ROUTE:-voyager-mcp}"
: "${SHIELD_API_KEY:?Set SHIELD_API_KEY to the voyager-mcp tenant key before running this}"

GW="$SHIELD_HOST/gateway/$ROUTE/mcp"
AUTH=(-H "X-API-Key: $SHIELD_API_KEY" -H "Content-Type: application/json")
AGENT=(-H "X-Agent-Key: $ROUTE")

cleanup() {
  echo "--- cleanup: reverting approval rule and data policy ---"
  curl -s -X PUT "$SHIELD_HOST/v1/tenant/me/agentic/config" "${AUTH[@]}" \
    -d '{"approvals":{"rules":[]}}' >/dev/null
  curl -s -X DELETE "$SHIELD_HOST/v1/data-policies/tools/list_bookings/policy" "${AUTH[@]}" >/dev/null
  echo "cleanup done"
}
trap cleanup EXIT

echo "=== LS-15 / LS-21: approval-required tool executes unapproved in monitor mode ==="

echo "--- baseline: BK-7002 before test ---"
curl -s "$GW" "${AUTH[@]}" "${AGENT[@]}" -H "X-User-Role: traveler" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_booking","arguments":{"bookingId":"BK-7002"}}}'
echo ""

echo "--- require approval for cancel_booking ---"
curl -s -X PUT "$SHIELD_HOST/v1/tenant/me/agentic/config" "${AUTH[@]}" \
  -d '{"approvals":{"rules":[{"tool_names":["cancel_booking"]}]}}'
echo ""

echo "--- attempt cancel_booking with NO approval grant ---"
curl -s "$GW" "${AUTH[@]}" "${AGENT[@]}" -H "X-User-Role: admin" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cancel_booking","arguments":{"bookingId":"BK-7002","reason":"LS-15/LS-21 repro"}}}'
echo ""

echo "--- LS-21: check the decision audit for this call ---"
echo "    Bug if metadata shows control_plane_mode=monitor, allowed=true, guardrails=[]"
echo "    even though an approval_required rule matched."
curl -s "$SHIELD_HOST/v1/shield/decisions/$ROUTE?tool_name=cancel_booking&limit=3" "${AUTH[@]}"
echo ""

echo "=== LS-14: wildcard role-policy bypass via a self-claimed X-User-Role ==="

echo "--- block PII on list_bookings except for admin ---"
curl -s -X POST "$SHIELD_HOST/v1/data-policies/tools/list_bookings/policy" "${AUTH[@]}" \
  -d '{"tool_name":"list_bookings","role_policies":[{"role":"*","action":"block"},{"role":"admin","action":"allow"}]}'
echo ""

echo "--- as guest: should be blocked ---"
curl -s "$GW" "${AUTH[@]}" "${AGENT[@]}" -H "X-User-Role: guest" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_bookings","arguments":{"travelerEmail":"diya.nair@example.com"}}}'
echo ""

echo "--- same call, just claiming admin: bug if this returns full PII ---"
curl -s "$GW" "${AUTH[@]}" "${AGENT[@]}" -H "X-User-Role: admin" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_bookings","arguments":{"travelerEmail":"diya.nair@example.com"}}}'
echo ""

echo "=== done (cleanup runs next via trap) ==="
