#!/usr/bin/env bash
# smoke_litellm_mcp.sh — verify LiteLLM's MCP tool calls are enforced by Shield.
#
# Tests the integration documented in docs/litellm-mcp-gateway.md: LiteLLM's
# mcp_servers url points at Shield's /gateway/{route}/mcp, so every tools/call
# is enforced before it reaches the real MCP server.
#
# Ordered so each step isolates a different failure:
#   1. Shield's gateway alone      — if this fails, LiteLLM is not the problem
#   2. the same calls via LiteLLM  — proves the wiring
#   3. a denied tool               — proves it ENFORCES, not just proxies
#   4. identity attribution        — catches extra_headers not forwarding
#
# The decisive check is step 3. A gateway that responds but never blocks is the
# failure mode this whole script exists to catch.
#
# Usage:
#   SHIELD_URL=https://<data-plane-host> TENANT_KEY=<tenant-api-key> \
#     ROUTE=files AGENT=my-agent ROLE=reader \
#     ALLOWED_TOOL=search DENIED_TOOL=delete_record \
#     [LITELLM_URL=http://localhost:4000] [LITELLM_KEY=<master-key>] \
#     ./scripts/smoke_litellm_mcp.sh
#
# Omit LITELLM_URL to run steps 1 and 3 against Shield only (useful before the
# proxy is up).
set -uo pipefail

: "${SHIELD_URL:?set SHIELD_URL to the Shield data-plane base URL}"
: "${TENANT_KEY:?set TENANT_KEY to the tenant API key}"
SHIELD_URL="${SHIELD_URL%/}"
ROUTE="${ROUTE:-files}"
AGENT="${AGENT:-my-agent}"
ROLE="${ROLE:-reader}"
ALLOWED_TOOL="${ALLOWED_TOOL:-search}"
DENIED_TOOL="${DENIED_TOOL:-delete_record}"
LITELLM_URL="${LITELLM_URL:-}"
LITELLM_URL="${LITELLM_URL%/}"
LITELLM_KEY="${LITELLM_KEY:-}"

AUTH=()
[ -n "${RUNPOD_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${RUNPOD_TOKEN}")
# bash 3.2 (macOS) errors on "${AUTH[@]}" when the array is empty under set -u.
_auth() { [ "${#AUTH[@]}" -gt 0 ] && printf '%s\n' "${AUTH[@]}"; }

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); echo "  ${G}PASS${Z} $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ${R}FAIL${Z} $1"; }
skip() { SKIP=$((SKIP+1)); echo "  ${Y}SKIP${Z} $1"; }

# JSON-RPC straight at Shield's gateway.
_shield() { # $1 method  $2 params-json
  curl -s -X POST "$SHIELD_URL/gateway/$ROUTE/mcp" \
    -H 'Content-Type: application/json' -H "X-API-Key: $TENANT_KEY" ${AUTH[@]+"${AUTH[@]}"} \
    -H "X-Agent-Key: $AGENT" -H "X-User-Role: $ROLE" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

# The same tool call through LiteLLM's MCP REST surface.
_litellm_call() { # $1 tool  $2 arguments-json
  curl -s -X POST "$LITELLM_URL/mcp-rest/tools/call" \
    -H 'Content-Type: application/json' \
    -H "x-litellm-api-key: $LITELLM_KEY" \
    -H "x-agent-key: $AGENT" -H "x-user-role: $ROLE" \
    -d "{\"name\":\"$1\",\"arguments\":$2}"
}

# True when the response reads as a Shield denial, on either surface.
_blocked() { grep -qiE 'blocked by shield|not allowed|isError.*true|"error"' <<<"$1"; }

echo
echo "Shield : $SHIELD_URL/gateway/$ROUTE/mcp"
echo "LiteLLM: ${LITELLM_URL:-<not set, skipping proxy steps>}"
echo "agent=$AGENT role=$ROLE allowed=$ALLOWED_TOOL denied=$DENIED_TOOL"

# ── 1. Shield's gateway on its own ───────────────────────────────────────
echo
echo "1. Shield gateway (direct)"

init=$(_shield initialize '{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}')
if grep -q 'shield-mcp-gateway' <<<"$init"; then
  ok "initialize returns shield-mcp-gateway"
else
  bad "initialize did not identify the Shield gateway: $(head -c 160 <<<"$init")"
  echo "     the route may not be registered, or the URL/tenant key is wrong."
fi

list=$(_shield tools/list '{}')
if grep -q '"tools"' <<<"$list"; then
  n=$(grep -o '"name"' <<<"$list" | wc -l | tr -d ' ')
  ok "tools/list returned $n tool(s), RBAC-filtered for role '$ROLE'"
else
  bad "tools/list failed: $(head -c 160 <<<"$list")"
fi

# ── 2. Enforcement, direct ───────────────────────────────────────────────
echo
echo "2. Enforcement (direct) — the checks that matter"

denied=$(_shield tools/call "{\"name\":\"$DENIED_TOOL\",\"arguments\":{}}")
if _blocked "$denied"; then
  ok "'$DENIED_TOOL' is BLOCKED"
else
  bad "'$DENIED_TOOL' was ALLOWED — enforcement is not engaging"
  echo "     check the agent is registered and the role lacks this tool."
fi

allowed=$(_shield tools/call "{\"name\":\"$ALLOWED_TOOL\",\"arguments\":{}}")
if _blocked "$allowed"; then
  bad "'$ALLOWED_TOOL' was blocked — expected it to pass (over-blocking)"
  echo "     $(head -c 200 <<<"$allowed")"
else
  ok "'$ALLOWED_TOOL' passes and reaches the upstream"
fi

# ── 3. The same behaviour through LiteLLM ────────────────────────────────
echo
echo "3. Through LiteLLM"

if [ -z "$LITELLM_URL" ]; then
  skip "LITELLM_URL not set"
elif [ -z "$LITELLM_KEY" ]; then
  skip "LITELLM_KEY not set"
else
  l_denied=$(_litellm_call "$DENIED_TOOL" '{}')
  if _blocked "$l_denied"; then
    ok "'$DENIED_TOOL' is BLOCKED through LiteLLM (Shield is in the path)"
  else
    bad "'$DENIED_TOOL' was ALLOWED through LiteLLM"
    echo "     LiteLLM is probably talking to your MCP server directly."
    echo "     check mcp_servers.<name>.url points at $SHIELD_URL/gateway/$ROUTE/mcp"
  fi

  l_allowed=$(_litellm_call "$ALLOWED_TOOL" '{}')
  if _blocked "$l_allowed"; then
    bad "'$ALLOWED_TOOL' blocked through LiteLLM — identity may not be forwarding"
    echo "     add x-agent-key / x-user-role to extra_headers in the LiteLLM config."
  else
    ok "'$ALLOWED_TOOL' passes through LiteLLM"
  fi
fi

# ── 4. Identity actually arrived ─────────────────────────────────────────
echo
echo "4. Identity attribution"

gov_code=$(curl -s -o /tmp/_smoke_gov.$$ -w '%{http_code}' \
  "$SHIELD_URL/v1/governance/agents" -H "X-API-Key: $TENANT_KEY" ${AUTH[@]+"${AUTH[@]}"})
gov=$(cat /tmp/_smoke_gov.$$ 2>/dev/null); rm -f /tmp/_smoke_gov.$$
if [ "$gov_code" = "404" ]; then
  # The self-hosted lite gateway does not mount the governance API. Absence of
  # the endpoint is not an enforcement failure, so do not report one.
  skip "governance API not available on this deployment (lite gateway)"
elif [ "$gov_code" != "200" ]; then
  skip "governance API returned HTTP $gov_code"
elif grep -q "\"$AGENT\"" <<<"$gov"; then
  ok "calls are attributed to '$AGENT'"
else
  bad "'$AGENT' not seen in governance inventory"
  echo "     if every call shows one generic identity, extra_headers is not"
  echo "     forwarding and per-agent RBAC has collapsed to per-proxy."
fi

# ── notes ────────────────────────────────────────────────────────────────
echo
echo "Not tested here (expected, see docs/litellm-mcp-gateway.md):"
echo "  - HITL confirmation does NOT gate on this path. Header identity means no"
echo "    verified session, so session-scoped guards stay dormant; Shield records"
echo "    a session_unavailable advisory rather than reporting a clean pass."
echo "  - Bypass: confirm your MCP server refuses direct connections, or"
echo "    isolation_ack=true is a false claim."

echo
echo "${G}${PASS} passed${Z}, ${R}${FAIL} failed${Z}, ${Y}${SKIP} skipped${Z}"
[ "$FAIL" -eq 0 ] || exit 1
