#!/usr/bin/env bash
# smoke_test_gateway.sh — prove a deployed MCP gateway ENFORCES, not just responds.
#
# Runs an ordered smoke test against a live gateway route: health, RBAC-filtered
# tools/list, an allowed call, and — the check that actually matters — a denied
# call that MUST be blocked. A gateway that answers but lets a denied tool through
# is worse than no gateway, so a green run here is the difference between
# "reachable" and "governed".
#
# Response shapes it asserts against (from api/routes_mcp_gateway_server.py):
#   health            -> {"status":"ok","routes":[...]}
#   tools/list        -> {"result":{"tools":[...]}}
#   allowed call      -> {"result":{"content":[...],"isError":false}}
#   blocked (allowlist)-> {"result":{"content":[{"text":"Blocked by Shield: ..."}],"isError":true}}
#   pending_confirmation-> {"error":{"code":-32002,...}}
#
# Usage:
#   GW=https://your-gateway ROUTE=files AGENT=coding-agent ROLE=reader \
#   ALLOW_TOOL=read_file  ALLOW_ARGS='{"path":"/data/x"}' \
#   DENY_TOOL=delete_file DENY_ARGS='{"path":"/data/x"}' \
#   [API_KEY=<tenant-key, hosted gateway only>] \
#   [PARITY=1] \
#     ./scripts/smoke_test_gateway.sh
set -uo pipefail

: "${GW:?set GW to the deployed gateway base URL}"
: "${ROUTE:?set ROUTE to a route from your gateway.yaml}"
: "${AGENT:?set AGENT to an X-Agent-Key from rbac.agents}"
: "${ROLE:?set ROLE to that agents role}"
GW="${GW%/}"
EP="$GW/gateway/$ROUTE/mcp"

# Hosted gateway also needs a tenant key; the self-hosted lite edition does not.
HDRS=(-H 'Content-Type: application/json' -H "X-Agent-Key: $AGENT" -H "X-User-Role: $ROLE")
[ -n "${API_KEY:-}" ] && HDRS+=(-H "X-API-Key: $API_KEY")

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); echo "  ${G}PASS${Z} $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ${R}FAIL${Z} $1"; }
skip() { SKIP=$((SKIP+1)); echo "  ${Y}SKIP${Z} $1"; }

# JSON-RPC tools/call, returns the raw response body. $2 defaults to {} — set
# separately, because ${VAR:-{}} appends a stray brace to a non-empty value.
_call() { # $1 tool  $2 args-json (may be empty)
  local tool="$1" args="$2"
  [ -z "$args" ] && args='{}'
  curl -s -X POST "$EP" "${HDRS[@]}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}"
}

# Extract a field via python3 (matches scripts/mcp_parity_smoke.sh convention).
_py() { python3 -c "$1" 2>/dev/null; }

echo "Gateway: $GW   route: $ROUTE   agent: $AGENT/$ROLE"
echo ""

# 1. Health — and the route must be registered (proves config loaded).
echo "1. Health"
H=$(curl -s "$GW/health")
if [ "$(echo "$H" | _py "import sys,json;print(json.load(sys.stdin).get('status'))")" = "ok" ]; then
  if echo "$H" | _py "import sys,json;r=json.load(sys.stdin).get('routes',[]);sys.exit(0 if '$ROUTE' in r else 1)"; then
    ok "gateway up, route '$ROUTE' registered"
  else
    bad "gateway up but route $ROUTE NOT in health.routes — config did not load this route"
  fi
else
  bad "no healthy response from $GW/health"
fi

# 2. tools/list — should return a (RBAC-filtered) tool set.
echo "2. tools/list (RBAC-filtered)"
TL=$(curl -s -X POST "$EP" "${HDRS[@]}" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
N=$(echo "$TL" | _py "import sys,json;print(len(json.load(sys.stdin).get('result',{}).get('tools',[])))")
if [ -n "$N" ] && [ "$N" -ge 0 ] 2>/dev/null; then
  ok "tools/list returned $N tool(s) for role '$ROLE'"
else
  bad "tools/list did not return a result.tools array — response: ${TL:0:160}"
fi

# 3. An allowed call passes.
echo "3. Allowed tool passes"
if [ -n "${ALLOW_TOOL:-}" ]; then
  A=$(_call "$ALLOW_TOOL" "${ALLOW_ARGS:-}")
  ERR=$(echo "$A" | _py "import sys,json;print(json.load(sys.stdin).get('result',{}).get('isError'))")
  if [ "$ERR" = "False" ]; then
    ok "$ALLOW_TOOL executed (isError=false)"
  else
    bad "$ALLOW_TOOL did not pass — response: ${A:0:160}"
  fi
else
  skip "set ALLOW_TOOL + ALLOW_ARGS to test an allowed call"
fi

# 4. THE CRITICAL CHECK — a denied tool must be blocked.
echo "4. Denied tool is BLOCKED (the check that proves enforcement)"
if [ -n "${DENY_TOOL:-}" ]; then
  D=$(_call "$DENY_TOOL" "${DENY_ARGS:-}")
  IS_ERR=$(echo "$D" | _py "import sys,json;print(json.load(sys.stdin).get('result',{}).get('isError'))")
  TXT=$(echo "$D" | _py "import sys,json;print((json.load(sys.stdin).get('result',{}).get('content') or [{}])[0].get('text',''))")
  if [ "$IS_ERR" = "True" ] && echo "$TXT" | grep -qi "block"; then
    ok "$DENY_TOOL blocked by Shield"
  else
    bad "$DENY_TOOL was NOT blocked — enforcement is not engaging. Response: ${D:0:200}"
  fi
else
  bad "DENY_TOOL not set — the most important check was SKIPPED. Set DENY_TOOL to a tool the $ROLE role may NOT use."
fi

# 5. Optional parity guards (only meaningful if SHIELD_MCP_TOOL_PARITY=1 at deploy).
if [ -n "${PARITY:-}" ] && [ -n "${SENSITIVE_TOOL:-}" ]; then
  echo "5. Parity: sensitive tool on header-only identity"
  S=$(_call "$SENSITIVE_TOOL" "${SENSITIVE_ARGS:-}")
  CODE=$(echo "$S" | _py "import sys,json;print(json.load(sys.stdin).get('error',{}).get('code'))")
  ADV=$(echo "$S" | _py "import sys,json;d=json.load(sys.stdin);print('session_unavailable' if 'session_unavailable' in json.dumps(d) else '')")
  if [ "$CODE" = "-32002" ]; then
    ok "$SENSITIVE_TOOL gated with HITL confirmation (-32002)"
  elif [ -n "$ADV" ]; then
    ok "$SENSITIVE_TOOL reported session_unavailable (header path cannot gate HITL — expected, not silent)"
  else
    skip "$SENSITIVE_TOOL neither gated nor advised — check SHIELD_MCP_TOOL_PARITY and require_confirmation"
  fi
fi

echo ""
if [ "$FAIL" -gt 0 ]; then FAILSTR="${R}${FAIL} failed${Z}"; else FAILSTR="0 failed"; fi
echo "Result: ${G}${PASS} passed${Z}, ${FAILSTR}, ${SKIP} skipped"
echo ""
echo "Reminder: also confirm your upstream MCP server refuses a DIRECT connection"
echo "(bypassing the gateway). A gateway only governs traffic that flows through it."
[ "$FAIL" -eq 0 ] || exit 1
