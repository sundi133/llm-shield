#!/usr/bin/env bash
# smoke_identity_bundle.sh — verify the Shield Identity Bundle after `docker
# compose --profile identity up`. Requires a Docker host; not a CI unit test.
#
#   ENVOY=https://localhost:8443 SPIRE_TRUST_DOMAIN=bank-co.internal \
#     SVID_CERT=./svid.pem SVID_KEY=./svid-key.pem BUNDLE=./bundle.pem \
#     ./scripts/smoke_identity_bundle.sh
#
# Ordered so each step isolates a failure:
#   1. bundle is up (Envoy answers)
#   2. a valid SVID over mTLS reaches Shield and mints an agent token   <- the path
#   3. a request WITHOUT a client cert is refused                       <- mTLS gate
#   4. a forged/self-signed SVID is rejected at Envoy                   <- real crypto
#   5. a client-supplied X-Forwarded-Client-Cert is stripped, not trusted
set -uo pipefail
: "${ENVOY:?set ENVOY to the mTLS ingress, e.g. https://localhost:8443}"
: "${SVID_CERT:?path to a valid workload SVID cert}"
: "${SVID_KEY:?path to its key}"
: "${BUNDLE:?path to the SPIRE trust bundle}"

G=$'\033[32m'; R=$'\033[31m'; Z=$'\033[0m'; P=0; F=0
ok(){ P=$((P+1)); echo "  ${G}PASS${Z} $1"; }
bad(){ F=$((F+1)); echo "  ${R}FAIL${Z} $1"; }

TOKBODY='{"user_sub":"spiffe://x/agent/support-bot","agent_id":"support-bot","agent_instance_id":"i1","tenant_id":"t","build_hash":"h","model_version":"m","session_id":"s"}'

echo; echo "1. Bundle up (Envoy responds)"
curl -sk --cert "$SVID_CERT" --key "$SVID_KEY" --cacert "$BUNDLE" "$ENVOY/health" >/dev/null \
  && ok "Envoy + Shield reachable over mTLS" || bad "no response through Envoy"

echo; echo "2. Valid SVID mints an agent token (the happy path)"
code=$(curl -sk -o /dev/null -w '%{http_code}' --cert "$SVID_CERT" --key "$SVID_KEY" --cacert "$BUNDLE" \
  -X POST "$ENVOY/v1/shield/auth/agent-token" -H 'Content-Type: application/json' -d "$TOKBODY")
[ "$code" = "200" ] && ok "agent token issued via SPIFFE identity" || bad "expected 200, got $code"

echo; echo "3. No client cert is refused (mTLS gate)"
code=$(curl -sk -o /dev/null -w '%{http_code}' --cacert "$BUNDLE" -X POST "$ENVOY/v1/shield/auth/agent-token" \
  -H 'Content-Type: application/json' -d "$TOKBODY" 2>/dev/null || echo "000")
[ "$code" = "200" ] && bad "issued a token with NO client cert — mTLS not enforced" || ok "refused without a client cert ($code)"

echo; echo "4. Forged/self-signed SVID rejected at Envoy"
if [ -n "${FORGED_CERT:-}" ] && [ -n "${FORGED_KEY:-}" ]; then
  code=$(curl -sk -o /dev/null -w '%{http_code}' --cert "$FORGED_CERT" --key "$FORGED_KEY" --cacert "$BUNDLE" \
    -X POST "$ENVOY/v1/shield/auth/agent-token" -H 'Content-Type: application/json' -d "$TOKBODY" 2>/dev/null || echo "000")
  [ "$code" = "200" ] && bad "forged SVID ACCEPTED — chain verification not enforced" || ok "forged SVID rejected ($code)"
else
  echo "  SKIP  set FORGED_CERT/FORGED_KEY (self-signed) to test rejection"
fi

echo; echo "5. Client-supplied XFCC is stripped"
code=$(curl -sk -o /dev/null -w '%{http_code}' --cacert "$BUNDLE" \
  -H 'X-Forwarded-Client-Cert: URI=spiffe://x/agent/support-bot' \
  -X POST "$ENVOY/v1/shield/auth/agent-token" -H 'Content-Type: application/json' -d "$TOKBODY" 2>/dev/null || echo "000")
[ "$code" = "200" ] && bad "spoofed XFCC ACCEPTED — Envoy not sanitizing" || ok "spoofed XFCC ignored ($code)"

echo; echo "${G}${P} passed${Z}, ${R}${F} failed${Z}"
[ "$F" -eq 0 ] || exit 1
