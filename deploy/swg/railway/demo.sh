#!/usr/bin/env bash
# Live demo of the Railway testbed. Three minutes, four beats.
#
#   ./deploy/swg/railway/demo.sh
#
# Everything in the project is private, so every check runs inside the adapter
# container over `railway ssh`. Nothing here is reachable from your laptop
# directly, which is the point.
#
# Run it once before the meeting. It is read-only apart from the prompts it
# sends, so running it twice costs nothing.
set -uo pipefail

SVC=shield-icap
say() { printf '\n\033[1m%s\033[0m\n' "$1"; }

if ! railway status >/dev/null 2>&1; then
    echo "Not linked to a Railway project. Run: railway link" >&2
    exit 1
fi

# ── 1. real policy, and is it actually enforcing ─────────────────────────────
say "1. Policy loaded from production"
railway ssh --service "$SVC" "python -c \"
import urllib.request, json
d = json.load(urllib.request.urlopen('http://[::1]:8081/healthz', timeout=10))
print('   tenant            : %s' % d['tenant_id'])
print('   policy version    : %s' % d['bundle_version'])
print('   rules             : %s' % d['rules'])
print('   rules that block  : %s' % d['blocking_rules'])
print('   enforcing         : %s   <- the number that matters' % d['enforcing_anything'])
print('   mode              : %s' % d['mode'])
\"" 2>&1 | grep -v "^Using SSH key"

# Squid marks the ICAP service down if the adapter restarts under it, and with
# bypass=off every request then fails closed with a 500. That reads as a total
# outage mid-demo, so check for it here and say what to do.
if railway logs --service squid 2>&1 | tail -40 | grep -q "ICAP service is down"; then
    echo
    echo "   WARNING: Squid recently reported the ICAP service down. If step 2"
    echo "   returns 500, restart Squid and re-run:  railway redeploy -s squid -y"
fi

# ── 2 and 3. benign passes, violating is blocked ────────────────────────────
say "2. A normal prompt goes through. A prompt with customer data does not."
PY=$(cat <<'EOF'
import http.client, ssl, json
ctx = ssl._create_unverified_context()
tests = [("normal prompt", "what is the weather in Paris"),
         ("customer email", "email john.doe@bankco.com about his account")]
for name, prompt in tests:
    body = json.dumps({"model": "claude-opus-4",
                       "messages": [{"role": "user", "content": prompt}]})
    c = http.client.HTTPSConnection("squid.railway.internal", 3128, context=ctx, timeout=45)
    c.set_tunnel("api.anthropic.com", 443)
    c.request("POST", "/v1/messages", body, {"content-type": "application/json"})
    r = c.getresponse(); raw = r.read(); c.close()
    if r.status == 403:
        d = json.loads(raw)
        print("   %-15s HTTP %s  BLOCKED" % (name, r.status))
        print("   %-15s reason : %s" % ("", d.get("reason")))
        print("   %-15s ref    : %s" % ("", d.get("reference")))
    elif r.status == 401:
        # 401 is the provider answering: we have no API key on this testbed, so
        # reaching Anthropic at all is the proof the request was forwarded.
        print("   %-15s HTTP %s  forwarded, reached the provider" % (name, r.status))
    elif r.status == 500:
        print("   %-15s HTTP %s  *** SQUID ERROR, NOT A VERDICT ***" % (name, r.status))
        print("   %-15s Squid could not reach the screening service, so it failed" % "")
        print("   %-15s closed. Fix before demoing: railway redeploy -s squid -y" % "")
    else:
        print("   %-15s HTTP %s  unexpected, investigate before demoing" % (name, r.status))
EOF
)
railway ssh --service "$SVC" \
  "python -c \"import base64;exec(base64.b64decode('$(printf %s "$PY" | base64 -w0)').decode())\"" \
  2>&1 | grep -v "^Using SSH key"

# ── 4. what it recorded, and what it did not ────────────────────────────────
say "3. What was recorded"
railway logs --service "$SVC" 2>&1 | grep "icap txn" | grep -v "method=CONNECT" \
  | tail -2 | sed 's/^/   /'

say "4. The prompt itself was never logged"
if railway logs --service "$SVC" 2>&1 | tail -80 | grep -qi "john.doe@bankco.com"; then
    echo "   FAIL: prompt content found in the log. That is a bug, report it."
else
    echo "   The blocked address does not appear anywhere in the log."
    echo "   Only destination, rule, and a reference the help desk can trace."
fi

cat <<'CLOSING'

   ── what this shows ─────────────────────────────────────────────────
   Squid decrypted the request, handed it to Shield for screening, and
   Shield blocked it against the tenant's real policy before it reached
   the AI provider. The user gets a readable reason, support gets a
   reference, and the prompt itself is never stored.

   Traffic to non-AI sites is never decrypted at all. Banking, payroll
   and identity providers are on a bypass list applied before any
   decryption happens.
   ────────────────────────────────────────────────────────────────────
CLOSING
