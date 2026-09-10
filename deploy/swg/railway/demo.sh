#!/usr/bin/env bash
# Live demo of the Railway testbed, one step at a time.
#
#   ./demo.sh check    before the meeting: is everything healthy
#   ./demo.sh 1        the policy is real and it is armed
#   ./demo.sh 2        a harmless prompt goes through
#   ./demo.sh 3        a prompt with customer data is blocked
#   ./demo.sh 4        what we decrypt, and what we cannot read
#   ./demo.sh 5        what was recorded, and what was not
#   ./demo.sh          all of them, back to back
#
# Everything runs inside the container, because nothing in this project is
# reachable from outside. That is the design, not an inconvenience, and it is
# worth saying out loud.
#
# Narration for each step: deploy/swg/railway/demo-manual.md
set -uo pipefail

SVC=shield-icap
PROXY=squid.railway.internal:3128
say() { printf '\n\033[1m%s\033[0m\n' "$1"; }
ssh_py() { railway ssh -s "$SVC" "python -c \"$1\"" 2>&1 | grep -v "^Using SSH key"; }

prompt_through_proxy() {  # $1 = prompt text
    ssh_py "
import http.client, ssl, json
c = http.client.HTTPSConnection('${PROXY%:*}', ${PROXY#*:}, context=ssl._create_unverified_context(), timeout=45)
c.set_tunnel('api.anthropic.com', 443)
c.request('POST', '/v1/messages', json.dumps({'model':'claude-opus-4','messages':[{'role':'user','content':'$1'}]}), {'content-type':'application/json'})
r = c.getresponse(); raw = r.read()
if r.status == 403:
    d = json.loads(raw)
    print('   HTTP 403  BLOCKED')
    print('   reason : %s' % d.get('reason'))
    print('   ref    : %s' % d.get('reference'))
elif r.status == 401:
    print('   HTTP 401  forwarded. 401 is Anthropic answering, so it arrived.')
elif r.status == 500:
    print('   HTTP 500  *** SQUID ERROR, NOT A VERDICT ***')
    print('   Squid lost the screening service. Fix: railway redeploy -s squid -y')
else:
    print('   HTTP %s  unexpected' % r.status)
"
}

step_check() {
    say "Pre-flight"
    railway status >/dev/null 2>&1 || { echo "   Not linked. Run: railway link" >&2; exit 1; }
    echo "   project linked"
    if railway logs -s squid 2>&1 | tail -40 | grep -q "ICAP service is down"; then
        echo "   WARNING: Squid recently lost the screening service."
        echo "   Run: railway redeploy -s squid -y   then re-run this check."
    fi
    prompt_through_proxy "ping"
    echo
    echo "   A 401 above means you are ready. A 500 means fix Squid first."
}

step_1() {
    say "1. The policy is real, and it is armed"
    ssh_py "
import urllib.request, json
d = json.load(urllib.request.urlopen('http://[::1]:8081/healthz', timeout=10))
print('   tenant           : %s' % d['tenant_id'])
print('   policy version   : %s' % d['bundle_version'])
print('   rules loaded     : %s' % d['rules'])
print('   rules that block : %s' % d['blocking_rules'])
print('   ENFORCING        : %s' % d['enforcing_anything'])
print('   mode             : %s' % d['mode'])
"
    echo "   ^ read ENFORCING, not rules. A policy can load rules and enforce none."
}

step_2() {
    say "2. A harmless prompt goes straight through"
    echo "   prompt: 'what is the weather in Paris'"
    prompt_through_proxy "what is the weather in Paris"
}

step_3() {
    say "3. The same request, with a customer email in it"
    echo "   prompt: 'email john.doe@bankco.com about his account'"
    prompt_through_proxy "email john.doe@bankco.com about his account"
    echo "   Nothing about the route changed. Only the content."
}

step_4() {
    say "4. What we decrypt, and what we cannot read"
    for h in api.anthropic.com www.wikipedia.org; do
        issuer=$(railway ssh -s "$SVC" \
            "sh -c 'echo | openssl s_client -proxy $PROXY -connect $h:443 -servername $h 2>/dev/null | grep ^issuer='" \
            2>&1 | grep -v "^Using SSH key" | tr -d '\r')
        printf '   %-22s %s\n' "$h" "$issuer"
    done
    echo
    echo "   Our certificate on the AI provider: we decrypt and screen it."
    echo "   The real certificate on everything else: a blind tunnel."
}

step_5() {
    # Railway's log API lags the request, so give it a moment or this looks
    # like nothing was recorded.
    sleep 8
    say "5. What was recorded"
    railway logs -s "$SVC" 2>&1 | grep "icap txn" | grep -v "method=CONNECT" \
        | tail -2 | sed 's/^/   /'
    echo
    echo "   And the prompt itself:"
    n=$(railway logs -s "$SVC" 2>&1 | grep -c "john.doe@bankco.com")
    echo "   occurrences of the blocked email address in the log: $n"
    [ "$n" = "0" ] && echo "   Destination, rule and a reference. Never the prompt."
}

case "${1:-all}" in
    check) step_check ;;
    1) step_1 ;;
    2) step_2 ;;
    3) step_3 ;;
    4) step_4 ;;
    5) step_5 ;;
    all) step_1; step_2; step_3; step_4; step_5 ;;
    *) echo "usage: $0 [check|1|2|3|4|5]" >&2; exit 2 ;;
esac
