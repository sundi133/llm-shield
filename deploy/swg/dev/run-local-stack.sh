#!/usr/bin/env bash
# Bring up the whole Mode A stack against a local stub, in enforce mode.
#
#   ./deploy/swg/dev/run-local-stack.sh          start
#   ./deploy/swg/dev/run-local-stack.sh stop     stop everything
#   ./deploy/swg/dev/run-local-stack.sh check    is traffic actually reaching it
#
# Why a script rather than "just set two env vars": passing SHIELD_API_BASE and
# SHIELD_ICAP_MODE inline to one `docker compose up` binds them to that
# invocation only. Any later `up -d`, or a container restart, silently reverts
# to the production defaults -- which means enforce becomes monitor and the
# rules go to zero, and the stack looks up while blocking nothing. That has
# already caused one confusing test run.
set -euo pipefail

cd "$(dirname "$0")/../../.."
COMPOSE="docker compose -f docker-compose.swg.yml"
STUB_PID_FILE=/tmp/shield-fake-shield.pid
PY="${PY:-.venv/bin/python}"

start_stub() {
    if lsof -iTCP:9099 -sTCP:LISTEN >/dev/null 2>&1; then
        echo "  stub already listening on 9099"
        return
    fi
    FAKE_SHIELD_HOST=0.0.0.0 nohup "$PY" -u deploy/swg/dev/fake_shield.py \
        > /tmp/shield-fake-shield.log 2>&1 &
    echo $! > "$STUB_PID_FILE"
    sleep 1
    echo "  stub started (log: /tmp/shield-fake-shield.log)"
}

case "${1:-start}" in
start)
    echo "== stub Shield =="
    start_stub

    echo "== stack =="
    SHIELD_API_BASE=http://host.docker.internal:9099 \
    SHIELD_ICAP_MODE=enforce \
        $COMPOSE up -d --build >/dev/null
    sleep 6

    echo "== health =="
    curl -s -m 10 http://127.0.0.1:8081/healthz | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
print("  mode=%s  rules=%s  enforcing=%s" % (d["mode"], d["rules"], d["enforcing_anything"]))
if d.get("policy_error"):
    print("  POLICY ERROR: %s" % d["policy_error"])
if not d["enforcing_anything"]:
    print("  WARNING: zero rules loaded. Nothing will be blocked.")
    sys.exit(1)
'
    echo
    echo "Browser test (macOS). Chrome must NOT already be running with this profile:"
    echo "  open -a 'Google Chrome' --args \\"
    echo "    --proxy-server='http://127.0.0.1:3128' \\"
    echo "    --user-data-dir=/tmp/shield-test-profile"
    echo
    echo "Then run '$0 check' to confirm traffic is actually reaching the proxy."
    ;;

stop)
    $COMPOSE down >/dev/null 2>&1 || true
    [ -f "$STUB_PID_FILE" ] && kill "$(cat "$STUB_PID_FILE")" 2>/dev/null || true
    rm -f "$STUB_PID_FILE"
    pkill -f fake_shield.py 2>/dev/null || true
    echo "stopped"
    ;;

check)
    echo "== requests Squid has proxied =="
    n=$($COMPOSE logs squid 2>&1 | grep -cE "CONNECT [a-z0-9.-]+:443" || true)
    echo "  CONNECT requests seen: $n"
    if [ "$n" = "0" ]; then
        echo "  -> The browser is NOT using the proxy. Nothing can be inspected."
        echo "     Most common cause: Chrome was already running, so --args was"
        echo "     ignored and the existing unproxied window opened the tab."
        echo "     Quit Chrome entirely, then relaunch with the flags above."
    fi
    echo
    echo "== prompts the adapter screened =="
    $COMPOSE logs shield-icap 2>&1 | grep "icap txn" | grep -v "method=CONNECT" | tail -10 \
        || echo "  none yet"
    ;;
*)
    echo "usage: $0 [start|stop|check]" >&2
    exit 2
    ;;
esac
