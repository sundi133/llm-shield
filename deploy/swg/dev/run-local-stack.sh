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
    cat <<'BROWSER'

Browser test (macOS):

  1. Quit Chrome COMPLETELY (Cmd-Q, not just closing the window). `open -a`
     is ignored while Chrome is running, which is the usual reason a test
     "does not block": the tab opens in the old, unproxied window.

  2. Relaunch YOUR NORMAL profile with the PAC file:

       open -a "Google Chrome" --args \
         --proxy-pac-url="http://127.0.0.1:8081/proxy.pac"

     Your normal profile, on purpose. A fresh --user-data-dir is not signed
     into ChatGPT, so there is nothing to type a prompt into, and you end up
     back in the unproxied window without noticing.

     The PAC sends ONLY AI hosts to the proxy. Everything else, banking
     included, returns DIRECT and never reaches it.

  3. Confirm the browser is really proxied BEFORE typing anything:

       ./deploy/swg/dev/run-local-stack.sh check

  4. Then in ChatGPT, send something your policy blocks, e.g.
     "our margin on this handbag is 62% and the supplier cost is 400 AED"

BROWSER
    ;;

stop)
    $COMPOSE down >/dev/null 2>&1 || true
    [ -f "$STUB_PID_FILE" ] && kill "$(cat "$STUB_PID_FILE")" 2>/dev/null || true
    rm -f "$STUB_PID_FILE"
    pkill -f fake_shield.py 2>/dev/null || true
    echo "stopped"
    ;;

check)
    # Only recent activity. Counting the whole log is how this check reported
    # "2 CONNECT requests" that were actually curl tests from five minutes
    # earlier, which is worse than no check at all.
    WINDOW=${WINDOW:-180}
    now=$(date +%s)
    echo "== Squid CONNECTs in the last ${WINDOW}s =="
    recent=$($COMPOSE logs --since "${WINDOW}s" squid 2>&1 \
             | grep -E "CONNECT [a-z0-9.-]+:443" || true)
    n=$(printf '%s' "$recent" | grep -c . || true)
    echo "  count: $n"
    [ -n "$recent" ] && printf '%s\n' "$recent" | sed 's/^/    /' | tail -5

    if [ "$n" = "0" ]; then
        cat <<'NOPROXY'
  -> The browser is NOT sending traffic through the proxy, so nothing can be
     inspected and nothing will ever block. Two usual causes:
       * Chrome was already running, so `open -a --args` was ignored.
         Quit it completely (Cmd-Q) and relaunch.
       * You typed into a different window than the proxied one. A fresh
         --user-data-dir profile is not signed into ChatGPT; use your normal
         profile with --proxy-pac-url instead.
NOPROXY
    fi

    echo
    echo "== prompts the adapter screened in the last ${WINDOW}s =="
    $COMPOSE logs --since "${WINDOW}s" shield-icap 2>&1 \
        | grep "icap txn" | grep -v "method=CONNECT" | tail -10 \
        || echo "  none"
    ;;
*)
    echo "usage: $0 [start|stop|check]" >&2
    exit 2
    ;;
esac
