#!/usr/bin/env bash
# Before/after demo: one fleet wave unprotected, Shield publishes indicators,
# then the same fleet again with the edge enforcing them.
#
#   run_demo.sh <python> [agents_per_wave=10] [ua_mode=spoofed] [prefix=demo] [observe=dom|screen|mixed]
#
# Human sessions: browse http://localhost:8180 yourself before or during wave 1;
# sessions without X-Forwarded-For count as people.
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PY="${1:?python with playwright and anthropic}"
N="${2:-10}"
MODE="${3:-spoofed}"
P="${4:-demo}"
OBS="${5:-dom}"
SINCE="${DEMO_SINCE:-}"   # epoch: include human sessions that started before wave 1

echo "== reset: clear indicators and suspended accounts, restart the shop"
mkdir -p "$LAB/state/shield"
: > "$LAB/state/shield/sid.map"; : > "$LAB/state/shield/fp.map"; : > "$LAB/state/shield/net.map"
echo "[]" > "$LAB/state/suspended.json"
"$LAB/shop/run_shop.sh" "$PY"

echo "== wave 1: $N agents, no protection"
( cd "$LAB/agents" && "$PY" fleet.py --n "$N" --concurrency 5 --label "$P-wave1" --ua-mode "$MODE" --observe "$OBS" --seed 11 )

echo "== analyze wave 1 (SIEM rules vs Shield), publish indicators to the edge"
( cd "$LAB/analysis" && "$PY" analyze.py --name "$P-wave1" --runs "$P-wave1" ${SINCE:+--since "$SINCE"} --publish --review )

echo "== wave 2: the same fleet again, new personas and IPs, edge enforcing"
( cd "$LAB/agents" && "$PY" fleet.py --n "$N" --concurrency 5 --label "$P-wave2" --ua-mode "$MODE" --observe "$OBS" --seed 23 )

echo "== analyze wave 2"
( cd "$LAB/analysis" && "$PY" analyze.py --name "$P-wave2" --runs "$P-wave2" )

( cd "$LAB/analysis" && "$PY" report.py --detect "$P-wave1" --enforce "$P-wave2" )
