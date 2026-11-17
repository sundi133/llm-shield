#!/usr/bin/env bash
# Lab v1 (spec task 0b): tier 2 measured on one set of sessions.
#
#   run_lab_v1.sh <python> [agents=10] [prefix=v1]
#
# 1. a shop fleet: half page-text agents, half screenshot agents; half on this
#    machine, half in sandbox containers from one image (build it first, see README)
# 2. an explore wave ("find anything useful") for decoys
# 3. declared agents: 2 signed by an allowed operator, 2 by an unknown one,
#    2 forging the allowed operator
# then one analysis over everything, scored three ways (SIEM rules, Shield on
# logs, Shield with the tag), and the report.
#
# Human sessions: browse http://localhost:8180 yourself (5 to 10 sessions,
# on your own devices) before or during the run, and pass DEMO_SINCE=<epoch>
# if you browsed before it started.
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PY="${1:?python with playwright and anthropic}"
N="${2:-10}"
P="${3:-v1}"
SINCE="${DEMO_SINCE:-}"
X=$(( (N + 1) / 2 ))

docker image inspect shield-lab-sandbox:1.65.2 >/dev/null 2>&1 || {
  echo "build the sandbox image first: docker build -t shield-lab-sandbox:1.65.2 $LAB/sandbox" >&2; exit 1; }

echo "== reset: clear indicators and suspended accounts, restart the shop"
mkdir -p "$LAB/state/shield"
: > "$LAB/state/shield/sid.map"; : > "$LAB/state/shield/fp.map"; : > "$LAB/state/shield/net.map"
echo "[]" > "$LAB/state/suspended.json"
"$LAB/shop/run_shop.sh" "$PY"

cd "$LAB/agents"
echo "== 1. shop fleet: $N agents, mixed page-text and screenshot, mixed local and sandbox"
"$PY" fleet.py --n "$N" --concurrency 5 --label "$P-shop" --observe mixed --sandbox mixed --seed 51
echo "== 2. explore wave: $X agents"
"$PY" fleet.py --n "$X" --concurrency 5 --label "$P-explore" --task explore --observe mixed --seed 52
echo "== 3. declared agents"
"$PY" fleet.py --n 2 --label "$P-allowed" --declare allowed --seed 53
"$PY" fleet.py --n 2 --label "$P-unknown" --declare unknown --seed 54
"$PY" fleet.py --n 2 --label "$P-forged" --declare forged --seed 55

cd "$LAB/analysis"
echo "== analyze all of it"
"$PY" analyze.py --name "$P" --runs "$P-shop" "$P-explore" "$P-allowed" "$P-unknown" "$P-forged" \
  ${SINCE:+--since "$SINCE"} --review
"$PY" report.py --detect "$P"
