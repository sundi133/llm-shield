#!/usr/bin/env bash
# The fleet demo on Shield's PRODUCT code (rev 8 step R8): the product tag on
# the lab shop, the product collector, worker, admin API and feed, and the
# lab Nginx as the customer's edge polling that feed.
#   demo_product.sh <lab python> [label=prod-$(date +%H%M)] [agents=12]
# Scripted agents (no model, free): AGENT_LLM_PROVIDER=scripted demo_product.sh ...
# Needs Docker, and the repo's Python at <repo>/.venv/bin/python (or SHIELD_PY).
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PY="${1:?lab python with playwright}"
L="${2:-prod-$(date +%H%M)}"
N="${3:-12}"
SANDBOX=mixed
docker image inspect shield-lab-sandbox:1.65.2 >/dev/null 2>&1 || SANDBOX=local

echo "== starting the shop in product mode (fresh lab Redis, product collector, worker, admin API, feed poller)"
LAB_PRODUCT=1 "$LAB/shop/run_shop.sh" "$PY"
K="$(cat "$LAB/state/product/admin_key")"
api() { curl -sf -H "X-API-Key: $K" "http://127.0.0.1:8205$1" "${@:2}"; }

echo "== wave 1: $N agents, one controller, each on its own home IP; Shield is in watch mode"
( cd "$LAB/agents" && "$PY" fleet.py --n "$N" --concurrency 5 --stagger 10 --label "$L-wave1" \
    --observe dom --sandbox "$SANDBOX" --seed 81 )

echo "== decoys: 3 agents told to look around find the hidden API in robots.txt and follow its instruction"
( cd "$LAB/agents" && "$PY" fleet.py --n 3 --concurrency 3 --stagger 2 --label "$L-explore" \
    --task explore --observe dom --sandbox local --seed 91 )

echo "== waiting for the worker to link the fleet"
for i in $(seq 1 40); do
  n="$(api /v1/agent-detection/fleets | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["fleets"]))')"
  [ "$n" -ge 1 ] && break; sleep 3
done
echo "   fleets found: $n"

echo "== switching session cookie and browser signature indicators to enforce"
api /v1/agent-detection/enforcement -X PUT -H 'Content-Type: application/json' \
  -d '{"modes":{"shs":"enforce","client":"enforce"}}' >/dev/null
for i in $(seq 1 20); do
  grep -q ' 1;$' "$LAB/state/shield/agd.conf" && break; sleep 1.5
done
echo "   the edge loaded $(grep -c ' 1;$' "$LAB/state/shield/agd.conf") indicators from the product feed"

echo "== wave 2: the same controller, new personas and IPs; the edge enforces"
( cd "$LAB/agents" && "$PY" fleet.py --n "$N" --concurrency 5 --stagger 10 --label "$L-wave2" \
    --observe dom --sandbox "$SANDBOX" --seed 82 )
sleep 8
python3 "$LAB/product/summary.py" "$L"
echo
echo "Portal: http://localhost:8205/tenant (sign in with the API key in state/product/admin_key)"
