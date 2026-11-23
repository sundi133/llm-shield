#!/usr/bin/env bash
# The fleet act of a customer demo (DEMO.md, act 4): a fleet with no protection,
# Shield publishes indicators to the edge, the same fleet again is challenged,
# then the report opens.
#   demo_fleet.sh <python> [label=demo-$(date +%H%M)] [agents=12]
# One kind of agent (page-text), half of them in sandbox containers: one
# controller, one fleet. 12 rather than 10 so a flaky agent can't drop the
# group under the fleet minimum of 10. Screenshot agents are measured in
# run_lab_v1.sh, not here: they behave differently and form their own group.
# Scripted agents (no model, free, about 2 minutes): AGENT_LLM_PROVIDER=scripted demo_fleet.sh ...
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PY="${1:?python with playwright}"
L="${2:-demo-$(date +%H%M)}"
N="${3:-12}"
SANDBOX=mixed
docker image inspect shield-lab-sandbox:1.65.2 >/dev/null 2>&1 || SANDBOX=local

echo "== wave 1: $N agents, one controller, each on its own home IP; nothing protects the shop"
( cd "$LAB/agents" && "$PY" fleet.py --n "$N" --concurrency 5 --stagger 10 --label "$L-wave1" \
    --observe dom --sandbox "$SANDBOX" --seed 81 )
echo "== Shield reads the logs, finds the fleet, publishes indicators to the edge"
( cd "$LAB/analysis" && "$PY" analyze.py --name "$L-wave1" --runs "$L-wave1" --publish )
echo "== wave 2: the same controller, new personas and IPs; the edge now enforces"
( cd "$LAB/agents" && "$PY" fleet.py --n "$N" --concurrency 5 --stagger 10 --label "$L-wave2" \
    --observe dom --sandbox "$SANDBOX" --seed 82 )
( cd "$LAB/analysis" && "$PY" analyze.py --name "$L-wave2" --runs "$L-wave2" --no-baseline-update \
    && "$PY" report.py --detect "$L-wave1" --enforce "$L-wave2" )
open "$LAB/state/reports/$L-wave1.html" 2>/dev/null || true
