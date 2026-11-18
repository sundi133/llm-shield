#!/usr/bin/env bash
# Start (or restart) the lab shop: the app on :8200 and Nginx on :8180.
# Servers are exec'd inside their background subshells so no shell is left holding the caller's output.
# Usage: run_shop.sh <python-with-fastapi>   Logs go to ../state/logs/.
#
# LAB_PRODUCT=1 runs the PRODUCT instead of the lab prototypes (rev 8 step R8):
# a lab-only Redis (127.0.0.1:6392, fresh every start), the product collector
# (:8201, python -m core.agent_detection.collector), the worker, the admin
# API (:8205, portal at http://localhost:8205/tenant) and a feed poller that
# writes the product feed into Nginx. These use the repo's Python
# (SHIELD_PY, default <repo>/.venv/bin/python).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(dirname "$HERE")"
REPO="$(cd "$LAB/../.." && pwd)"
PY="${1:-python3}"
SHIELD_PY="${SHIELD_PY:-$REPO/.venv/bin/python}"
PRODUCT="${LAB_PRODUCT:-0}"
STATE="$LAB/state"
mkdir -p "$STATE/logs" "$STATE/shield"
for f in sid.map fp.map net.map; do [ -f "$STATE/shield/$f" ] || : > "$STATE/shield/$f"; done
# Product feed maps start empty every run; the poller fills them.
printf 'map $cookie__shs $shield_agd_shs {\n    default 0;\n}\nmap "$http_user_agent|$http_sec_ch_ua|$http_sec_ch_ua_platform|$http_sec_ch_ua_mobile" $shield_agd_client {\n    default 0;\n}\n' \
  > "$STATE/shield/agd.conf"
if [ "$PRODUCT" = "1" ]; then
  echo "# product mode: canary links go to the collector" > "$STATE/shield/canary.conf"
  # Only the product feed drives the edge here: drop the lab prototype's maps
  # and its suspended accounts (the shop numbers accounts from 1 every start).
  for f in sid.map fp.map net.map; do : > "$STATE/shield/$f"; done
  echo "[]" > "$STATE/suspended.json"
else
  echo 'location ^~ /_shs/v/ { return 204; }' > "$STATE/shield/canary.conf"
fi

for p in "uvicorn app:app --port 8201" "core.agent_detection.collector" "core.agent_detection.worker" \
         "admin_app:app --host 127.0.0.1 --port 8205" "product/feed_poll.sh"; do
  pkill -f "$p" 2>/dev/null || true
done

if [ "$PRODUCT" = "1" ]; then
  [ -x "$SHIELD_PY" ] || { echo "product mode needs the repo's Python: set SHIELD_PY" >&2; exit 1; }
  docker rm -f shield-lab-redis >/dev/null 2>&1 || true
  docker run -d --name shield-lab-redis -p 127.0.0.1:6392:6379 redis:7-alpine \
    redis-server --save "" --appendonly no --maxmemory-policy noeviction >/dev/null
  for i in $(seq 1 30); do docker exec shield-lab-redis redis-cli ping >/dev/null 2>&1 && break; sleep 0.3; done
  mkdir -p "$STATE/product"
  umask 077
  cat > "$STATE/product/env" <<ENV
REDIS_URL=redis://127.0.0.1:6392/0
SHIELD_AGENT_DETECTION_HASH_SALT=$(openssl rand -hex 32)
SHIELD_AGENT_DETECTION_TRAP_SECRET=$(openssl rand -hex 32)
SHIELD_ADMIN_KEY=adm-lab-$(openssl rand -hex 16)
SHIELD_TRUST_PROXY_HEADERS=1
SHIELD_AGENT_DETECTION_CYCLE_S=3
SHIELD_AGENT_DETECTION_FLEET_S=10
SHIELD_AGENT_DETECTION_TAG_URL=http://localhost:8180/_shs
SHIELD_AGENT_DETECTION_COLLECTOR_URL=http://localhost:8180/_shs
ENV
  umask 022
  set -a; . "$STATE/product/env"; set +a
  ( cd "$REPO" && LAB_STATE_DIR="$STATE" "$SHIELD_PY" "$LAB/product/setup.py" )
  ( cd "$REPO" && exec env PORT=8201 nohup "$SHIELD_PY" -m core.agent_detection.collector \
      > "$STATE/logs/collector.out" 2>&1 < /dev/null ) &
  ( cd "$REPO" && exec nohup "$SHIELD_PY" -m core.agent_detection.worker \
      > "$STATE/logs/worker.out" 2>&1 < /dev/null ) &
  ( cd "$REPO" && exec nohup "$SHIELD_PY" -m uvicorn admin_app:app --host 127.0.0.1 --port 8205 --log-level warning \
      > "$STATE/logs/admin.out" 2>&1 < /dev/null ) &
  for i in $(seq 1 60); do curl -sf -o /dev/null http://127.0.0.1:8205/health && break; sleep 0.5; done
  ( exec nohup "$LAB/product/feed_poll.sh" "$STATE" http://127.0.0.1:8205 3 \
      > "$STATE/logs/feed_poll.err" 2>&1 < /dev/null ) &
fi

# App (restart clears its in-memory accounts and orders).
pkill -f "uvicorn app:app --port 8200" 2>/dev/null || true
( cd "$HERE" && exec env LAB_STATE_DIR="$STATE" LAB_PRODUCT="$PRODUCT" nohup "$PY" -m uvicorn app:app --port 8200 --log-level warning \
    > "$STATE/logs/app.out" 2>&1 < /dev/null ) &

# Tier 2 collector (lab mode): the lab prototype, routed by Nginx at /_shs/.
if [ "$PRODUCT" != "1" ]; then
  docker rm -f shield-lab-redis >/dev/null 2>&1 || true      # product mode's, if it ran before
  ( cd "$LAB/collector" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn app:app --port 8201 --log-level warning \
      > "$STATE/logs/collector.out" 2>&1 < /dev/null ) &
fi

# Reference Web Bot Auth verifier (spec 2.5), called by Nginx for every request.
pkill -f "uvicorn verifier:app --port 8203" 2>/dev/null || true
( cd "$LAB/edge" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn verifier:app --port 8203 --log-level warning \
    > "$STATE/logs/verifier.out" 2>&1 < /dev/null ) &

# Decoys (spec 2.6): generated per deployment from state/decoy_seed; Nginx routes their paths here.
# Product mode: product/setup.py already wrote decoys.conf from the PRODUCT's
# edge rules (paths forwarded to the product collector), so the lab service stays off.
pkill -f "uvicorn decoys:app --port 8204" 2>/dev/null || true
if [ "$PRODUCT" != "1" ]; then
  ( cd "$LAB/edge" && LAB_STATE_DIR="$STATE" "$PY" decoys.py --write-nginx "$STATE/shield/decoys.conf" )
  ( cd "$LAB/edge" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn decoys:app --port 8204 --log-level warning \
      > "$STATE/logs/decoys.out" 2>&1 < /dev/null ) &
fi

# Nginx (the "edge").
docker rm -f shield-lab-nginx >/dev/null 2>&1 || true
docker run -d --name shield-lab-nginx -p 8180:8180 \
  --add-host host.docker.internal:host-gateway \
  -v "$HERE/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$STATE/shield:/etc/nginx/shield:ro" \
  -v "$STATE/logs:/var/log/shop" \
  nginx:1.27-alpine >/dev/null

for i in $(seq 1 30); do
  curl -sf -o /dev/null http://localhost:8180/ && { echo "shop up: http://localhost:8180"; exit 0; }
  sleep 0.5
done
echo "shop did not come up; see $STATE/logs/app.out and: docker logs shield-lab-nginx" >&2
exit 1
