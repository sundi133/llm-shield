#!/usr/bin/env bash
# Start (or restart) the lab shop: the app on :8200 and Nginx on :8180.
# Servers are exec'd inside their background subshells so no shell is left holding the caller's output.
# Usage: run_shop.sh <python-with-fastapi>   Logs go to ../state/logs/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(dirname "$HERE")"
PY="${1:-python3}"
STATE="$LAB/state"
mkdir -p "$STATE/logs" "$STATE/shield"
for f in sid.map fp.map net.map; do [ -f "$STATE/shield/$f" ] || : > "$STATE/shield/$f"; done

# App (restart clears its in-memory accounts and orders).
pkill -f "uvicorn app:app --port 8200" 2>/dev/null || true
( cd "$HERE" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn app:app --port 8200 --log-level warning \
    > "$STATE/logs/app.out" 2>&1 < /dev/null ) &

# Tier 2 collector: the tag and its beacons, routed by Nginx at /_shs/.
pkill -f "uvicorn app:app --port 8201" 2>/dev/null || true
( cd "$LAB/collector" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn app:app --port 8201 --log-level warning \
    > "$STATE/logs/collector.out" 2>&1 < /dev/null ) &

# Reference Web Bot Auth verifier (spec 2.5), called by Nginx for every request.
pkill -f "uvicorn verifier:app --port 8203" 2>/dev/null || true
( cd "$LAB/edge" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn verifier:app --port 8203 --log-level warning \
    > "$STATE/logs/verifier.out" 2>&1 < /dev/null ) &

# Decoys (spec 2.6): generated per deployment from state/decoy_seed; Nginx routes their paths here.
pkill -f "uvicorn decoys:app --port 8204" 2>/dev/null || true
( cd "$LAB/edge" && LAB_STATE_DIR="$STATE" "$PY" decoys.py --write-nginx "$STATE/shield/decoys.conf" )
( cd "$LAB/edge" && exec env LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn decoys:app --port 8204 --log-level warning \
    > "$STATE/logs/decoys.out" 2>&1 < /dev/null ) &

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
