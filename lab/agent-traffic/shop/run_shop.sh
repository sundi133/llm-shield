#!/usr/bin/env bash
# Start (or restart) the lab shop: the app on :8200 and Nginx on :8180.
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
( cd "$HERE" && LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn app:app --port 8200 --log-level warning \
    > "$STATE/logs/app.out" 2>&1 & )

# Tier 2 collector: the tag and its beacons, routed by Nginx at /_shs/.
pkill -f "uvicorn app:app --port 8201" 2>/dev/null || true
( cd "$LAB/collector" && LAB_STATE_DIR="$STATE" nohup "$PY" -m uvicorn app:app --port 8201 --log-level warning \
    > "$STATE/logs/collector.out" 2>&1 & )

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
