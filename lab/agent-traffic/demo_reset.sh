#!/usr/bin/env bash
# Reset the lab between customer demos: clear published indicators and
# suspended accounts, restart the shop (its accounts and orders are in memory).
#   demo_reset.sh <python>
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PY="${1:?python with playwright}"
mkdir -p "$LAB/state/shield"
: > "$LAB/state/shield/sid.map"; : > "$LAB/state/shield/fp.map"; : > "$LAB/state/shield/net.map"
echo "[]" > "$LAB/state/suspended.json"
"$LAB/shop/run_shop.sh" "$PY"
echo "decoys this deployment: $(grep -oE 'location (= |\^~ )[^ ]+' "$LAB/state/shield/decoys.conf" | awk '{print $3}' | grep -vE '^/(robots.txt|static/app.js)$' | tr '\n' ' ')"
