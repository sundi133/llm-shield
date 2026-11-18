#!/usr/bin/env bash
# The lab edge's feed poller (product mode): pull the PRODUCT indicator feed
# every few seconds with the feed token, write the Nginx maps, reload Nginx.
# What a customer's cron job or CDN integration does, at a faster cadence.
#   feed_poll.sh <state dir> [admin url=http://127.0.0.1:8205] [every=3]
set -uo pipefail
STATE="${1:?state dir}"
URL="${2:-http://127.0.0.1:8205}"
EVERY="${3:-3}"
TOKEN="$(cat "$STATE/product/feed_token")"
OUT="$STATE/shield/agd.conf"
ETAG=""
while true; do
  HDRS="$(mktemp)"; BODY="$(mktemp)"
  CODE="$(curl -s -o "$BODY" -D "$HDRS" -w '%{http_code}' -H "X-Shield-Feed-Token: $TOKEN" \
          ${ETAG:+-H "If-None-Match: $ETAG"} "$URL/v1/agent-detection/indicators?format=nginx")"
  if [ "$CODE" = "200" ] && grep -q '^map ' "$BODY"; then
    ETAG="$(grep -i '^etag:' "$HDRS" | cut -d' ' -f2 | tr -d '\r')"
    if ! cmp -s "$BODY" "$OUT"; then
      cp "$BODY" "$OUT"
      docker exec shield-lab-nginx nginx -s reload >/dev/null 2>&1 || true
      echo "$(date +%T) feed: $(grep -c ' 1;$' "$OUT") indicators" >> "$STATE/logs/feed_poll.out"
    fi
  fi
  rm -f "$HDRS" "$BODY"
  sleep "$EVERY"
done
