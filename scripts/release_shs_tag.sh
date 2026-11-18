#!/usr/bin/env bash
# Publish the AI agent detection tag to a public GCS bucket served by Cloud CDN
# (docs/specs/agent-impersonation-defense.md section 11, rev 8).
#
#   scripts/release_shs_tag.sh <bucket> <tag-host> [--dry-run]
#   e.g. scripts/release_shs_tag.sh votal-shs-tag tag.votal.ai
#
# Uploads static/agent-detection/shs.js as shs-<version>.js, never overwriting
# a published version (the upload is conditional on the object not existing),
# with Content-Type application/javascript and a one-year immutable cache. Then
# it fetches the file back from https://<tag-host>/ and checks the bytes and the
# CORS header, and prints the install snippet with its SRI hash.
#
# Runs with YOUR gcloud login; no credentials live in the repo or CI.
#
# One-time bucket setup (yours to run, once):
#   gcloud storage buckets create gs://BUCKET --uniform-bucket-level-access
#   gcloud storage buckets update gs://BUCKET --versioning
#   gcloud storage buckets add-iam-policy-binding gs://BUCKET --member=allUsers --role=roles/storage.objectViewer
#   gcloud storage buckets update gs://BUCKET --cors-file=scripts/shs_tag_cors.json
# then a Cloud CDN backend bucket and an HTTPS load balancer on <tag-host>.
# The CORS rule matters: browsers check SRI on a cross-origin script only when
# the response carries Access-Control-Allow-Origin.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/static/agent-detection/shs.js"
BUCKET="${1:?usage: release_shs_tag.sh <bucket> <tag-host> [--dry-run]}"
HOST="${2:?usage: release_shs_tag.sh <bucket> <tag-host> [--dry-run]}"
DRY="${3:-}"
BUCKET="${BUCKET#gs://}"; BUCKET="${BUCKET%/}"
HOST="${HOST#https://}"; HOST="${HOST%/}"

VERSION="$(head -c 400 "$SRC" | grep -oE '@version [0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d' ' -f2)"
[ -n "$VERSION" ] || { echo "no @version x.y.z in the first comment of $SRC" >&2; exit 2; }
SIZE="$(wc -c < "$SRC" | tr -d ' ')"
[ "$SIZE" -le 15360 ] || { echo "shs.js is $SIZE bytes, over the 15 KB budget" >&2; exit 2; }
NAME="shs-$VERSION.js"
SRI="sha384-$(openssl dgst -sha384 -binary "$SRC" | openssl base64 -A)"
URL="https://$HOST/$NAME"

run() { if [ "$DRY" = "--dry-run" ]; then echo "+ $*"; else "$@"; fi; }

echo "== shs.js $VERSION ($SIZE bytes) -> gs://$BUCKET/$NAME"
if [ "$DRY" != "--dry-run" ] && gcloud storage objects describe "gs://$BUCKET/$NAME" >/dev/null 2>&1; then
  echo "gs://$BUCKET/$NAME already exists: published versions are never overwritten." >&2
  echo "Bump @version in $SRC for a new release." >&2
  exit 3
fi
run gcloud storage cp "$SRC" "gs://$BUCKET/$NAME" \
  --if-generation-match=0 \
  --content-type=application/javascript \
  --cache-control="public, max-age=31536000, immutable"

if [ "$DRY" != "--dry-run" ]; then
  echo "== checking $URL"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  if curl -fsS -D "$TMP/h" -o "$TMP/b" -H "Origin: https://example.com" "$URL"; then
    if cmp -s "$TMP/b" "$SRC"; then echo "   bytes match"; else echo "   WARNING: served bytes differ (CDN still caching an old object?)" >&2; fi
    grep -qi '^access-control-allow-origin:' "$TMP/h" \
      && echo "   CORS header present" \
      || echo "   WARNING: no Access-Control-Allow-Origin; SRI will block the tag. Set the bucket CORS (see the header of this script)." >&2
  else
    echo "   WARNING: $URL not reachable yet (CDN or DNS); the object is uploaded." >&2
  fi
fi

cat <<EOF

Install snippet (the site key comes from the portal; data-collector only when
the collector isn't routed at /_shs on the customer's site):

<script src="$URL" integrity="$SRI" crossorigin="anonymous" data-site="SITE_KEY" async></script>
EOF
