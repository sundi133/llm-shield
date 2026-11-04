#!/usr/bin/env bash
# Copy the Shield images into your own registry, then point the install files
# at it. Needs only `oc` (it uses `oc image mirror`). Images keep their digests,
# so the install files' digest pins stay valid.
#
#   ./mirror.sh to-registry <registry>         one machine reaches docker.io AND your registry
#   ./mirror.sh to-dir <dir>                   internet side: save images to <dir>, carry it in
#   ./mirror.sh from-dir <dir> <registry>      inside: push <dir> to your registry
#   ./mirror.sh set-registry <registry>        point openshift/overlays/* at <registry>
#
# <registry> is host[:port][/path], e.g. registry.example.internal/votal
# Log in to your registry first:  oc registry login --registry <host> ...
# or pass a pull secret with:     REGISTRY_CONFIG=/path/to/auth.json ./mirror.sh ...
# Self-signed registry TLS:       INSECURE=true ./mirror.sh ...
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGES="${IMAGES_FILE:-$HERE/images.txt}"

opts=(--keep-manifest-list=true)
[ -n "${REGISTRY_CONFIG:-}" ] && opts+=(--registry-config="$REGISTRY_CONFIG")
[ "${INSECURE:-false}" = "true" ] && opts+=(--insecure=true)

# logical name -> repository name in your registry
repo() { case "$1" in
  shield-admin) echo llm-shield-admin ;; shield-cloud) echo llm-shield-cloud ;;
  shield-vllm) echo llm-shield ;; redis) echo redis ;; *) echo "unknown image $1" >&2; exit 1 ;;
esac; }

each() {   # calls "$1" name source tag for every image
  grep -v '^\s*#' "$IMAGES" | grep -v '^\s*$' | while read -r name src tag; do "$1" "$name" "$src" "$tag"; done
}

usage() { sed -n '2,15p' "$0"; exit 1; }

cmd="${1:-}"; shift || true
case "$cmd" in
  to-registry)
    reg="${1:?registry}"
    _m() { echo "== $1"; oc image mirror "${opts[@]}" "$2" "$reg/$(repo "$1"):$3"; }
    each _m
    "$0" set-registry "$reg" ;;
  to-dir)
    dir="${1:?dir}"; mkdir -p "$dir"
    _m() { echo "== $1"; oc image mirror "${opts[@]}" --dir="$dir" "$2" "file://votal/$(repo "$1"):$3"; }
    each _m
    cp "$IMAGES" "$dir/images.txt"
    echo "Done. Carry $dir inside, then: ./mirror.sh from-dir $dir <registry>" ;;
  from-dir)
    dir="${1:?dir}"; reg="${2:?registry}"
    _m() { echo "== $1"; oc image mirror "${opts[@]}" --from-dir="$dir" "file://votal/$(repo "$1"):$3" "$reg/$(repo "$1"):$3"; }
    each _m
    "$0" set-registry "$reg" ;;
  set-registry)
    reg="${1:?registry}"
    for k in "$HERE"/openshift/overlays/*/kustomization.yaml; do
      for name in shield-admin shield-cloud shield-vllm redis; do
        # rewrite the newName line that follows "- name: <name>"
        awk -v n="$name" -v r="$reg/$(repo "$name")" '
          $0 ~ "^  - name: " n "$" {print; hit=1; next}
          hit && $0 ~ /^    newName: / {print "    newName: " r; hit=0; next}
          {print}' "$k" > "$k.tmp" && mv "$k.tmp" "$k"
      done
    done
    echo "openshift/overlays now pull from $reg (digests unchanged)." ;;
  *) usage ;;
esac
