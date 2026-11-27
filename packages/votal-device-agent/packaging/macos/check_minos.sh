#!/bin/bash
# Fail when any Mach-O file under a directory needs a newer macOS than we
# support (docs/device-dlp-agent.md: macOS 14 or later). CI builds on a newer
# runner image than the oldest supported release, so a wheel or the frozen
# Python built for that image would otherwise ship unnoticed.
#
#   check_minos.sh <dir> [max_minos]     (default max 14.0)
set -euo pipefail
DIR="${1:?usage: check_minos.sh <dir> [max_minos]}"
MAX="${2:-14.0}"

ver_gt() {   # ver_gt A B: A > B, comparing major.minor numerically
  local a1 a2 b1 b2
  IFS=. read -r a1 a2 _ <<<"$1"; IFS=. read -r b1 b2 _ <<<"$2"
  a2=${a2:-0}; b2=${b2:-0}
  [ "$a1" -gt "$b1" ] || { [ "$a1" -eq "$b1" ] && [ "$a2" -gt "$b2" ]; }
}

checked=0
bad=0
while IFS= read -r -d '' f; do
  file -b "$f" | grep -q "Mach-O" || continue
  # LC_BUILD_VERSION prints "minos X.Y"; the older LC_VERSION_MIN_MACOSX
  # prints "version X.Y". One line per architecture slice.
  for v in $(otool -l "$f" | awk '/LC_BUILD_VERSION|LC_VERSION_MIN_MACOSX/ {cmd=$2}
                                  cmd=="LC_BUILD_VERSION" && $1=="minos" {print $2; cmd=""}
                                  cmd=="LC_VERSION_MIN_MACOSX" && $1=="version" {print $2; cmd=""}'); do
    if ver_gt "$v" "$MAX"; then
      echo "::error::${f#"$DIR"/} needs macOS $v (supported: $MAX and later)"
      bad=1
    fi
  done
  checked=$((checked + 1))
done < <(find "$DIR" -type f -print0)

[ "$checked" -gt 0 ] || { echo "::error::no Mach-O files under $DIR"; exit 1; }
if [ "$bad" -ne 0 ]; then
  echo "checked $checked Mach-O files: some need a macOS newer than $MAX"
  exit 1
fi
echo "checked $checked Mach-O files: none needs a macOS newer than $MAX"
