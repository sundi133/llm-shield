#!/usr/bin/env bash
# Live evidence feed for a demo: every page request as the edge logs it, with
# trap hits, decoy touches and edge challenges called out. Needs jq.
#   watch_evidence.sh
LAB="$(cd "$(dirname "$0")" && pwd)"
tail -n0 -F "$LAB/state/logs/access.jsonl" | jq --unbuffered -r '
  select((.uri | test("^/(static/|_shs/b$|_shs/shs.js|favicon)")) | not)
  | "\(.ts[11:19])  \(.ip | .[0:15] | . + (" " * (15 - length)))  \(.method) \(.uri)  \(.status)"
    + (if (.trip // "") != "" then "   << TRAP " + .trip else "" end)
    + (if (.uri | startswith("/_shs/v/")) then "   << TRAP LINK" else "" end)
    + (if (.decoy // "") != "" then "   << DECOY " + .decoy else "" end)
    + (if (.wba // "") != "" and .wba != "none" then "   << SIGNED " + .wba else "" end)
    + (if .enforced == "1" then "   << CHALLENGED" else "" end)'
