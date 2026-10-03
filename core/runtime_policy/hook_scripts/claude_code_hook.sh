#!/bin/sh
# Votal Shield fail-closed hook for Claude Code (PreToolUse).
# Spec: docs/specs/agent-hook-adapter.md, section 4.3.
#
# Claude Code runs this before every matched tool call and pipes the call's
# JSON on stdin. It is forwarded to Shield (POST /v1/shield/hooks/claude-code)
# and Shield's answer is turned into Claude Code's:
#
#   allow  ({})           -> exit 0, no output
#   deny                  -> exit 2, reason on stderr (Claude Code shows it)
#   ask                   -> exit 0, an "ask" decision on stdout
#   anything else         -> exit 2
#
# Claude Code lets a call through when a hook exits with any code other than
# 2 (checked in task 0). So EVERY failure here exits 2: no config, no curl,
# Shield unreachable or slow, any non-200, an answer that is not one of the
# three above. Deploy it with "|| exit 2" after the command, so a missing or
# unrunnable script denies too:
#
#   "command": "/bin/sh '/Library/Application Support/Votal/claude_code_hook.sh' || exit 2"
#
# Settings come from a root-owned config file, never from the environment
# (Claude Code's environment is the user's). Default locations:
#   macOS  /Library/Application Support/Votal/hook.conf
#   Linux  /etc/votal/hook.conf
# or --config <path> as the first argument (fixed by the admin in the
# managed setting). Format, one per line, # for comments:
#   SHIELD_URL=https://api.guardrails.votal.ai
#   SHIELD_API_KEY=<tenant key with the runtime scope>
#   SHIELD_AGENT=claude-code          (optional, default claude-code)
#   SHIELD_TIMEOUT=4                  (optional, seconds, 1 to 30; keep it
#                                      below the hook's timeout in settings)
#
# Needs only sh, curl, sed, tr and mktemp: no Python, which on a Mac without
# developer tools is a stub that fails, and would fail open.

deny() {
    printf 'Blocked by Votal Shield: %s\n' "$1" >&2
    exit 2
}

CONF=""
if [ "${1:-}" = "--config" ]; then
    CONF="${2:-}"
elif [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    CONF="/Library/Application Support/Votal/hook.conf"
else
    CONF="/etc/votal/hook.conf"
fi
[ -n "$CONF" ] && [ -r "$CONF" ] || deny "hook config $CONF is missing or unreadable, so this action is not allowed"

# Parse KEY=value lines; never source the file.
URL="" KEY="" AGENT="claude-code" TIMEOUT="4"
while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | tr -d '\r')
    case "$line" in
        ''|'#'*) continue ;;
    esac
    k=${line%%=*}
    v=${line#*=}
    [ "$k" = "$line" ] && continue
    k=$(printf '%s' "$k" | tr -d ' \t')
    v=$(printf '%s' "$v" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
                               -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")
    case "$k" in
        SHIELD_URL) URL=$v ;;
        SHIELD_API_KEY) KEY=$v ;;
        SHIELD_AGENT) AGENT=$v ;;
        SHIELD_TIMEOUT) TIMEOUT=$v ;;
    esac
done < "$CONF"

[ -n "$URL" ] || deny "SHIELD_URL is not set in $CONF, so this action is not allowed"
[ -n "$KEY" ] || deny "SHIELD_API_KEY is not set in $CONF, so this action is not allowed"
case "$URL" in
    https://*|http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*) ;;
    *) deny "SHIELD_URL must be https (or a localhost address for testing)" ;;
esac
case "$TIMEOUT" in
    ''|*[!0-9]*) TIMEOUT=4 ;;
esac
[ "$TIMEOUT" -ge 1 ] 2>/dev/null && [ "$TIMEOUT" -le 30 ] || TIMEOUT=4
command -v curl >/dev/null 2>&1 || deny "curl is not installed, so Shield cannot be asked and this action is not allowed"

ENDPOINT="${URL%/}/v1/shield/hooks/claude-code"
USER_NAME=${USER:-$(id -un 2>/dev/null)}
HOST_NAME=$(hostname 2>/dev/null)

# Headers go through a private file (curl -H @file) so the key never appears
# in the process list.
BODY=$(mktemp "${TMPDIR:-/tmp}/votal-hook.XXXXXX") || deny "could not create a temporary file"
HDRS=$(mktemp "${TMPDIR:-/tmp}/votal-hook.XXXXXX") || { rm -f "$BODY"; deny "could not create a temporary file"; }
trap 'rm -f "$BODY" "$HDRS"' EXIT HUP INT TERM
chmod 600 "$HDRS" "$BODY"
{
    printf 'X-API-Key: %s\n' "$KEY"
    printf 'X-Agent-Key: %s\n' "$AGENT"
    printf 'X-Shield-User: %s\n' "$USER_NAME"
    printf 'X-Device-Id: %s\n' "$HOST_NAME"
    printf 'Content-Type: application/json\n'
} > "$HDRS"

STATUS=$(curl -sS --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
              -H @"$HDRS" --data-binary @- -o "$BODY" -w '%{http_code}' \
              "$ENDPOINT" 2>/dev/null) \
    || deny "Shield could not be reached at $URL, so this action is not allowed"
[ "$STATUS" = "200" ] || deny "Shield answered HTTP $STATUS, so this action is not allowed"

ANSWER=$(tr -d '\r\n' < "$BODY")
COMPACT=$(printf '%s' "$ANSWER" | tr -d ' \t')

# The reason Shield gave, made safe to print and to put back into JSON.
reason() {
    printf '%s' "$ANSWER" \
        | sed -n -E 's/.*"permissionDecisionReason"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\1/p' \
        | sed -e 's/\\"/'"'"'/g' -e 's/\\[nrt]/ /g' -e 's/\\//g' -e 's/"//g' \
        | tr -d '\000-\037' | cut -c1-500
}

case "$COMPACT" in
    '{}')
        exit 0 ;;
    *'"permissionDecision":"deny"'*)
        why=$(reason)
        why=${why#Blocked by Votal Shield: }
        deny "${why:-denied by policy}" ;;
    *'"permissionDecision":"ask"'*)
        why=$(reason)
        printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}\n' \
            "${why:-Votal Shield: this action needs your confirmation}"
        exit 0 ;;
esac
deny "Shield's answer was not understood, so this action is not allowed"
