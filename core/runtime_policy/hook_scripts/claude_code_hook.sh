#!/bin/sh
# Votal Shield fail-closed hook for Claude Code and Codex (PreToolUse and
# PostToolUse).
# Specs: docs/specs/agent-hook-adapter.md section 4.3 (before a call);
#        docs/specs/agent-hooks-tool-policies.md section 4.3 (after a call, Codex).
#
# Arguments, in any order:
#   --config <path>                  the config file (see below)
#   --target claude-code | codex     whose hook this is (default claude-code).
#                                    Codex has no HTTP hooks, so it always uses
#                                    this script; it posts to
#                                    /v1/shield/hooks/codex.
#
# AFTER a call (PostToolUse) Shield's answer is passed through unchanged: the
# redacted result, or a note that it was withheld. When Shield cannot answer,
# the result goes through by default (withholding every result during an
# outage stops all work); ON_UNREACHABLE_RESULT=withhold withholds instead.
# Everything below about exit 2 is about BEFORE a call.
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
# Settings come from a config file, never from the environment (Claude Code's
# environment is the user's). Which file (docs/specs/hooks-plugin-production.md
# section 5):
#   1. The managed file, when it exists. It wins over --config, so neither a
#      plugin nor a settings file can point the hook somewhere else:
#        macOS  /Library/Application Support/Votal/hook.conf
#        Linux  /etc/votal/hook.conf
#      It and its folder must be owned by root and writable by no one else;
#      otherwise every call is refused.
#   2. Otherwise --config <path>.
#   3. Otherwise ~/.votal/hook.conf (a self-install, which the user can edit).
# The hook runs MANAGED when the file it read is owned by root and writable by
# no one else, wherever it is; then SHIELD_URL may not be a localhost address
# (only the Votal device agent's, with its local secret). Shield is told the
# mode, the version and the OS, so an admin can see which laptops are managed.
# Format, one per line, # for comments:
#   SHIELD_URL=https://api.guardrails.votal.ai
#   SHIELD_API_KEY=<tenant key with the runtime scope>
#   SHIELD_AGENT=claude-code          (optional, default claude-code)
#   SHIELD_TIMEOUT=4                  (optional, seconds, 1 to 30; keep it
#                                      below the hook's timeout in settings)
#   ON_UNREACHABLE=deny               (optional: deny, the default, or allow;
#                                      what a FAILURE means. Shield's own
#                                      denials always deny.)
#   ON_UNREACHABLE_RESULT=allow       (optional: allow, the default, or withhold;
#                                      what a failure means AFTER a call)
#   ON_UNREACHABLE_PROMPT=allow       (optional: allow, the default, or block;
#                                      what a failure means for a submitted
#                                      prompt, UserPromptSubmit;
#                                      docs/specs/agent-hooks-prompt-check.md)
#   SHIELD_LOCAL_SECRET_FILE=<path>   (set by the Votal device agent: ask the
#                                      agent on 127.0.0.1 with its local secret
#                                      instead of Shield with a tenant key;
#                                      docs/specs/claude-code-fleet-rollout.md)
#
# Needs only sh, curl, sed, tr and mktemp: no Python, which on a Mac without
# developer tools is a stub that fails, and would fail open.

deny() {
    printf 'Blocked by Votal Shield: %s\n' "$1" >&2
    exit 2
}

# A failure (no answer, bad answer, bad setup): denied unless the config says
# ON_UNREACHABLE=allow. Shield's own denials go through deny(), never here.
# After a call (EVENT=PostToolUse) a failure follows ON_UNREACHABLE_RESULT; for
# a submitted prompt (EVENT=UserPromptSubmit) it follows ON_UNREACHABLE_PROMPT.
ON_UNREACHABLE=deny
ON_UNREACHABLE_RESULT=allow
ON_UNREACHABLE_PROMPT=allow
EVENT=PreToolUse
TARGET=claude-code
fail() {
    if [ "$EVENT" = "UserPromptSubmit" ]; then
        # The same answer in both agents: the prompt is refused before the
        # model runs. Exit 0 either way: exit 2 would also refuse it, but with
        # the internal failure as the message.
        [ "$ON_UNREACHABLE_PROMPT" = "block" ] && \
            printf '{"decision":"block","reason":"Votal Shield could not check this request"}\n'
        exit 0
    fi
    if [ "$EVENT" = "PostToolUse" ]; then
        if [ "$ON_UNREACHABLE_RESULT" = "withhold" ]; then
            if [ "$TARGET" = "codex" ]; then
                printf '{"decision":"block","reason":"[Shield withheld this result: Shield could not check it]"}\n'
            else
                printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"[Shield withheld this result: Shield could not check it]"}}\n'
            fi
        fi
        exit 0
    fi
    if [ "$ON_UNREACHABLE" = "allow" ]; then
        printf 'Votal Shield: %s; allowed, because this fleet lets actions through when Shield cannot answer\n' "${1%, so this action is not allowed}" >&2
        exit 0
    fi
    deny "$1"
}

CONF=""
while [ $# -gt 0 ]; do
    case "$1" in
        # Never "shift 2" past the end: in some shells that is fatal, and an
        # exit code other than 2 lets the call through.
        --config) CONF="${2:-}"; shift; [ $# -gt 0 ] && shift ;;
        --target) TARGET="${2:-}"; shift; [ $# -gt 0 ] && shift ;;
        *) shift ;;
    esac
done
case "$TARGET" in
    claude-code|codex) ;;
    *) deny "unknown --target '$TARGET' (claude-code or codex), so this action is not allowed" ;;
esac

# Windows: Claude Code runs a hook command through Git Bash, so a plugin's
# "/bin/sh .../claude_code_hook.sh" lands here. Hand over to the PowerShell
# twin beside this script, which knows Windows owners and ACLs: the same
# arguments, the same answers, the same exit codes
# (docs/specs/hooks-plugin-production.md task 4). stdin passes through exec.
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
        winpath() { cygpath -w "$1" 2>/dev/null || printf '%s' "$1"; }
        case "$0" in
            */*) PS1="${0%/*}/claude_code_hook.ps1" ;;
            *\\*) PS1="${0%\\*}\\claude_code_hook.ps1" ;;
            *) PS1=claude_code_hook.ps1 ;;
        esac
        [ -f "$PS1" ] || deny "the Windows hook claude_code_hook.ps1 is missing beside $0, so this action is not allowed"
        if [ -n "$CONF" ]; then
            exec powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
                -File "$(winpath "$PS1")" -Target "$TARGET" -Config "$(winpath "$CONF")"
        fi
        exec powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
            -File "$(winpath "$PS1")" -Target "$TARGET"
        ;;
esac

HOOK_VERSION=1.2.0   # the plugin's version (plugin.json); tests pin them together
MANAGED_UID=0
MANAGED_CONF_DARWIN="/Library/Application Support/Votal/hook.conf"
MANAGED_CONF_OTHER="/etc/votal/hook.conf"
if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    HOOK_OS=darwin MANAGED_CONF=$MANAGED_CONF_DARWIN
else
    HOOK_OS=linux MANAGED_CONF=$MANAGED_CONF_OTHER
fi

# The file and its folder are owned by MANAGED_UID and writable by no one else
# (ls -n gives the numeric owner; -L judges what a symlink points at).
managed_ok() {
    for p in "$1" "${1%/*}"; do
        line=$(ls -ldnL "$p" 2>/dev/null) || return 1
        set -- $line
        [ "$3" = "$MANAGED_UID" ] || return 1
        case "$1" in
            ?????w*|????????w*) return 1 ;;
        esac
    done
    return 0
}

# The event comes in on stdin with the call; buffer it to read the event name
# (the body is forwarded unchanged). Before the config, so that a broken setup
# after a call is a PostToolUse failure, not a PreToolUse one.
IN=$(mktemp "${TMPDIR:-/tmp}/votal-hook.XXXXXX") || deny "could not create a temporary file"
chmod 600 "$IN"
cat > "$IN"
case "$(tr -d ' \t\r\n' < "$IN")" in
    *'"hook_event_name":"PostToolUse"'*) EVENT=PostToolUse ;;
    *'"hook_event_name":"UserPromptSubmit"'*) EVENT=UserPromptSubmit ;;
esac
MODE=user
if [ -e "$MANAGED_CONF" ]; then
    CONF=$MANAGED_CONF
    managed_ok "$CONF" || fail "$CONF and its folder must be owned by root and writable by no one else, so this action is not allowed"
    MODE=managed
else
    [ -n "$CONF" ] || CONF="${HOME:-}/.votal/hook.conf"
    [ -r "$CONF" ] && managed_ok "$CONF" && MODE=managed
fi
[ -n "$CONF" ] && [ -r "$CONF" ] || fail "hook config $CONF is missing or unreadable, so this action is not allowed"

# Parse KEY=value lines; never source the file.
URL="" KEY="" AGENT="claude-code" TIMEOUT="4" SECRET_FILE="" UNREACH="deny"
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
        SHIELD_LOCAL_SECRET_FILE) SECRET_FILE=$v ;;
        ON_UNREACHABLE) UNREACH=$v ;;
        ON_UNREACHABLE_RESULT) [ "$v" = "withhold" ] && ON_UNREACHABLE_RESULT=withhold ;;
        ON_UNREACHABLE_PROMPT) [ "$v" = "block" ] && ON_UNREACHABLE_PROMPT=block ;;
    esac
done < "$CONF"
[ "$UNREACH" = "allow" ] && ON_UNREACHABLE=allow

[ -n "$URL" ] || fail "SHIELD_URL is not set in $CONF, so this action is not allowed"
if [ -n "$SECRET_FILE" ]; then
    # The Votal device agent on this laptop: loopback only, its local secret.
    case "$URL" in
        http://127.0.0.1:*|http://localhost:*) ;;
        *) fail "SHIELD_URL must be the local agent (http://127.0.0.1:<port>) when SHIELD_LOCAL_SECRET_FILE is set" ;;
    esac
    SECRET=$(tr -d '\r\n' < "$SECRET_FILE" 2>/dev/null)
    [ -n "$SECRET" ] || fail "the Votal agent's local secret could not be read, so this action is not allowed"
else
    [ -n "$KEY" ] || fail "SHIELD_API_KEY is not set in $CONF, so this action is not allowed"
    case "$URL" in
        https://*) ;;
        http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*)
            # A local stand-in answering {} would allow everything: testing only.
            [ "$MODE" = "user" ] || fail "SHIELD_URL must be https in a managed install, so this action is not allowed" ;;
        *) fail "SHIELD_URL must be https (or a localhost address for testing)" ;;
    esac
fi
case "$TIMEOUT" in
    ''|*[!0-9]*) TIMEOUT=4 ;;
esac
[ "$TIMEOUT" -ge 1 ] 2>/dev/null && [ "$TIMEOUT" -le 30 ] || TIMEOUT=4
command -v curl >/dev/null 2>&1 || fail "curl is not installed, so Shield cannot be asked and this action is not allowed"

ENDPOINT="${URL%/}/v1/shield/hooks/$TARGET"
if [ -n "$SECRET_FILE" ]; then
    [ "$TARGET" = "claude-code" ] || fail "the Votal device agent does not install Codex hooks yet"
    ENDPOINT="${URL%/}/v1/local/claude-code/hook"
fi
USER_NAME=${USER:-$(id -un 2>/dev/null)}
HOST_NAME=$(hostname 2>/dev/null)

# Headers go through a private file (curl -H @file) so the key never appears
# in the process list.
BODY=$(mktemp "${TMPDIR:-/tmp}/votal-hook.XXXXXX") || fail "could not create a temporary file"
HDRS=$(mktemp "${TMPDIR:-/tmp}/votal-hook.XXXXXX") || { rm -f "$BODY"; fail "could not create a temporary file"; }
trap 'rm -f "$BODY" "$HDRS" "$IN"' EXIT HUP INT TERM
chmod 600 "$HDRS" "$BODY"
{
    if [ -n "$SECRET_FILE" ]; then
        printf 'X-Votal-Local-Secret: %s\n' "$SECRET"
    else
        printf 'X-API-Key: %s\n' "$KEY"
        printf 'X-Agent-Key: %s\n' "$AGENT"
        printf 'X-Device-Id: %s\n' "$HOST_NAME"
    fi
    printf 'X-Shield-User: %s\n' "$USER_NAME"
    printf 'X-Votal-Hook-Version: %s\n' "$HOOK_VERSION"
    printf 'X-Votal-Hook-Mode: %s\n' "$MODE"
    printf 'X-Votal-Hook-OS: %s\n' "$HOOK_OS"
    printf 'Content-Type: application/json\n'
} > "$HDRS"

STATUS=$(curl -sS --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
              -H @"$HDRS" --data-binary @"$IN" -o "$BODY" -w '%{http_code}' \
              "$ENDPOINT" 2>/dev/null) \
    || fail "Shield could not be reached at $URL, so this action is not allowed"
[ "$STATUS" = "200" ] || fail "Shield answered HTTP $STATUS, so this action is not allowed"

ANSWER=$(tr -d '\r\n' < "$BODY")
COMPACT=$(printf '%s' "$ANSWER" | tr -d ' \t')

if [ "$EVENT" = "PostToolUse" ]; then
    # Shield's answer is already in this agent's format: pass it on whole.
    case "$COMPACT" in
        '{}') exit 0 ;;
        '{'*'"updatedToolOutput"'*'}'|'{'*'"decision":"block"'*'}')
            printf '%s\n' "$ANSWER"
            exit 0 ;;
    esac
    fail "Shield's answer was not understood"
fi

if [ "$EVENT" = "UserPromptSubmit" ]; then
    # A refusal ({"decision":"block"}) or a note for the agent: pass it on whole.
    case "$COMPACT" in
        '{}') exit 0 ;;
        '{'*'"decision":"block"'*'}'|'{'*'"additionalContext"'*'}')
            printf '%s\n' "$ANSWER"
            exit 0 ;;
    esac
    fail "Shield's answer was not understood"
fi

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
fail "Shield's answer was not understood, so this action is not allowed"
