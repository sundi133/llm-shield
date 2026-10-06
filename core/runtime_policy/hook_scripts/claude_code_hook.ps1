# Votal Shield fail-closed hook for Claude Code and Codex (PreToolUse and
# PostToolUse), Windows. -Target claude-code (default) or codex; after a call
# Shield's answer is passed through, and a failure follows
# ON_UNREACHABLE_RESULT (allow, the default, or withhold). For a submitted
# prompt (UserPromptSubmit) a refusal or note is passed through, and a failure
# follows ON_UNREACHABLE_PROMPT (allow, the default, or block);
# docs/specs/agent-hooks-prompt-check.md.
# docs/specs/agent-hooks-tool-policies.md section 4.3.
# Spec: docs/specs/agent-hook-adapter.md, section 4.3. The twin of
# claude_code_hook.sh: same config, same answers, same rule that EVERY
# failure exits 2 (Claude Code lets a call through on any other exit code).
#
#   allow  ({})  -> exit 0, no output
#   deny         -> exit 2, reason on stderr
#   ask          -> exit 0, an "ask" decision on stdout
#   anything else, or any error -> exit 2
#
# Deploy with "|| exit 2" after the command, so a missing script denies too:
#   "command": "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"C:\\Program Files\\Votal\\claude_code_hook.ps1\" || exit 2"
#
# Config: C:\ProgramData\Votal\hook.conf (or -Config <path>), KEY=value lines:
#   SHIELD_URL, SHIELD_API_KEY, SHIELD_AGENT (default claude-code),
#   SHIELD_TIMEOUT (seconds, 1 to 30, default 4), ON_UNREACHABLE (deny, the
#   default, or allow: what a FAILURE means; Shield's own denials always deny),
#   SHIELD_LOCAL_SECRET_FILE (set by the Votal device agent: ask the agent on
#   127.0.0.1 with its local secret instead of Shield with a tenant key).
#   Never read from the environment. Windows PowerShell 5.1 or later.

param([string]$Config = "$env:ProgramData\Votal\hook.conf",
      [ValidateSet("claude-code", "codex")][string]$Target = "claude-code")

$ErrorActionPreference = "Stop"

function Deny([string]$Why) {
    [Console]::Error.WriteLine("Blocked by Votal Shield: $Why")
    exit 2
}

# A failure (no answer, bad answer, bad setup): denied unless the config says
# ON_UNREACHABLE=allow. Shield's own denials go through Deny, never here.
$script:OnUnreachable = "deny"
$script:OnUnreachableResult = "allow"
$script:OnUnreachablePrompt = "allow"
$script:Event = "PreToolUse"
function Fail([string]$Why) {
    if ($script:Event -eq "UserPromptSubmit") {
        if ($script:OnUnreachablePrompt -eq "block") {
            $o = @{ decision = "block"; reason = "Votal Shield could not check this request" }
            [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4))
        }
        exit 0
    }
    if ($script:Event -eq "PostToolUse") {
        if ($script:OnUnreachableResult -eq "withhold") {
            $note = "[Shield withheld this result: Shield could not check it]"
            if ($Target -eq "codex") { $o = @{ decision = "block"; reason = $note } }
            else { $o = @{ hookSpecificOutput = @{ hookEventName = "PostToolUse"; updatedToolOutput = $note } } }
            [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4))
        }
        exit 0
    }
    if ($script:OnUnreachable -eq "allow") {
        [Console]::Error.WriteLine("Votal Shield: $($Why -replace ', so this action is not allowed$', ''); allowed, because this fleet lets actions through when Shield cannot answer")
        exit 0
    }
    Deny $Why
}

trap { Fail "the hook failed ($($_.Exception.Message)), so this action is not allowed" }

# Read the event first, so a broken setup after a call is a PostToolUse failure.
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$body = [Console]::In.ReadToEnd()
if ($body -match '"hook_event_name"\s*:\s*"PostToolUse"') { $script:Event = "PostToolUse" }
elseif ($body -match '"hook_event_name"\s*:\s*"UserPromptSubmit"') { $script:Event = "UserPromptSubmit" }

if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    Fail "hook config $Config is missing or unreadable, so this action is not allowed"
}

$settings = @{ SHIELD_URL = ""; SHIELD_API_KEY = ""; SHIELD_AGENT = "claude-code"; SHIELD_TIMEOUT = "4";
              SHIELD_LOCAL_SECRET_FILE = ""; ON_UNREACHABLE = "deny"; ON_UNREACHABLE_RESULT = "allow";
              ON_UNREACHABLE_PROMPT = "allow" }
foreach ($line in Get-Content -LiteralPath $Config) {
    $l = $line.Trim()
    if ($l -eq "" -or $l.StartsWith("#") -or -not $l.Contains("=")) { continue }
    $k, $v = $l.Split("=", 2)
    $k = $k.Trim(); $v = $v.Trim()
    if ($v.Length -ge 2 -and (($v[0] -eq '"' -and $v[-1] -eq '"') -or ($v[0] -eq "'" -and $v[-1] -eq "'"))) {
        $v = $v.Substring(1, $v.Length - 2)
    }
    if ($settings.ContainsKey($k)) { $settings[$k] = $v }
}

if ($settings.ON_UNREACHABLE -eq "allow") { $script:OnUnreachable = "allow" }
if ($settings.ON_UNREACHABLE_RESULT -eq "withhold") { $script:OnUnreachableResult = "withhold" }
if ($settings.ON_UNREACHABLE_PROMPT -eq "block") { $script:OnUnreachablePrompt = "block" }
$url = $settings.SHIELD_URL
$local = [bool]$settings.SHIELD_LOCAL_SECRET_FILE
if (-not $url) { Fail "SHIELD_URL is not set in $Config, so this action is not allowed" }
if ($local) {
    # The Votal device agent on this laptop: loopback only, its local secret.
    if (-not ($url -match '^http://(127\.0\.0\.1|localhost):\d+/?$')) {
        Fail "SHIELD_URL must be the local agent (http://127.0.0.1:<port>) when SHIELD_LOCAL_SECRET_FILE is set"
    }
    $secret = ""
    try { $secret = (Get-Content -LiteralPath $settings.SHIELD_LOCAL_SECRET_FILE -Raw).Trim() } catch { }
    if (-not $secret) { Fail "the Votal agent's local secret could not be read, so this action is not allowed" }
} else {
    if (-not $settings.SHIELD_API_KEY) { Fail "SHIELD_API_KEY is not set in $Config, so this action is not allowed" }
    if (-not ($url -match '^https://' -or $url -match '^http://(127\.0\.0\.1|localhost)([:/]|$)')) {
        Fail "SHIELD_URL must be https (or a localhost address for testing)"
    }
}
$timeout = 4
[int]::TryParse($settings.SHIELD_TIMEOUT, [ref]$timeout) | Out-Null
if ($timeout -lt 1 -or $timeout -gt 30) { $timeout = 4 }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($local) {
    if ($Target -ne "claude-code") { Fail "the Votal device agent does not install Codex hooks yet" }
    $headers = @{ "X-Votal-Local-Secret" = $secret; "X-Shield-User" = $env:USERNAME }
    $endpoint = $url.TrimEnd("/") + "/v1/local/claude-code/hook"
} else {
    $headers = @{
        "X-API-Key"     = $settings.SHIELD_API_KEY
        "X-Agent-Key"   = $settings.SHIELD_AGENT
        "X-Shield-User" = $env:USERNAME
        "X-Device-Id"   = $env:COMPUTERNAME
    }
    $endpoint = $url.TrimEnd("/") + "/v1/shield/hooks/$Target"
}
try {
    $resp = Invoke-WebRequest -Uri $endpoint -Method Post `
        -Headers $headers -ContentType "application/json" `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec $timeout -UseBasicParsing
} catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($code) { Fail "Shield answered HTTP $code, so this action is not allowed" }
    Fail "Shield could not be reached at $url, so this action is not allowed"
}
if ([int]$resp.StatusCode -ne 200) { Fail "Shield answered HTTP $($resp.StatusCode), so this action is not allowed" }

try { $answer = $resp.Content | ConvertFrom-Json } catch { Fail "Shield's answer was not understood, so this action is not allowed" }
if ($null -eq $answer) { Fail "Shield's answer was not understood, so this action is not allowed" }
$names = @($answer.PSObject.Properties | ForEach-Object { $_.Name })
if ($names.Count -eq 0) { exit 0 }                                  # {} = allow

if ($script:Event -eq "PostToolUse") {
    # Already in this agent's format (redacted result or withheld note): pass it on.
    $hso = $answer.hookSpecificOutput
    if (($hso -and $null -ne $hso.updatedToolOutput) -or [string]$answer.decision -eq "block") {
        [Console]::Out.WriteLine($resp.Content)
        exit 0
    }
    Fail "Shield's answer was not understood"
}

if ($script:Event -eq "UserPromptSubmit") {
    # A refusal or a note for the agent, already in its format: pass it on.
    $hso = $answer.hookSpecificOutput
    if ([string]$answer.decision -eq "block" -or ($hso -and $null -ne $hso.additionalContext)) {
        [Console]::Out.WriteLine($resp.Content)
        exit 0
    }
    Fail "Shield's answer was not understood"
}

$out = $answer.hookSpecificOutput
$decision = if ($out) { [string]$out.permissionDecision } else { "" }
$reason = if ($out) { [string]$out.permissionDecisionReason } else { "" }
$reason = ($reason -replace '[\x00-\x1f]', ' ')
if ($reason.Length -gt 500) { $reason = $reason.Substring(0, 500) }

if ($decision -eq "deny") {
    $why = $reason -replace '^Blocked by Votal Shield: ', ''
    if (-not $why) { $why = "denied by policy" }
    Deny $why
}
if ($decision -eq "ask") {
    if (-not $reason) { $reason = "Votal Shield: this action needs your confirmation" }
    $ask = @{ hookSpecificOutput = @{ hookEventName = "PreToolUse"; permissionDecision = "ask";
                                      permissionDecisionReason = $reason } }
    [Console]::Out.WriteLine(($ask | ConvertTo-Json -Compress -Depth 4))
    exit 0
}
Fail "Shield's answer was not understood, so this action is not allowed"
