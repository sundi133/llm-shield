# Runtime integration examples (infrastructure guardrails)

Reference scripts for running agents inside a boundary that Shield defines.
Guide: [docs/infra-guardrails.md](../../docs/infra-guardrails.md).
Spec: [docs/specs/infra-guardrails.md](../../docs/specs/infra-guardrails.md).

| File | Runs where | Does |
|---|---|---|
| `shield_runtime_sync.py` | Sandbox broker / CI (holds the tenant key) | Pulls the signed runtime bundle, verifies signature and claims, writes the policy file (and `--hash-file` for attestation). Refuses to write anything that does not verify. |
| `openshell_events.py` | Next to the sandbox | Tails `openshell logs` and forwards denials, degraded-boundary findings and policy loads to `/v1/shield/runtime/events`. |
| `envoy/ext_authz.yaml` | Egress proxy (reference, not run in CI) | Envoy asks `/v1/shield/runtime/ext-authz` about every outbound request. |
| [`claude_code_hook.sh`](../../core/runtime_policy/hook_scripts/claude_code_hook.sh) | Employee laptops (macOS, Linux) | Claude Code's fail-closed PreToolUse hook: asks `/v1/shield/hooks/claude-code` before every tool call and denies when Shield says so **or cannot answer**. |
| [`claude_code_hook.ps1`](../../core/runtime_policy/hook_scripts/claude_code_hook.ps1) | Employee laptops (Windows) | The same hook in Windows PowerShell 5.1. |

The first three read the tenant key from `SHIELD_API_KEY`, never from a flag.
None of them belongs inside the sandbox.

## Claude Code hook (fail closed)

The two hook scripts live in `core/runtime_policy/hook_scripts/` so the
portal can hand them out (Runtime Profiles, "Claude Code on laptops", builds
a ready install script). The steps below are the manual equivalent.

Spec: [docs/specs/agent-hook-adapter.md](../../docs/specs/agent-hook-adapter.md).
Claude Code can call Shield directly with an HTTP hook (nothing to install),
but an HTTP hook that times out or gets an error lets the tool call through.
Use this script when "Shield unreachable" must mean "denied".

Claude Code lets a call through when a command hook exits with any code other
than 2, so the script turns every failure into exit 2: no config, no `curl`,
Shield unreachable or slow, any non-200, an answer it does not recognise.

**1. Install** (by MDM, as root) the script and a config file only root can
write. The hook reads its settings from this file, never from the
environment, because Claude Code's environment belongs to the user.

| | Script | Config |
|---|---|---|
| macOS | `/Library/Application Support/Votal/claude_code_hook.sh` | `/Library/Application Support/Votal/hook.conf` |
| Linux | `/opt/votal/claude_code_hook.sh` | `/etc/votal/hook.conf` |
| Windows | `C:\Program Files\Votal\claude_code_hook.ps1` | `C:\ProgramData\Votal\hook.conf` |

```
SHIELD_URL=https://api.guardrails.votal.ai
SHIELD_API_KEY=<tenant key with the runtime scope>
SHIELD_AGENT=claude-code
SHIELD_TIMEOUT=4
```

Make the config readable by the user (the hook runs as the user) and writable
only by root: `chown root:wheel hook.conf && chmod 644 hook.conf` on macOS.

**2. Point Claude Code at it** in managed settings
(`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS,
`/etc/claude-code/managed-settings.json` on Linux,
`C:\Program Files\ClaudeCode\managed-settings.json` on Windows):

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Glob|Grep|WebFetch|mcp__.*",
      "hooks": [{
        "type": "command",
        "command": "/bin/sh '/Library/Application Support/Votal/claude_code_hook.sh' || exit 2",
        "timeout": 10
      }]
    }]
  },
  "allowManagedHooksOnly": true
}
```

Two rules, both checked against a real Claude Code:

- **Keep `|| exit 2`.** Without it a missing or unrunnable script exits 127
  and the call goes through.
- **Keep `SHIELD_TIMEOUT` below the hook's `timeout`.** When Claude Code's
  own timeout stops the hook first, the call goes through. The defaults (4
  and 10 seconds) leave room for both connection and answer.

On Windows the command is
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files\Votal\claude_code_hook.ps1" || exit 2`.
The PowerShell hook is checked against the same contract in CI by reading it,
but has not yet been run on a Windows laptop.

**3. Check it** on one laptop: in Claude Code, ask for something the profile
denies (for example `openssl enc -in notes.txt -out notes.enc`). Claude Code
shows "Blocked by Votal Shield: ..." and the file is not written. Then stop
Shield from being reachable (wrong `SHIELD_URL`) and ask for something
harmless: it is denied with "Shield could not be reached".
