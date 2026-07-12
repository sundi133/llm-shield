# Spec: MCP scanner Phase 2 — distribution (GitHub Action + npx wrapper)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.
Builds on the shipped `packages/shield-mcp/` (PR #263). The three design forks are
**decided** (see §9): hybrid npx provisioning, a dedicated Marketplace repo, and
publishing `shield-mcp` to PyPI now.

## 1. Problem & outcome

Phase 1 shipped `shield-mcp scan` as a Python CLI (`pipx install shield-mcp`).
But a large share of the MCP ecosystem is JS/TS: those developers won't add a
Python toolchain to run a security check, and no one adds a scanner that isn't
one line to invoke. Distribution *is* the product here — the wedge only works if
"is this MCP server safe?" resolves to a command a JS dev already knows (`npx`)
and a CI step they can paste (`uses:`).

**Outcome.** Two thin wrappers over the **existing** CLI, no detection logic
duplicated:
- **`npx @votal/mcp-scan <target> [flags]`** — runs the scan with no global
  install; JS/TS devs never touch pip.
- **A GitHub Action** — `uses: votal/mcp-scan-action@v1` with `target` +
  `fail-on` inputs; fails the job when the scan exits non-zero.

Both **forward flags verbatim** to `shield-mcp scan` and **propagate its exit
codes** (`0` clean / `2` findings / `3` unreachable / `4` usage), `--json`,
`--fail-on`, and connected-mode flags (`--shield-url` / `--api-key` / `--offline`).
Success = a JS dev scans a server with `npx @votal/mcp-scan stdio:'npx -y some-server'`
and the same repo gates PRs with a 6-line workflow, neither having installed Python
by hand.

**Non-goals.**
- **Not** reimplementing detection in JS/TS — that would fork the heuristics and
  let them drift. The Python package (`packages/shield-mcp/`) stays the single
  detection engine; wrappers only marshal arguments and exit codes.
- **No** new server endpoint, Redis key, or plane code. Connected mode still just
  calls the existing `/guardrails/input` as a client (unchanged from Phase 1).
- **Not** the registry/ratings site (Phase 3) or the small-team gateway edition
  (Phase 4).

## 2. Plane & latency contract

- **Off every plane.** This is client-side CI/distribution tooling — a GitHub
  Action and an npm package. It runs on the developer's machine or a CI runner,
  not on the data (GPU/vLLM) or admin (CPU portal) plane.
- **Off the hot path — no guarded-traffic impact.** It touches `/guardrails/*`
  only in connected mode, and only as an outbound *client* initiated by the
  developer, exactly as the Phase 1 CLI already does. It adds **zero** latency to
  `/guardrails/*`, `cap/mint`, or `tools/call`, and mounts nothing on any plane.

## 3. Data model

**None.** No Redis keys, no server-side state, no tenant records. The wrappers are
stateless processes. Tenant resolution in connected mode is unchanged: the tenant
API key (passed through to `shield-mcp scan --api-key`) resolves server-side at
`/guardrails/input` exactly as any Phase 1 call. The wrappers persist nothing.

## 4. API / interface

No HTTP endpoints. The "interface" is two invocation surfaces, both of which
shell out to `shield-mcp scan` and return its exit code unchanged.

**A. npm wrapper — `@votal/mcp-scan`** (package under `packages/mcp-scan-npm/`,
scope matches the existing `@votal/shield-mcp-server`):
```
npx @votal/mcp-scan <target> [--json] [--fail-on <sev>] [--timeout <s>]
                             [--shield-url <url>] [--api-key <key>] [--offline]
```
- `bin`: `mcp-scan`. All argv after the program name are forwarded **verbatim**
  to `shield-mcp scan` (no re-parsing — the Python CLI remains the source of truth
  for flags/help, so the two can't diverge).
- **Provisioning = hybrid (decided).** On invoke: (1) if a `shield-mcp` is on
  `PATH` or importable, exec it; (2) else, download the pinned, checksum-verified
  **standalone binary** for the host OS/arch (from the scanner's GitHub Release
  assets) into an npm cache dir and exec that. Never mutates the user's Python
  env. `--offline`/network-blocked with no local CLI and no cached binary → a
  clear error (exit 4). No Python required in path (2).
- Runs the resolved executable and exits with **the child's exit code**; child
  stdout is streamed through byte-for-byte (so `--json | jq` works), wrapper
  diagnostics go to stderr only.

**B. GitHub Action — `action.yml`** (composite; **hosted in a dedicated public
repo `votal/mcp-scan-action` for a Marketplace listing** — decided). The
`action.yml` + its self-test are authored here first (staging dir
`packages/mcp-scan-action/`) and mirrored to the release repo:
```yaml
- uses: votal/mcp-scan-action@v1
  with:
    target: "stdio:python -m my_server"   # required
    fail-on: high                         # default: critical
    json: "false"                         # default: false
    timeout: "20"
    shield-url: ""                        # optional (connected mode)
    api-key: ${{ secrets.SHIELD_API_KEY }} # optional; MUST be a secret
    offline: "false"
    version: ""                           # pin shield-mcp; default: latest
```
- **Outputs:** `exit-code`, `verdict` (`pass|fail`), `report` (the `--json`
  document when `json: true`).
- **Behavior:** ensure Python → install `shield-mcp` (pinned by `version`) →
  run `shield-mcp scan` with the mapped flags → set outputs → the step fails
  (non-zero) when the scan exits `2`, so a poisoned server blocks the PR.
- **Auth:** `api-key` is masked (`::add-mask::`) and only ever passed as an env
  var to the child, never interpolated into a logged command line.

## 5. Security & backward compatibility

- **Purely additive & non-breaking.** No change to the shipped `shield-mcp` CLI,
  its flags, or any server path. Nothing that runs today behaves differently.
- **Secret hygiene (Action).** `api-key` must be a `secrets.*` reference; the
  Action masks it and passes it via env, never on a command line that gets echoed.
  Document "never paste a literal key." Connected mode still sends only the
  description text to `/guardrails/input` (Phase 1 guarantee, unchanged).
- **Supply chain.** Both wrappers install/execute a pinned `shield-mcp` version
  (`version` input / a pinned dependency), not "latest-at-runtime" by default in
  CI examples. If Open Q1 lands on a downloaded standalone binary, its release
  artifact is checksum-verified before exec.
- **Untrusted target.** The wrapper `exec`s the target for the MCP handshake
  exactly as the CLI does (stdio launches the server; sse/http connect read-only).
  Same trust model as Phase 1: only scan a server you were about to run anyway.
  The wrapper adds no new execution surface beyond forwarding argv.

## 6. Packaging & deploy

- **New, self-contained directories** — none imported by `admin_app.py`:
  - `packages/mcp-scan-npm/` — `package.json` (`name: @votal/mcp-scan`, `bin:
    mcp-scan`), the wrapper + binary-resolver script, node tests.
  - `packages/mcp-scan-action/` — staging copy of `action.yml` + `README.md`,
    authored here and mirrored to the dedicated repo `votal/mcp-scan-action`.
- **Standalone-binary build (for the hybrid npx fallback).** A release workflow
  builds a single-file `shield-mcp` binary (PyInstaller) across an OS/arch
  matrix — linux x64/arm64, macos x64/arm64, windows x64 — publishes them as
  GitHub Release assets **with a `SHA256SUMS`**, and the npm postinstall/resolver
  downloads the matching, checksum-verified asset. v1 support = Linux + macOS
  runners; Windows best-effort (§7).
- **PyPI publish of `shield-mcp` (decided).** Add a release workflow
  (`.github/workflows/release-shield-mcp.yml`, tag/manual trigger) that runs
  `python -m build` + `twine check` + `twine upload`. Reserve the `shield-mcp`
  name; version from the package's `pyproject.toml`. This makes `pipx install
  shield-mcp` real for the Action's fast path and for humans.
- **No `Dockerfile.admin` change** (nothing added to the admin import graph) and
  **no runtime image rebuild** — this ships as an Action + npm package + release
  binaries, not a service image.
- **Publish tokens (user-provisioned secrets).** npm publish under `@votal` needs
  `NPM_TOKEN`; PyPI needs a scoped API token (or Trusted Publishing). Both are
  repo/org secrets the **maintainer** must create; neither touches the guard path.
- **Cross-repo constraint (needs the maintainer).** The dedicated
  `votal/mcp-scan-action` repo and the Marketplace listing must be created by the
  account owner. This phase produces the Action files *ready to publish*; the repo
  creation + "Publish to Marketplace" click are manual maintainer steps, noted in
  Task 4.
- **Env / inputs:** `SHIELD_URL` / `SHIELD_API_KEY` pass through to the CLI. No
  new *server* env flags.

## 7. Failure modes & edge cases

- **Python absent (npx path):** detect and act per Open Q1 — either auto-provision
  or exit with a clear, actionable message (install hint) and a usage-style code,
  never a raw stack trace.
- **`shield-mcp` install fails (PyPI/network down):** the Action step fails with
  an actionable message ("could not install shield-mcp@X"), distinct from a scan
  failure, so a red build is diagnosable.
- **Exit-code fidelity:** wrapper exit must equal the child's for `0/2/3/4`. A
  wrapper bug must not turn a `2` (findings) into `0` (false green) — the highest-
  severity failure mode; explicitly tested.
- **`--json` integrity:** the wrapper must stream the child's stdout untouched
  (no banner/log on stdout) so piping `--json` to `jq` works. Wrapper diagnostics
  go to stderr only.
- **Version skew:** npm wrapper vX pinning `shield-mcp` vY — document the pin and
  keep them released together; a mismatched pin fails install loudly, not silently.
- **Secret in logs:** assert the Action masks `api-key`; a scan run with a key set
  must not surface it in the job log.
- **Windows runners / exotic quoting:** stdio target quoting differs across shells;
  v1 supports Linux + macOS runners, Windows is best-effort and documented.
- **Fail policy:** the Action **fails closed on findings** (exit 2 → red build —
  that's the whole point). It fails *loud* on infra errors (install/unreachable)
  rather than silently passing. Connected mode inside the CLI remains fail-**open**
  on model-augmentation errors (Phase 1 behavior, unchanged).

## 8. Test plan (Definition of Done)

- **npm wrapper (node tests, no network):**
  1. argv forwarding — every flag/positional after `mcp-scan` reaches the child
     verbatim (spy on the spawned process args).
  2. exit-code propagation — child exits `0/2/3/4` → wrapper exits the same
     (mock child); explicit assert that `2` is never coerced to `0`.
  3. stdout passthrough — `--json` output from the child reaches the wrapper
     stdout byte-for-byte; wrapper's own messages go to stderr.
  4. Python/CLI-missing path → actionable error + non-zero, no stack trace.
- **GitHub Action (workflow self-test, opt-in job):**
  5. run the composite action against the repo's example **poisoned** stdio server
     → step fails (exit 2), `verdict == fail`.
  6. run it against a **clean** server → step passes (exit 0), `verdict == pass`.
  7. `api-key` masking — a run with a dummy key set does not print it in the log.
  These run on a fresh `ubuntu-latest` with **no preinstalled `shield-mcp`** — the
  "clean environment" analog of the clean-venv rule.
- **Publish dry-run:** `npm publish --dry-run` (and, per Open Q3, a PyPI build/
  `twine check`) succeed in CI without actually publishing.
- **Regression:** no changes to `packages/shield-mcp/` behavior; the full
  `pytest tests -q` suite stays green in a clean venv; CI `pytest` gate passes.

## Invariant risk flags
- ✅ **Off the hot path** — pure CI/distribution tooling; connected mode is a
  client of `/guardrails/input`, never inline (§2).
- ✅ **No `admin_app` import** ⇒ no `Dockerfile.admin` change; no image rebuild.
- ⚠️ **New publish surfaces (npm + PyPI)** — supply-chain: pin versions, scoped
  publish tokens as secrets, checksum-verify any downloaded binary, never echo the
  api-key (§5, §7).
- ⚠️ **Prerequisite: `shield-mcp` installable** (not yet on PyPI) — resolved in
  the *same* phase (PyPI publish workflow, Task 1), not stranded.
- ⚠️ **New build/release surface** — PyInstaller binary matrix + checksummed
  Release assets for the hybrid npx fallback; pin + verify (§6, §7).
- ⚠️ **Cross-repo + maintainer secrets** — the Marketplace repo and the
  `NPM_TOKEN`/PyPI-token secrets are maintainer-provisioned; files are authored
  here ready to publish (§6, Task 4).
- ✅ **Non-breaking** — purely additive; the Phase 1 CLI is unchanged and remains
  the single detection engine.

## Task breakdown (one branch, ordered — one PR each)
1. **Publish `shield-mcp` to PyPI** — release workflow (`python -m build` +
   `twine check` + `twine upload`, tag/manual trigger), name reserved, version
   from `pyproject.toml`. Unblocks the Action fast path and human installs.
2. **Standalone-binary release** — PyInstaller build matrix (linux x64/arm64,
   macos x64/arm64, windows x64) → Release assets + `SHA256SUMS`. Smoke-test each
   binary runs `shield-mcp scan --help`. Feeds the npx fallback (Task 3).
3. **npm wrapper** — `packages/mcp-scan-npm/` (`@votal/mcp-scan`, `bin:
   mcp-scan`): hybrid resolver (local CLI → else download+verify binary), argv
   forwarding, exit-code + stdout passthrough. Node tests (tests 1–4) +
   `npm publish --dry-run` in CI. Docs.
4. **GitHub Action** — `packages/mcp-scan-action/action.yml` (composite): inputs →
   `shield-mcp scan`, outputs, key masking; workflow self-test job (tests 5–7)
   against the example servers. Mirror to `votal/mcp-scan-action`; Marketplace
   publish + `NPM_TOKEN`/PyPI-token secret creation are the maintainer steps.
5. **Docs polish** — extend `docs/mcp-scanner.md` with the `npx @votal/mcp-scan`
   and `uses: votal/mcp-scan-action@v1` one-liners + a Marketplace/badge section.

## Resolved decisions (locked)
1. **npx provisioning = hybrid** — local `shield-mcp` if present, else download the
   pinned, checksum-verified standalone binary. (Best UX; accepts the binary build
   matrix as new release surface.)
2. **Action hosting = dedicated Marketplace repo** `votal/mcp-scan-action` — files
   authored here, mirrored + listed by the maintainer for `uses:
   votal/mcp-scan-action@v1`.
3. **`shield-mcp` availability = publish to PyPI now** — release workflow in Task 1.

## Maintainer-only steps (cannot be automated from this repo)
- Create the public repo `votal/mcp-scan-action` and publish it to the GitHub
  Marketplace.
- Reserve/own the `shield-mcp` PyPI project and `@votal/mcp-scan` npm name.
- Add repo/org secrets: `PYPI_API_TOKEN` (or Trusted Publishing), `NPM_TOKEN`.
