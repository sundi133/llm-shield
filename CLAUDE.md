# LLM Shield (Votal Shield)

## Repository purpose
AI guardrails platform that sits between an application and its LLM: inspects
inputs, enforces policy, scans outputs, and secures agentic tool-calling
workflows, with multi-tenant isolation (per-tenant policies in Redis). Runs on
RunPod (GPU) with a built-in vLLM backend, or proxies to any OpenAI-compatible
API. See `README.md` and `ARCHITECTURE.md` for the full picture.

## How we build LLM Shield

**Spec-first, not vibe-coded.** Before writing or changing code for any
non-trivial feature, write the spec using `docs/spec-template.md`. Execute one
small, scoped task per PR. Review with PR rigor. Ship only when tests pass.

When asked to build something, default to: **(1) produce a filled spec and
pause for approval, (2) then implement the scoped task.** Use the `spec`
skill (`/spec`) to scaffold the spec. Don't invent data models, planes, or
APIs that aren't in an approved spec.

**Working on the NeMo Guardrails task?** Read
`docs/investigation/nemo-guardrails-task-brief.md` first — it's the source of
truth for that workstream's scope and constraints.

## Important directories
| Path | What lives there |
|---|---|
| `core/` | Data-plane guardrail server internals (`core/app.py`), auth, telemetry, MCP upstream proxy |
| `api/` | FastAPI route modules (gateway, MCP, SIEM, SSF, audit, edge) |
| `guardrails/` | Individual guardrail implementations (input/output/agentic), `registry.py` |
| `storage/` | Persistence layer (Redis/Upstash-backed state, audit, metrics) |
| `config/` | `default.yaml` guardrail config, `schema.py` |
| `admin_app.py`, `static/` | Admin plane (CPU portal) app + `tenant.html` UI |
| `scripts/` | Ops scripts (start_vllm.sh, benchmarks, codegen, smoke tests) |
| `tests/` | pytest suite — the merge gate |
| `sdk/`, `mcp/`, `extension/` | Client SDK, MCP server, browser extension |
| `docs/` | Published docs (Jekyll/Just-the-Docs site) + `docs/investigation/` task briefs |
| `saas/` | SaaS-specific integrations/docs, separate from core platform |

## Installation
```bash
pip install -r requirements.txt
```
Validate in a clean venv before trusting it locally:
```bash
python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt
```
Admin-plane-only image: `docker build -f Dockerfile.admin -t shield-admin .`

## Test commands
```bash
python -m pytest tests -q
```
Run from the repo root (puts it on `sys.path` so `core/`, `api/`, `storage/`
import without a src layout) — this matches `.github/workflows/test.yml`,
the CI merge gate. Extension tests: `node --test extension/test/*.mjs`.

## Lint and formatting
No linter or formatter is configured in this repo (no ruff/black/flake8/mypy
config found). Match the style of surrounding code rather than introducing a
new tool or convention unilaterally.

## Coding conventions (observed)
- Python 3.12, full type hints on function signatures (`Optional[str]`,
  `list[str]`, etc.).
- Module-level docstring at the top of each file; function docstrings
  explain *why*/non-obvious behavior, not just what.
- Env-var-driven config with a `SHIELD_` prefix and `os.getenv(..., default)`
  at module scope; constants in `UPPER_SNAKE_CASE`.
- Comments explain rationale/constraints (e.g. "vLLM max-model-len = 8196"),
  not restate the code.
- No em dashes in customer-facing docs; Arial for generated docx/xlsx/pdf.

## Security constraints
- **Off the hot path.** Governance/portal/analytics/read endpoints must not
  add latency to the guard path: `/guardrails/*`, `cap/mint`, `tools/call`.
  Call this out explicitly in any spec touching those areas.
- **Two planes.** Data plane = GPU/vLLM guardrail server (`core/app.py`,
  started by `scripts/start_vllm.sh`). Admin plane = CPU portal
  (`admin_app.py`, serves `static/tenant.html`). State which plane(s) a
  change targets.
- **`Dockerfile.admin` is a curated per-file COPY allowlist.** Any new module
  `admin_app.py` imports must be added to it, or the admin image crash-loops
  at boot. Enforced by `tests/test_admin_dockerfile_imports.py`.
- **Declare dependencies.** New pip imports → `requirements.txt` (runtime)
  and `requirements-test.txt` (CI); add to `requirements-admin.txt` if the
  admin plane uses it.
- **Secure-by-default but non-breaking.** A behavior-changing default must
  be opt-in or shipped with an escape-hatch env flag and a migration note.
- **Never commit secrets** (API keys, tokens, `.env` contents). Rotate any
  token that appears in chat/history.

## Scope discipline
- Don't modify code unrelated to the task at hand, even if you notice
  something that looks improvable — flag it instead of fixing it inline.
- Self-contained PRs: if a change needs a dep/Dockerfile/CI update to pass,
  put it in the *same* PR.

## Git discipline
- Never develop on `main`; use a feature branch and open a PR.
- Do not `git commit` or `git push` without explicit user confirmation for
  that specific commit/push — an earlier approval doesn't carry forward to
  later ones.
- Make the test suite green in a clean venv before trusting CI; the `pytest`
  CI gate (`.github/workflows/test.yml`) must pass before merge.

## Confirmed vs. recommended
When responding, clearly distinguish:
- **Confirmed requirements** — explicitly stated by the user, or fixed by an
  approved spec/existing code/config.
- **Recommendations** — your own suggestions, assumptions, or best guesses
  filling a gap.
Label the latter as such (e.g. "Recommendation:" or "Assuming X — confirm?")
rather than presenting them as settled.
