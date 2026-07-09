# How we build LLM Shield

**Spec-first, not vibe-coded.** Before writing or changing code for any
non-trivial feature, write the spec using `docs/spec-template.md`. Execute one
small, scoped task per PR. Review with PR rigor. Ship only when tests pass.

When asked to build something, default to: **(1) produce a filled spec and pause
for approval, (2) then implement the scoped task.** Use the `spec` skill (`/spec`)
to scaffold the spec. Don't invent data models, planes, or APIs that aren't in
an approved spec.

## Repo invariants (hard rules — each is a past incident)
- **Off the hot path.** Governance / portal / analytics / read endpoints must
  not add latency to the guard path: `/guardrails/*`, `cap/mint`, `tools/call`.
  Say so explicitly in the spec.
- **Two planes.** Data plane = GPU/vLLM guardrail server (`core/app.py`, started
  by `scripts/start_vllm.sh`). Admin plane = CPU portal (`admin_app.py`, serves
  `static/tenant.html`). State the plane(s) a change targets.
- **`Dockerfile.admin` is a curated per-file COPY allowlist.** Any new module
  `admin_app.py` imports MUST be added to it, or the admin image crash-loops at
  boot. Enforced by `tests/test_admin_dockerfile_imports.py`.
- **Declare dependencies.** New pip imports → `requirements.txt` (runtime) and
  `requirements-test.txt` (CI); add to `requirements-admin.txt` if the admin
  plane uses it. A polluted local venv hides missing deps — validate in a clean
  venv (`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`).
- **Secure-by-default but non-breaking.** A behavior-changing default must be
  opt-in or shipped with an escape-hatch env flag and a migration note.
- **Self-contained PRs.** If a change needs a dep/Dockerfile/CI update to pass,
  put it in the *same* PR — don't strand companion fixes.

## Test & merge discipline
- Run the full suite with `python -m pytest tests -q` (repo root on sys.path).
- Make it green in a **clean venv** before trusting CI.
- The `pytest` CI gate (`.github/workflows/test.yml`) must pass before merge.
- Never develop on `main`; use a feature branch and open a PR.

## Conventions
- No em dashes in customer-facing docs; Arial for generated docx/xlsx/pdf.
- Don't commit secrets; rotate any token that appears in chat/history.
