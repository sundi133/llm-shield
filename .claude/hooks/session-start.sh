#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Makes the Python test gate reliable in fresh remote containers. Two quirks
# of the base image break a plain `pip install -r requirements.txt`:
#   1. `langdetect` ships an sdist that fails the legacy setup.py wheel build
#      — `--use-pep517` builds it correctly.
#   2. Several deps (PyJWT, cryptography) are pre-installed by debian without
#      RECORD files, so pip cannot uninstall/upgrade them and aborts the whole
#      batch — `--ignore-installed` installs fresh copies instead.
# `python-multipart` (used by the OAuth form endpoints) is also not pinned in
# requirements.txt, so it is added here.
#
# Runs only in the remote web environment; local runs are left untouched.
# Safe to run repeatedly (pip reuses cached wheels).
set -uo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

echo "[session-start] installing Python dependencies for the test gate..."

python -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1 || true

# One shot: PEP 517 builds langdetect; --ignore-installed avoids the
# "cannot uninstall (installed by debian)" abort on PyJWT/cryptography.
python -m pip install --use-pep517 --ignore-installed -r requirements.txt \
  >/dev/null 2>&1 || true

# Required by the OAuth /oauth/token form endpoints; not in requirements.txt.
python -m pip install python-multipart >/dev/null 2>&1 || true

# Persist PYTHONPATH so pytest resolves the project's top-level packages.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export PYTHONPATH="."' >> "$CLAUDE_ENV_FILE"
fi

# Report readiness without failing the hook.
if python -c "import fastapi, pydantic, cryptography, jwt, multipart, ahocorasick, langdetect, tiktoken" >/dev/null 2>&1; then
  echo "[session-start] test dependencies ready."
else
  echo "[session-start] WARNING: some dependencies failed to import; tests may not run."
fi

exit 0
