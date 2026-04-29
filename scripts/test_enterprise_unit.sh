#!/bin/bash
# Run all enterprise feature unit tests (no server required)
#
# Usage:
#   ./scripts/test_enterprise_unit.sh          # Run all
#   ./scripts/test_enterprise_unit.sh -k kill  # Run only killswitch tests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "  LLM Shield — Enterprise Feature Unit Tests"
echo "=============================================="
echo ""

PYTEST_ARGS="${@:--v}"

.venv/bin/python -m pytest \
    tests/test_killswitch.py \
    tests/test_decision_audit.py \
    tests/test_webhooks.py \
    tests/test_policy_versioning.py \
    tests/test_policy_export_import.py \
    tests/test_policy_inheritance.py \
    $PYTEST_ARGS

echo ""
echo "All enterprise feature tests completed."
