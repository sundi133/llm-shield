#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
# Complete Guardrails Test Suite Runner
#
# Runs both basic and agentic guardrail tests in sequence
# ═══════════════════════════════════════════════════════════════════

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Configuration ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASIC_TEST="$SCRIPT_DIR/test_basic_guardrails.sh"
AGENTIC_TEST="$SCRIPT_DIR/test_agentic_guardrails.sh"

echo_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 Complete Guardrails Test Suite               ║"
    echo "║              Basic + Agentic Validation Tests                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  Basic Test    : $BASIC_TEST"
    echo -e "  Agentic Test  : $AGENTIC_TEST"
    echo -e "  Timestamp     : $(date)"
    echo ""
}

check_requirements() {
    # Check if test scripts exist
    if [ ! -f "$BASIC_TEST" ]; then
        echo -e "${RED}Error: Basic test script not found at $BASIC_TEST${RESET}"
        exit 1
    fi

    if [ ! -f "$AGENTIC_TEST" ]; then
        echo -e "${RED}Error: Agentic test script not found at $AGENTIC_TEST${RESET}"
        exit 1
    fi

    # Check if scripts are executable
    if [ ! -x "$BASIC_TEST" ]; then
        echo -e "${YELLOW}Making basic test script executable...${RESET}"
        chmod +x "$BASIC_TEST"
    fi

    if [ ! -x "$AGENTIC_TEST" ]; then
        echo -e "${YELLOW}Making agentic test script executable...${RESET}"
        chmod +x "$AGENTIC_TEST"
    fi

    # Check required environment variables
    if [ -z "$RUNPOD_TOKEN" ]; then
        echo -e "${RED}Error: RUNPOD_TOKEN not set${RESET}"
        echo "  export RUNPOD_TOKEN=\"your-token\""
        exit 1
    fi

    if [ -z "$SHIELD_ADMIN_KEY" ]; then
        echo -e "${RED}Error: SHIELD_ADMIN_KEY not set${RESET}"
        echo "  export SHIELD_ADMIN_KEY=\"your-admin-key\""
        exit 1
    fi
}

run_test_suite() {
    local test_name="$1"
    local test_script="$2"
    local test_color="$3"

    echo -e "${test_color}${BOLD}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Running $test_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${RESET}"

    local start_time=$(date +%s)

    # Run the test script
    if "$test_script"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${GREEN}✓ $test_name completed successfully (${duration}s)${RESET}"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${RED}✗ $test_name failed (${duration}s)${RESET}"
        return 1
    fi
}

# ── Main Execution ────────────────────────────────────────────────

echo_header

# Parse command line options
RUN_BASIC=true
RUN_AGENTIC=true
STOP_ON_FAILURE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --basic-only)
            RUN_AGENTIC=false
            shift
            ;;
        --agentic-only)
            RUN_BASIC=false
            shift
            ;;
        --stop-on-failure)
            STOP_ON_FAILURE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --basic-only        Run only basic guardrail tests"
            echo "  --agentic-only      Run only agentic guardrail tests"
            echo "  --stop-on-failure   Stop execution if any test suite fails"
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Environment Variables Required:"
            echo "  RUNPOD_TOKEN        Your RunPod API token"
            echo "  SHIELD_ADMIN_KEY    LLM Shield admin key"
            echo ""
            echo "Optional Environment Variables:"
            echo "  RUNPOD_HOST         RunPod endpoint (default: https://kk5losqxwr2ui7.api.runpod.ai)"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${RESET}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

check_requirements

# Track overall results
OVERALL_SUCCESS=true
TESTS_RUN=0
TESTS_PASSED=0

echo -e "${BLUE}Starting comprehensive guardrails test suite...${RESET}"
echo ""

# Run basic guardrails tests
if [ "$RUN_BASIC" = true ]; then
    TESTS_RUN=$((TESTS_RUN + 1))
    if run_test_suite "Basic Guardrails Tests" "$BASIC_TEST" "$BLUE"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        OVERALL_SUCCESS=false
        if [ "$STOP_ON_FAILURE" = true ]; then
            echo -e "${RED}Stopping due to basic test failure (--stop-on-failure enabled)${RESET}"
            exit 1
        fi
    fi
    echo ""
fi

# Run agentic guardrails tests
if [ "$RUN_AGENTIC" = true ]; then
    TESTS_RUN=$((TESTS_RUN + 1))
    if run_test_suite "Agentic Guardrails Tests" "$AGENTIC_TEST" "$MAGENTA"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        OVERALL_SUCCESS=false
        if [ "$STOP_ON_FAILURE" = true ]; then
            echo -e "${RED}Stopping due to agentic test failure (--stop-on-failure enabled)${RESET}"
            exit 1
        fi
    fi
    echo ""
fi

# Final summary
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    FINAL TEST SUMMARY                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "  Test Suites Run: ${BOLD}$TESTS_RUN${RESET}"
echo -e "  Test Suites Passed: ${GREEN}$TESTS_PASSED${RESET}"
echo -e "  Test Suites Failed: ${RED}$((TESTS_RUN - TESTS_PASSED))${RESET}"
echo ""

if [ "$OVERALL_SUCCESS" = true ]; then
    echo -e "${GREEN}${BOLD}🎉 ALL TEST SUITES PASSED!${RESET}"
    echo ""
    echo -e "${GREEN}Your LLM Shield deployment is working correctly:${RESET}"
    echo -e "  ✅ Input guardrails (safety, PII, topic, language)"
    echo -e "  ✅ Output guardrails (bias, tone, PII leakage, links)"
    echo -e "  ✅ Agent registration and tool policies"
    echo -e "  ✅ Role-based authorization and LLM validation"
    echo -e "  ✅ Data sanitization and policy enforcement"
    echo ""
    echo -e "${CYAN}Your guardrails platform is ready for production! 🚀${RESET}"
else
    echo -e "${RED}${BOLD}❌ SOME TEST SUITES FAILED${RESET}"
    echo ""
    echo -e "${YELLOW}Common troubleshooting steps:${RESET}"
    echo -e "  1. Check server is running: curl \$RUNPOD_HOST/health"
    echo -e "  2. Verify authentication: check RUNPOD_TOKEN and SHIELD_ADMIN_KEY"
    echo -e "  3. Check guardrail configurations in tenant settings"
    echo -e "  4. Review server logs for error details"
    echo -e "  5. Ensure all required guardrails are enabled"
    echo ""
    echo -e "${BLUE}For detailed debugging:${RESET}"
    echo -e "  • Run individual tests: $BASIC_TEST or $AGENTIC_TEST"
    echo -e "  • Check API docs: \$RUNPOD_HOST/docs"
    echo -e "  • Review test output above for specific failures"
fi

echo ""
echo -e "${CYAN}Test completed at: $(date)${RESET}"

# Exit with appropriate code
if [ "$OVERALL_SUCCESS" = true ]; then
    exit 0
else
    exit 1
fi