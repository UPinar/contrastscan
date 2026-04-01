#!/bin/bash
###############################################################################
# run_tests.sh — run all ContrastScan test suites
#
# Uses a temporary DB in /tmp/ so production scans.db is never touched.
#
# Usage: bash run_tests.sh [--all]
#   default: C unit + pytest (no network)
#   --all:   + scanner integration + smoke + load (requires network)
###############################################################################

set -uo pipefail

GREEN='\033[32m'
RED='\033[31m'
BOLD='\033[1m'
NC='\033[0m'

DIR="$(cd "$(dirname "$0")" && pwd)"
FAILED=0
RUN_ALL=0

[[ "${1:-}" == "--all" ]] && RUN_ALL=1

# use isolated test DB — never touch production scans.db
export CONTRASTSCAN_DB="/tmp/contrastscan_test_$$.db"

cleanup() {
    rm -f "$CONTRASTSCAN_DB" "${CONTRASTSCAN_DB}-wal" "${CONTRASTSCAN_DB}-shm"
}
trap cleanup EXIT

run_suite() {
    local name="$1"
    local cmd="$2"
    echo ""
    echo -e "${BOLD}━━━ $name ━━━${NC}"
    cleanup  # fresh DB per suite
    if eval "$cmd"; then
        echo -e "${GREEN}$name: OK${NC}"
    else
        echo -e "${RED}$name: FAILED${NC}"
        FAILED=$((FAILED + 1))
    fi
}

# C unit tests
run_suite "C Unit Tests (159)" \
    "cd '$DIR/scanner' && make test 2>&1"

# Python tests (pytest)
run_suite "Python Tests (pytest)" \
    "cd '$DIR' && source venv/bin/activate && cd app && python -m pytest tests/ -v --tb=short 2>&1"

if [ "$RUN_ALL" -eq 1 ]; then
    # Scanner integration tests (network required)
    run_suite "Scanner Integration Tests" \
        "cd '$DIR' && bash scanner/tests/test_integration.sh 2>&1"

    # Smoke tests (live site)
    run_suite "Smoke Tests (~25)" \
        "bash '$DIR/app/tests/test_smoke.sh' 2>&1"

    # Load tests (live site)
    run_suite "Load Tests" \
        "bash '$DIR/app/tests/test_load.sh' 2>&1"
fi

# Summary
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}ALL SUITES PASSED${NC}"
else
    echo -e "${RED}${BOLD}$FAILED SUITE(S) FAILED${NC}"
fi
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exit $FAILED
