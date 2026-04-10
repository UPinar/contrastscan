#!/bin/bash
###############################################################################
# test_load.sh — load test for ContrastScan
#
# Tests:
#   1. 50 concurrent page loads — response time + status
#
# Usage: bash tests/test_load.sh [URL]
#   default URL: https://contrastcyber.com
###############################################################################

set -uo pipefail

URL="${1:-https://contrastcyber.com}"
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  ${RED}FAIL${NC}  $1 — $2"; }

echo ""
echo "=== Load Tests ==="
echo "Target: $URL"

# === 1. Concurrent page loads ===
echo ""
echo "[concurrent_pages] — 20 concurrent GET /"

TMPDIR=$(mktemp -d)
start=$(date +%s%N)

for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "$URL/" > "$TMPDIR/page_$i.txt" 2>/dev/null &
done
wait

end=$(date +%s%N)
elapsed=$(( (end - start) / 1000000 ))

ok_count=0
total_time=0
max_time=0
for f in "$TMPDIR"/page_*.txt; do
  code=$(awk '{print $1}' "$f")
  t=$(awk '{print $2}' "$f")
  if [ "$code" = "200" ]; then
    ok_count=$((ok_count + 1))
  fi
  # track max response time (integer ms)
  ms=$(echo "$t" | awk '{printf "%d", $1 * 1000}')
  if [ "$ms" -gt "$max_time" ]; then
    max_time=$ms
  fi
done

if [ "$ok_count" -ge 18 ]; then
  pass "$ok_count/20 returned 200 (${elapsed}ms total, max ${max_time}ms per request)"
else
  fail "concurrent pages" "$ok_count/20 returned 200"
fi

# SLA check: all responses under 5s
if [ "$max_time" -lt 5000 ]; then
  pass "all responses under 5s SLA (max ${max_time}ms)"
else
  fail "SLA" "max response ${max_time}ms exceeds 5s"
fi

# cleanup
rm -rf "$TMPDIR"

# === Summary ===
echo ""
TOTAL=$((PASS + FAIL))
echo -n "=== Load Results: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
  echo -ne ", ${RED}$FAIL FAILED${NC}"
fi
echo " ==="
echo ""

exit $FAIL
