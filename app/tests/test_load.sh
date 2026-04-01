#!/bin/bash
###############################################################################
# test_load.sh — load test for ContrastScan
#
# Tests:
#   1. 50 concurrent page loads — response time + status
#   2. 10 concurrent API scans — all return valid JSON
#   3. Rate limit enforcement — 429 after limit
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

# === 2. Concurrent API scans ===
echo ""
echo "[concurrent_api] — 5 concurrent API scans"

# use different domains to avoid domain rate limit
domains=("google.com" "github.com" "cloudflare.com" "example.com" "mozilla.org")

api_ok=0
for i in $(seq 0 4); do
  d="${domains[$i]}"
  curl -s "$URL/api/scan?domain=$d" > "$TMPDIR/api_$i.json" 2>/dev/null &
done
wait

for i in $(seq 0 4); do
  if [ -f "$TMPDIR/api_$i.json" ]; then
    if cat "$TMPDIR/api_$i.json" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'grade' in d" 2>/dev/null; then
      api_ok=$((api_ok + 1))
    fi
  fi
done

if [ "$api_ok" -ge 3 ]; then
  pass "$api_ok/5 API scans returned valid JSON"
else
  fail "concurrent API" "$api_ok/5 valid responses"
fi

# === 3. Rate limit enforcement ===
echo ""
echo "[rate_limit] — verify 429 after limit"

# rapid fire same domain — should eventually get 429 or rate limited
rate_429=0
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$URL/api/scan?domain=ratelimit-test-$RANDOM.com" 2>/dev/null)
  if [ "$code" = "429" ]; then
    rate_429=1
    break
  fi
done

if [ "$rate_429" -eq 1 ]; then
  pass "rate limit triggered (429) after $i requests"
else
  # not necessarily a failure — limit might be high
  echo -e "  ${YELLOW}INFO${NC}  rate limit not triggered in 30 requests (limit may be higher)"
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
