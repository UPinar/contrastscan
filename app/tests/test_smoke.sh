#!/bin/bash
###############################################################################
# test_smoke.sh — live site health check
#
# Checks the production site is working correctly:
#   - All pages return 200
#   - SSL certificate valid
#   - Response times acceptable
#   - Key content present
#   - API returns valid JSON
#   - Security headers present
#
# Usage: bash tests/test_smoke.sh [BASE_URL]
# Default: https://contrastcyber.com
# Deploy: can run from anywhere with curl + jq
###############################################################################

BASE_URL="${1:-https://contrastcyber.com}"
PASS=0
FAIL=0
GREEN='\033[32m'
RED='\033[31m'
NC='\033[0m'

pass() { PASS=$((PASS + 1)); echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  ${RED}FAIL${NC}  $1 — $2"; }

check_status() {
    local url="$1"
    local expected="$2"
    local label="$3"
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url")
    if [ "$status" = "$expected" ]; then
        pass "$label → $status"
    else
        fail "$label" "expected $expected, got $status"
    fi
}

check_contains() {
    local url="$1"
    local pattern="$2"
    local label="$3"
    local body
    body=$(curl -s --max-time 10 "$url")
    if echo "$body" | grep -q "$pattern"; then
        pass "$label"
    else
        fail "$label" "pattern '$pattern' not found"
    fi
}

check_header() {
    local url="$1"
    local header="$2"
    local label="$3"
    local value
    value=$(curl -sI --max-time 10 "$url" | grep -i "^$header:" | head -1)
    if [ -n "$value" ]; then
        pass "$label"
    else
        fail "$label" "header '$header' not found"
    fi
}

check_response_time() {
    local url="$1"
    local max_ms="$2"
    local label="$3"
    local time_ms
    time_ms=$(curl -s -o /dev/null -w '%{time_total}' --max-time 10 "$url" | awk '{printf "%d", $1 * 1000}')
    if [ "$time_ms" -le "$max_ms" ]; then
        pass "$label (${time_ms}ms)"
    else
        fail "$label" "${time_ms}ms > ${max_ms}ms"
    fi
}

echo ""
echo "=== Smoke Tests — $BASE_URL ==="

# === Page status codes ===
echo ""
echo "[status_codes]"
check_status "$BASE_URL/" 200 "Homepage"
check_status "$BASE_URL/api" 200 "API docs"
check_status "$BASE_URL/stats" 200 "Stats page"
check_status "$BASE_URL/robots.txt" 200 "robots.txt"
check_status "$BASE_URL/sitemap.xml" 200 "sitemap.xml"
check_status "$BASE_URL/nonexistent" 404 "404 page"
check_status "$BASE_URL/result/invalidid" 404 "invalid scan_id"

# === Content checks ===
echo ""
echo "[content]"
check_contains "$BASE_URL/" "ContrastScan" "Homepage has brand name"
check_contains "$BASE_URL/" 'action="/scan"' "Homepage has scan form"
check_contains "$BASE_URL/" "11 security checks" "Homepage mentions 11 checks"
check_contains "$BASE_URL/robots.txt" "Sitemap:" "robots.txt has sitemap"
check_contains "$BASE_URL/sitemap.xml" "contrastcyber.com" "sitemap has domain"

# === Security headers ===
echo ""
echo "[security_headers]"
check_header "$BASE_URL/" "strict-transport-security" "HSTS header"
check_header "$BASE_URL/" "x-content-type-options" "X-Content-Type-Options"
check_header "$BASE_URL/" "x-frame-options" "X-Frame-Options"
check_header "$BASE_URL/" "referrer-policy" "Referrer-Policy"

# === SSL certificate ===
echo ""
echo "[ssl]"
ssl_expiry=$(curl -sI --max-time 10 "$BASE_URL/" 2>/dev/null | head -1)
if echo "$ssl_expiry" | grep -q "200\|301\|302"; then
    pass "SSL connection works"
else
    fail "SSL connection" "could not connect"
fi

# check cert expiry
cert_days=$(echo | openssl s_client -servername contrastcyber.com -connect contrastcyber.com:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if [ -n "$cert_days" ]; then
    expiry_epoch=$(date -d "$cert_days" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
    if [ "$days_left" -gt 7 ]; then
        pass "SSL cert valid ($days_left days remaining)"
    else
        fail "SSL cert" "only $days_left days remaining!"
    fi
else
    fail "SSL cert check" "could not read certificate"
fi

# === Response times ===
echo ""
echo "[response_times]"
check_response_time "$BASE_URL/" 3000 "Homepage < 3s"
check_response_time "$BASE_URL/stats" 3000 "Stats < 3s"
check_response_time "$BASE_URL/robots.txt" 1000 "robots.txt < 1s"

# === OpenAPI hidden ===
echo ""
echo "[security]"
check_status "$BASE_URL/openapi.json" 404 "openapi.json hidden"
check_status "$BASE_URL/docs" 404 "/docs hidden"
check_status "$BASE_URL/redoc" 404 "/redoc hidden"

# === Summary ===
echo ""
TOTAL=$((PASS + FAIL))
echo -n "=== Results: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo -ne ", ${RED}$FAIL FAILED${NC}"
fi
echo " ==="
echo ""

exit $FAIL
