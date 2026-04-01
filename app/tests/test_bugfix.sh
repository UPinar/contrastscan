#!/bin/bash
###############################################################################
# test_bugfix.sh — verify TLS false positive bug fix
#
# Tests _ssl_findings() and enrich_with_findings() behavior for:
#   1. TCP connection failed → info, SSL excluded from scoring
#   2. Connection reset during TLS handshake → info, SSL excluded from scoring
#   3. TLS handshake failed (certificate error) → critical
#   4. TLS handshake failed (generic) → medium
#   5. Normal SSL (no error) → no error-level findings
#
# Usage: cd contrastscan && bash test_bugfix.sh
###############################################################################

set -uo pipefail

GREEN='\033[32m'
RED='\033[31m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  ${RED}FAIL${NC}  $1 — $2"; }

PYTHON="app/../venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  PYTHON="python3"
fi

# helper: run Python snippet in app context, return JSON
run_test() {
  local desc="$1"
  local snippet="$2"
  local check="$3"  # jq expression that should return "true"

  result=$($PYTHON -c "
import sys, json
sys.path.insert(0, 'app')
from findings import _ssl_findings, enrich_with_findings
$snippet
" 2>&1)

  if [ $? -ne 0 ]; then
    fail "$desc" "Python error: $result"
    return
  fi

  check_result=$(echo "$result" | jq -r "$check" 2>/dev/null)
  if [ "$check_result" = "true" ]; then
    pass "$desc"
  else
    fail "$desc" "got: $result"
  fi
}

echo ""
echo "=== TLS False Positive Bug Fix Tests ==="

# --- _ssl_findings tests ---
echo ""
echo "[_ssl_findings] — severity classification"

# 1. TCP connection failed → info
run_test "TCP connection failed → info" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'TCP connection failed'}}
f = _ssl_findings(r)
print(json.dumps({'severity': f[0]['severity'], 'count': len(f)}))
" \
  '.severity == "info"'

# 2. Connection reset during TLS handshake → info
run_test "Connection reset during TLS → info" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'Connection reset during TLS handshake'}}
f = _ssl_findings(r)
print(json.dumps({'severity': f[0]['severity'], 'count': len(f)}))
" \
  '.severity == "info"'

# 3. TLS handshake failed with cert error → critical
run_test "TLS cert verify failed → critical" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'TLS handshake failed: certificate verify failed'}}
f = _ssl_findings(r)
print(json.dumps({'severity': f[0]['severity'], 'count': len(f)}))
" \
  '.severity == "critical"'

# 4. TLS handshake failed (generic) → medium
run_test "TLS generic failure → medium" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'TLS handshake failed'}}
f = _ssl_findings(r)
print(json.dumps({'severity': f[0]['severity'], 'count': len(f)}))
" \
  '.severity == "medium"'

# 5. SSL_CTX_new failed → medium (internal error, not cert issue)
run_test "SSL_CTX_new failed → medium" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'SSL_CTX_new failed'}}
f = _ssl_findings(r)
print(json.dumps({'severity': f[0]['severity'], 'count': len(f)}))
" \
  '.severity == "medium"'

# 6. No SSL error, valid cert → no error findings
run_test "Valid SSL → no error findings" \
  "
r = {'ssl': {'score': 20, 'max': 20, 'details': {'tls_version': 'TLSv1.3', 'cert_valid': True, 'chain_valid': True, 'days_remaining': 90, 'cipher': 'AES_256_GCM', 'cipher_score': 10}}}
f = _ssl_findings(r)
print(json.dumps({'count': len(f)}))
" \
  '.count == 0'

# --- enrich_with_findings scoring tests ---
echo ""
echo "[enrich_with_findings] — SSL scoring exclusion"

# 7. TCP failed → SSL excluded from max_score
run_test "TCP failed → SSL excluded from scoring" \
  "
r = {'domain': 'test.com', 'grade': 'A', 'total_score': 75, 'max_score': 100,
     'ssl': {'score': 0, 'max': 20, 'error': 'TCP connection failed'},
     'headers': {'score': 25, 'max': 25, 'details': {}},
     'dns': {'score': 15, 'max': 15, 'details': {'spf': True, 'dmarc': True, 'dkim': True}},
     'redirect': {'score': 8, 'max': 8, 'details': {'redirects_to_https': True}},
     'disclosure': {'score': 5, 'max': 5, 'details': {}},
     'cookies': {'score': 5, 'max': 5, 'details': {'cookies_found': 0}},
     'dnssec': {'score': 5, 'max': 5, 'details': {'dnssec_enabled': True}}}
e = enrich_with_findings(r)
print(json.dumps({'ssl_max': e['ssl']['max'], 'max_score': e['max_score']}))
" \
  '.ssl_max == 0 and .max_score == 80'

# 8. Connection reset → SSL excluded from max_score
run_test "Connection reset → SSL excluded from scoring" \
  "
r = {'domain': 'test.com', 'grade': 'A', 'total_score': 75, 'max_score': 100,
     'ssl': {'score': 0, 'max': 20, 'error': 'Connection reset during TLS handshake'},
     'headers': {'score': 25, 'max': 25, 'details': {}},
     'dns': {'score': 15, 'max': 15, 'details': {'spf': True, 'dmarc': True, 'dkim': True}},
     'redirect': {'score': 8, 'max': 8, 'details': {'redirects_to_https': True}},
     'disclosure': {'score': 5, 'max': 5, 'details': {}},
     'cookies': {'score': 5, 'max': 5, 'details': {'cookies_found': 0}},
     'dnssec': {'score': 5, 'max': 5, 'details': {'dnssec_enabled': True}}}
e = enrich_with_findings(r)
print(json.dumps({'ssl_max': e['ssl']['max'], 'max_score': e['max_score']}))
" \
  '.ssl_max == 0 and .max_score == 80'

# 9. Cert error → SSL NOT excluded from scoring
run_test "Cert error → SSL stays in scoring" \
  "
r = {'domain': 'test.com', 'grade': 'F', 'total_score': 75, 'max_score': 100,
     'ssl': {'score': 0, 'max': 20, 'error': 'TLS handshake failed: certificate verify failed'},
     'headers': {'score': 25, 'max': 25, 'details': {}},
     'dns': {'score': 15, 'max': 15, 'details': {'spf': True, 'dmarc': True, 'dkim': True}},
     'redirect': {'score': 8, 'max': 8, 'details': {'redirects_to_https': True}},
     'disclosure': {'score': 5, 'max': 5, 'details': {}},
     'cookies': {'score': 5, 'max': 5, 'details': {'cookies_found': 0}},
     'dnssec': {'score': 5, 'max': 5, 'details': {'dnssec_enabled': True}}}
e = enrich_with_findings(r)
print(json.dumps({'ssl_max': e['ssl']['max'], 'max_score': e['max_score']}))
" \
  '.ssl_max == 20 and .max_score == 100'

# --- Description/remediation sanity checks ---
echo ""
echo "[descriptions] — correct messaging"

# 10. Connection reset → description mentions network issue
run_test "Connection reset → mentions network issue" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'Connection reset during TLS handshake'}}
f = _ssl_findings(r)
desc = f[0]['description'].lower()
print(json.dumps({'has_network': 'network' in desc or 'block' in desc or 'firewall' in desc or 'connection' in desc}))
" \
  '.has_network == true'

# 11. Connection reset → remediation does NOT say "install certificate"
run_test "Connection reset → no 'install cert' remediation" \
  "
r = {'ssl': {'score': 0, 'max': 20, 'error': 'Connection reset during TLS handshake'}}
f = _ssl_findings(r)
rem = f[0]['remediation'].lower()
print(json.dumps({'no_install_cert': 'install' not in rem}))
" \
  '.no_install_cert == true'

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
