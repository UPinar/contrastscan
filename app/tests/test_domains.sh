#!/bin/bash
###############################################################################
# test_domains.sh — bulk scan test against 55 diverse domains
#
# Tests grade, score, SSL error handling across different server configs
# Usage: bash test_domains.sh [BASE_URL]
# Default: https://contrastcyber.com
###############################################################################

BASE_URL="${1:-https://contrastcyber.com}"
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
NC='\033[0m'
PASS=0
FAIL=0
SKIP=0

domains=(
  # Big tech — likely block datacenter IPs (TLS false positive test)
  facebook.com
  instagram.com
  twitter.com
  linkedin.com
  tiktok.com
  netflix.com
  spotify.com
  apple.com
  microsoft.com
  amazon.com

  # Well-configured sites — should score high
  contrastcyber.com
  cloudflare.com
  github.com
  google.com
  mozilla.org
  protonmail.com
  signal.org
  duckduckgo.com
  brave.com
  wireguard.com

  # News / media
  bbc.com
  cnn.com
  nytimes.com
  theguardian.com
  reuters.com

  # Government / edu
  nasa.gov
  mit.edu
  stanford.edu
  harvard.edu
  ox.ac.uk

  # Turkish sites
  turkiye.gov.tr
  boun.edu.tr
  hurriyet.com.tr
  sahibinden.com
  hepsiburada.com

  # Security companies
  crowdstrike.com
  paloaltonetworks.com
  fortinet.com
  checkpoint.com
  snyk.io

  # Dev tools
  gitlab.com
  stackoverflow.com
  docker.com
  kubernetes.io
  npmjs.com
  pypi.org

  # Misc — different stacks
  wordpress.org
  drupal.org
  shopify.com
  stripe.com
  twilio.com

  # Edge cases — old/weird configs
  example.com
  example.org
  httpbin.org
  neverssl.com
  badssl.com
)

CONCURRENT=10
TMPDIR=$(mktemp -d)

scan_domain() {
  local domain="$1"
  local outfile="$TMPDIR/$domain.json"
  curl -s --max-time 120 "$BASE_URL/api/scan?domain=$domain" > "$outfile" 2>/dev/null
}

echo ""
echo "=== Bulk Scan Test — ${#domains[@]} domains ($CONCURRENT concurrent) ==="
echo "Target: $BASE_URL"
echo ""

# launch in batches
running=0
for domain in "${domains[@]}"; do
  scan_domain "$domain" &
  running=$((running + 1))
  if [ "$running" -ge "$CONCURRENT" ]; then
    wait -n 2>/dev/null || wait
    running=$((running - 1))
  fi
done
wait

# print results
printf "%-30s %-6s %-10s %-40s %s\n" "DOMAIN" "GRADE" "SCORE" "SSL" "STATUS"
printf "%-30s %-6s %-10s %-40s %s\n" "------" "-----" "-----" "---" "------"

for domain in "${domains[@]}"; do
  outfile="$TMPDIR/$domain.json"

  if [ ! -s "$outfile" ]; then
    printf "%-30s ${RED}%-6s${NC} %-10s %-40s %s\n" "$domain" "-" "-" "-" "TIMEOUT"
    SKIP=$((SKIP + 1))
    continue
  fi

  parsed=$(python3 -c "
import sys, json
try:
    d = json.load(open('$outfile'))
    err = d.get('detail','')
    if err:
        print(f'ERROR|{err}')
    else:
        g = d.get('grade','?')
        s = d.get('total_score','?')
        m = d.get('max_score','?')
        ssl = d.get('ssl',{}).get('error','ok') or 'ok'
        print(f'{g}|{s}|{m}|{ssl}')
except:
    print('PARSE_ERROR|')
" 2>/dev/null)

  IFS='|' read -r grade score max ssl_err <<< "$parsed"

  if [[ "$grade" == "ERROR" ]]; then
    printf "%-30s ${RED}%-6s${NC} %-10s %-40s %s\n" "$domain" "-" "-" "-" "ERROR: $score"
    FAIL=$((FAIL + 1))
    continue
  fi

  if [[ "$grade" == "PARSE_ERROR" ]]; then
    printf "%-30s ${RED}%-6s${NC} %-10s %-40s %s\n" "$domain" "-" "-" "-" "PARSE ERROR"
    FAIL=$((FAIL + 1))
    continue
  fi

  case "$grade" in
    A) gc="$GREEN" ;;
    B) gc="$GREEN" ;;
    C) gc="$YELLOW" ;;
    D|F) gc="$RED" ;;
    *) gc="$NC" ;;
  esac

  ssl_short=$(echo "$ssl_err" | cut -c1-40)
  printf "%-30s ${gc}%-6s${NC} %-10s %-40s ${GREEN}%s${NC}\n" "$domain" "$grade" "$score/$max" "$ssl_short" "OK"
  PASS=$((PASS + 1))
done

rm -rf "$TMPDIR"

echo ""
TOTAL=$((PASS + FAIL + SKIP))
echo -n "=== Results: $PASS/$TOTAL OK"
if [ "$FAIL" -gt 0 ]; then echo -ne ", ${RED}$FAIL FAILED${NC}"; fi
if [ "$SKIP" -gt 0 ]; then echo -ne ", ${YELLOW}$SKIP SKIPPED${NC}"; fi
echo " ==="
echo ""

exit $FAIL
