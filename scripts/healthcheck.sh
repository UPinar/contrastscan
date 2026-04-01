#!/bin/bash
###############################################################################
# healthcheck.sh — ContrastCyber API & server health monitor
#
# Checks services, response times, error rates, nginx tuning indicators,
# and system resources. Sends Telegram alert only when something is wrong.
#
# Deploy: scp /tmp/healthcheck.sh local:/opt/scripts/healthcheck.sh
# Cron:   */5 * * * * bash /opt/scripts/healthcheck.sh
# Manual: bash /opt/scripts/healthcheck.sh --verbose
###############################################################################

set -uo pipefail

# === Config ===
SCAN_URL="https://contrastcyber.com"
API_URL="https://api.contrastcyber.com"
NGINX_LOG="/var/log/nginx/access.log"
TELEGRAM_TOKEN_FILE="/etc/telegram-bot/token"
TELEGRAM_CHAT_FILE="/etc/telegram-bot/chat_ids"

# Thresholds
MAX_RESPONSE_TIME=5        # seconds
MAX_5XX_RATE=5             # percent in last 5 min
MAX_ACTIVE_CONNECTIONS=200 # nginx active connections
MAX_CACHE_MISS_RATE=70     # percent — if higher, nginx cache needs tuning
MAX_DISK_USAGE=85          # percent
MAX_MEMORY_USAGE=90        # percent
MAX_REQUESTS_PER_IP=100    # per 5 min — rate limit abuse

VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

ALERTS=()
METRICS=()

alert() { ALERTS+=("$1"); }
metric() { METRICS+=("$1"); }

log() { [[ "$VERBOSE" -eq 1 ]] && echo "$1"; }

# === 1. Service Status ===
check_services() {
  for svc in contrastscan contrastapi; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
      alert "🔴 $svc service is DOWN"
    else
      log "✓ $svc running"
    fi
  done
}

# === 2. HTTP Health + Response Time ===
check_http() {
  local name="$1" url="$2"
  local result
  result=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" \
    --max-time 10 "$url" 2>/dev/null)

  local code time_s
  code=$(echo "$result" | awk '{print $1}')
  time_s=$(echo "$result" | awk '{print $2}')

  if [[ "$code" != "200" ]]; then
    alert "🔴 $name returned HTTP $code"
  fi

  local time_int=${time_s%%.*}
  if [[ "$time_int" -ge "$MAX_RESPONSE_TIME" ]]; then
    alert "🟡 $name slow response: ${time_s}s (threshold: ${MAX_RESPONSE_TIME}s)"
  fi

  metric "$name: HTTP $code, ${time_s}s"
  log "✓ $name: $code (${time_s}s)"
}

# === 3. 5xx Error Rate (last 5 min) ===
check_error_rate() {
  if [[ ! -f "$NGINX_LOG" ]]; then
    log "⚠ nginx log not found"
    return
  fi

  local cutoff
  cutoff=$(date -u -d '5 minutes ago' '+%d/%b/%Y:%H:%M' 2>/dev/null)
  if [[ -z "$cutoff" ]]; then
    return
  fi

  local total=0 errors=0
  while IFS= read -r line; do
    local status
    status=$(echo "$line" | grep -oP '" \K[0-9]{3}' | head -1)
    [[ -z "$status" ]] && continue
    total=$((total + 1))
    if [[ "$status" =~ ^5 ]]; then
      errors=$((errors + 1))
    fi
  done < <(awk -v cutoff="$cutoff" '$0 ~ cutoff {found=1} found' "$NGINX_LOG" 2>/dev/null | tail -5000)

  if [[ "$total" -gt 0 ]]; then
    local rate=$((errors * 100 / total))
    metric "5xx: ${errors}/${total} (${rate}%)"
    if [[ "$rate" -ge "$MAX_5XX_RATE" ]]; then
      alert "🔴 High 5xx rate: ${rate}% (${errors}/${total} in 5 min)"
    fi
    log "✓ 5xx rate: ${rate}% (${errors}/${total})"
  else
    log "✓ No requests in last 5 min"
  fi
}

# === 4. Nginx Active Connections ===
check_nginx_connections() {
  local status_url="http://127.0.0.1/nginx_status"
  local active
  active=$(curl -s "$status_url" 2>/dev/null | awk '/Active connections/ {print $3}')

  if [[ -n "$active" ]]; then
    metric "nginx active: $active"
    if [[ "$active" -ge "$MAX_ACTIVE_CONNECTIONS" ]]; then
      alert "🟡 Nginx active connections high: $active (threshold: $MAX_ACTIVE_CONNECTIONS)"
    fi
    log "✓ nginx connections: $active"
  else
    log "⚠ nginx stub_status not available"
  fi
}

# === 5. Cache Hit Ratio ===
check_cache_ratio() {
  if [[ ! -f "$NGINX_LOG" ]]; then
    return
  fi

  # count cache status from last 5 min (requires $upstream_cache_status in log)
  local hits=0 misses=0 total=0
  while IFS= read -r status; do
    total=$((total + 1))
    case "$status" in
      HIT|STALE|UPDATING|REVALIDATED) hits=$((hits + 1)) ;;
      MISS|EXPIRED|BYPASS) misses=$((misses + 1)) ;;
    esac
  done < <(awk '{print $NF}' "$NGINX_LOG" 2>/dev/null | tail -1000)

  if [[ "$total" -gt 10 ]]; then
    local miss_rate=$((misses * 100 / total))
    metric "cache miss: ${miss_rate}% (${misses}/${total})"
    if [[ "$miss_rate" -ge "$MAX_CACHE_MISS_RATE" ]]; then
      alert "🟡 Cache miss rate high: ${miss_rate}% — consider tuning nginx proxy_cache"
    fi
    log "✓ cache miss rate: ${miss_rate}%"
  fi
}

# === 6. Disk & Memory ===
check_system() {
  # Disk
  local disk_pct
  disk_pct=$(df / | awk 'NR==2 {gsub(/%/,""); print $5}')
  metric "disk: ${disk_pct}%"
  if [[ "$disk_pct" -ge "$MAX_DISK_USAGE" ]]; then
    alert "🟡 Disk usage high: ${disk_pct}% (threshold: ${MAX_DISK_USAGE}%)"
  fi
  log "✓ disk: ${disk_pct}%"

  # Memory
  local mem_pct
  mem_pct=$(free | awk '/Mem:/ {printf "%.0f", $3/$2*100}')
  metric "memory: ${mem_pct}%"
  if [[ "$mem_pct" -ge "$MAX_MEMORY_USAGE" ]]; then
    alert "🟡 Memory usage high: ${mem_pct}% (threshold: ${MAX_MEMORY_USAGE}%)"
  fi
  log "✓ memory: ${mem_pct}%"
}

# === 7. Rate Limit Abuse Detection ===
check_rate_abuse() {
  if [[ ! -f "$NGINX_LOG" ]]; then
    return
  fi

  local cutoff
  cutoff=$(date -u -d '5 minutes ago' '+%d/%b/%Y:%H:%M' 2>/dev/null)
  [[ -z "$cutoff" ]] && return

  local top_ip top_count
  top_ip=$(awk -v cutoff="$cutoff" '$0 ~ cutoff {found=1} found {print $1}' \
    "$NGINX_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -1)

  if [[ -n "$top_ip" ]]; then
    top_count=$(echo "$top_ip" | awk '{print $1}')
    local ip=$(echo "$top_ip" | awk '{print $2}')
    if [[ "$top_count" -ge "$MAX_REQUESTS_PER_IP" ]]; then
      alert "🟡 Rate abuse: $ip sent $top_count requests in 5 min"
    fi
    log "✓ top IP: $ip ($top_count reqs/5min)"
  fi
}

# === Send Telegram ===
send_telegram() {
  local message="$1"
  [[ ! -f "$TELEGRAM_TOKEN_FILE" ]] && return
  [[ ! -f "$TELEGRAM_CHAT_FILE" ]] && return

  local token
  token=$(cat "$TELEGRAM_TOKEN_FILE")

  while IFS= read -r chat_id; do
    [[ -z "$chat_id" || "$chat_id" == \#* ]] && continue
    curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
      -d "chat_id=${chat_id}" \
      -d "parse_mode=HTML" \
      -d "text=${message}" \
      --max-time 10 >/dev/null 2>&1
  done < "$TELEGRAM_CHAT_FILE"
}

# === Main ===
main() {
  check_services
  check_http "ContrastScan" "$SCAN_URL"
  check_http "ContrastAPI" "$API_URL"
  check_error_rate
  check_nginx_connections
  check_cache_ratio
  check_system
  check_rate_abuse

  # Verbose mode — print all metrics
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo ""
    echo "=== Metrics ==="
    for m in "${METRICS[@]}"; do
      echo "  $m"
    done
  fi

  # Alert if problems found
  if [[ ${#ALERTS[@]} -gt 0 ]]; then
    local msg="<b>⚠ Health Check Alert</b>"
    msg+="%0A$(date -u '+%Y-%m-%d %H:%M UTC')"
    for a in "${ALERTS[@]}"; do
      msg+="%0A$a"
    done
    # Add relevant metrics for context
    msg+="%0A%0A<b>Metrics:</b>"
    for m in "${METRICS[@]}"; do
      msg+="%0A$m"
    done

    send_telegram "$msg"

    if [[ "$VERBOSE" -eq 1 ]]; then
      echo ""
      echo "=== ALERTS ==="
      for a in "${ALERTS[@]}"; do
        echo "  $a"
      done
    fi
    exit 1
  fi

  log "✓ All checks passed"
  exit 0
}

main
