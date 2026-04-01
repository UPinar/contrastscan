#!/bin/bash

###############################################################################
# ContrastScan Server Status Monitor
# Shows security, service, and scan status at a glance
###############################################################################

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             ContrastScan Server Status                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Generated: $(date)"
echo ""

# System health
echo -e "${YELLOW}━━━ System Health ━━━${NC}"
up=$(uptime -p | sed 's/up //')
echo "  Uptime: $up"
load=$(uptime | awk -F'load average:' '{print $2}')
echo "  System load:$load"

mem_total=$(free -h | awk '/^Mem:/ {print $2}')
mem_used=$(free -h | awk '/^Mem:/ {print $3}')
echo "  Memory: $mem_used / $mem_total"

disk_usage=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
echo "  Disk: $disk_usage"
echo ""

# Services
echo -e "${YELLOW}━━━ Services ━━━${NC}"
for svc in contrastcyber nginx fail2ban ssh; do
    if systemctl is-active --quiet "$svc"; then
        echo -e "  ${GREEN}✓${NC} $svc"
    else
        echo -e "  ${RED}✗${NC} $svc ${RED}DOWN${NC}"
    fi
done

# SSL cert expiry
if [ -f /etc/letsencrypt/live/contrastcyber.com/fullchain.pem ]; then
    expiry=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/contrastcyber.com/fullchain.pem 2>/dev/null | cut -d= -f2)
    days_left=$(( ($(date -d "$expiry" +%s) - $(date +%s)) / 86400 ))
    if [ "$days_left" -lt 14 ]; then
        echo -e "  ${RED}!${NC} SSL cert expires in ${RED}${days_left} days${NC}"
    else
        echo -e "  ${GREEN}✓${NC} SSL cert: ${days_left} days left"
    fi
fi
echo ""

# fail2ban
echo -e "${YELLOW}━━━ fail2ban ━━━${NC}"
if systemctl is-active --quiet fail2ban; then
    jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//;s/,/ /g')
    jail_count=$(echo "$jails" | wc -w)
    echo -e "  Active jails: ${GREEN}$jail_count${NC}"

    total_banned=0
    for jail in $jails; do
        banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | grep -oE '[0-9]+' | tail -1)
        total=$(fail2ban-client status "$jail" 2>/dev/null | grep "Total banned" | grep -oE '[0-9]+' | tail -1)
        echo "    • $jail: $banned active, $total total"
        total_banned=$((total_banned + banned))
    done
    echo -e "  ${BLUE}➤${NC} Currently banned: ${RED}$total_banned${NC}"
fi
echo ""

# UFW
echo -e "${YELLOW}━━━ Firewall (UFW) ━━━${NC}"
if ufw status | grep -q "Status: active"; then
    open_ports=$(ufw status | grep "ALLOW" | awk '{print $1}' | sort -u | paste -sd, -)
    echo -e "  ${GREEN}✓${NC} Active — open ports: $open_ports"
else
    echo -e "  ${RED}✗${NC} UFW is not active"
fi
echo ""

# ContrastScan scan stats
echo -e "${YELLOW}━━━ Scan Statistics ━━━${NC}"
DB="/opt/contrastcyber/app/scans.db"
if [ -f "$DB" ]; then
    total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM scans;" 2>/dev/null)
    unique=$(sqlite3 "$DB" "SELECT COUNT(DISTINCT domain) FROM scans;" 2>/dev/null)
    today_scans=$(sqlite3 "$DB" "SELECT COUNT(*) FROM scans WHERE created_at >= date('now');" 2>/dev/null)
    avg=$(sqlite3 "$DB" "SELECT ROUND(AVG(s), 1) FROM (SELECT MAX(total_score) as s FROM scans GROUP BY domain);" 2>/dev/null)
    echo "  Total scans: $total"
    echo "  Unique domains: $unique"
    echo "  Today: $today_scans"
    echo "  Avg score (unique): ${avg:-0}/100"
else
    echo "  Database not found"
fi
echo ""

# Recent attacks
echo -e "${YELLOW}━━━ Recent Attacks (Last 20) ━━━${NC}"
ATTACK_PATTERN='(wp-admin|wp-login|xmlrpc|phpMyAdmin|phpmyadmin|\.env|\.git|actuator|cgi-bin|shell|eval-stdin|CONNECT |SSH-2\.0|\\x[0-9a-fA-F]|setup-config|\.php|nmap|http://)'

if [ -f /var/log/nginx/access.log ]; then
    grep -E "$ATTACK_PATTERN" /var/log/nginx/access.log 2>/dev/null | \
        tail -20 | while IFS= read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        request=$(echo "$line" | awk -F'"' '{print $2}')
        status=$(echo "$line" | awk '{print $9}')
        if [ -n "$request" ] && [ "$request" != "-" ]; then
            echo -e "  ${RED}$ip${NC} → \"$request\" [${YELLOW}$status${NC}]"
        else
            echo -e "  ${RED}$ip${NC} → (malformed) [${YELLOW}$status${NC}]"
        fi
    done

    attack_count=$(grep -cE "$ATTACK_PATTERN" /var/log/nginx/access.log 2>/dev/null)
    echo ""
    echo -e "  ${BLUE}➤${NC} Total attack requests in log: ${RED}${attack_count:-0}${NC}"
else
    echo "  No nginx access.log found"
fi
echo ""

# Recent bans (last 24h)
echo -e "${YELLOW}━━━ Recent Bans (24h) ━━━${NC}"
today=$(date +%Y-%m-%d)
yesterday=$(date -d "yesterday" +%Y-%m-%d)

if [ -f /var/log/fail2ban.log ]; then
    bans_24h=$(grep -E "($today|$yesterday).*Ban " /var/log/fail2ban.log 2>/dev/null | grep -v "Restore Ban" | wc -l)
    echo -e "  New bans (24h): ${RED}$bans_24h${NC}"

    echo "  Last 5 bans:"
    grep "Ban " /var/log/fail2ban.log 2>/dev/null | grep -v "Restore Ban" | tail -5 | \
        awk '{printf "    %s %s  %s\n", $1, $2, $NF}'
else
    echo "  No fail2ban log found"
fi
echo ""

# Recommendations
echo -e "${YELLOW}━━━ Recommendations ━━━${NC}"
recs=0

if ! systemctl is-active --quiet contrastcyber; then
    echo -e "  ${RED}!${NC} contrastcyber service is down"
    recs=$((recs + 1))
fi

if ! systemctl is-active --quiet fail2ban; then
    echo -e "  ${RED}!${NC} fail2ban is not running"
    recs=$((recs + 1))
fi

disk_pct=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$disk_pct" -gt 80 ]; then
    echo -e "  ${RED}!${NC} Disk usage at ${disk_pct}%"
    recs=$((recs + 1))
fi

if [ "$days_left" -lt 14 ] 2>/dev/null; then
    echo -e "  ${RED}!${NC} SSL cert renew needed"
    recs=$((recs + 1))
fi

if [ $recs -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} Everything looks good!"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
